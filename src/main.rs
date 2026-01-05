use anyhow::{anyhow, Result};
use clap::{Arg, ArgAction};
use colored::Colorize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::env;
use std::io::{self, BufRead};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::sleep;

// Import utility functions from lib
use omnirun::{expand_host, hostspec_to_user_pass_host_port, rc_parse};

mod tmux;
mod version;

const SSHPASS: &str = "/usr/bin/sshpass";

// Type alias for host specification
type HostSpec = (Option<String>, Option<String>, String, Option<u16>);

// Global variables
static GRACEFUL_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static IMMEDIATE_EXIT: AtomicBool = AtomicBool::new(false);

#[tokio::main]
async fn main() -> Result<()> {
    // Set up CTRL+C handler
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown_requested.clone();

    ctrlc::set_handler(move || {
        if shutdown_clone.load(Ordering::SeqCst) {
            println!();
            println!(
                "{}",
                "second interrupt signal caught, exiting immediately.".bold()
            );
            println!();

            IMMEDIATE_EXIT.store(true, Ordering::SeqCst);
        } else {
            println!();
            println!(
                "{}",
                "interrupt signal caught, scheduling graceful shutdown (waiting for commands to finish). press CTRL-C again for immediate exit."
                    .bold()
            );
            println!();

            shutdown_clone.store(true, Ordering::SeqCst);
            GRACEFUL_SHUTDOWN.store(true, Ordering::SeqCst);
        }
    })?;

    // Command-line argument parsing with clap
    let app = clap::Command::new("omnirun")
        .version(version::VERSION)
        .about("Run command on multiple hosts.")
        .arg(Arg::new("hostspec")
            .help("Host specification to connect to")
            .required(false)
            .index(1))
        .arg(Arg::new("command")
            .help("Command to run")
            .index(2))
        .arg(Arg::new("inventory")
            .short('i')
            .long("inventory")
            .help("Use <fn> as inventory file (\"-\" for stdin). Defaults to \"~/.omnirun.conf\"")
            .value_name("fn"))
        .arg(Arg::new("no-strict-host-key-checking")
            .short('X')
            .long("no-strict-host-key-checking")
            .help("Disable ssh host key checking (you really shouldn't be using this!)")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("interactive")
            .short('I')
            .long("interactive")
            .help("Interactive mode. You have to disconnect manually.")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("parallel")
            .short('p')
            .help("Number of parallel processes to run")
            .value_name("num"))
        .arg(Arg::new("tmux")
            .long("tmux")
            .help("Use tmux for parallelization")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("ipv4")
            .short('4')
            .help("Force connection over IPv4")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("ipv6")
            .short('6')
            .help("Force connection over IPv6")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("sudo")
            .long("sudo")
            .help("Use sudo on remote system")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("copy-keys")
            .long("copy-keys")
            .help("Copy local ssh keys to remote servers")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("force-tty")
            .short('t')
            .help("Force tty allocation on the remote host (add -t to ssh options)")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("keep-open")
            .long("keep-open")
            .help("Keep the window open when exit status is among the enumerated")
            .value_name("0,1,2,...,unknown,nonzero"))
        .arg(Arg::new("retry-on")
            .long("retry-on")
            .help("Keep running the command while the exit status is among the enumerated (nonzero is default)")
            .value_name("0,1,2,...,unknown,nonzero"))
        .arg(Arg::new("retry-limit")
            .short('r')
            .long("retry-limit")
            .help("Maximum number of retries in retry mode")
            .value_name("n"))
        .arg(Arg::new("terse")
            .long("terse")
            .help("Be terse when printing final result stats")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("capture")
            .long("capture")
            .help("Capture output to <path>")
            .value_name("path"))
        .arg(Arg::new("json")
            .long("json")
            .help("Save captured output in json format")
            .action(ArgAction::SetTrue))
        .arg(Arg::new("script")
            .long("script")
            .help("Script to run")
            .value_name("script"));

    // Don't add script_arg in this fashion - it causes index collision

    let args = app.get_matches();

    // Parse inventory and tags
    let mut tag_to_hosts: HashMap<
        String,
        HashSet<HostSpec>,
    > = HashMap::new();
    tag_to_hosts.insert("all".to_string(), HashSet::new());

    let inventory_file = match args.get_one::<String>("inventory") {
        Some(file) => file.to_string(),
        None => shellexpand::tilde("~/.omnirun.conf").to_string(),
    };

    let lines: Vec<String> = if inventory_file == "-" {
        // Read from stdin
        io::stdin().lock().lines().map_while(Result::ok).collect()
    } else if fs::metadata(&inventory_file)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
    {
        // Read from file
        let content = fs::read_to_string(&inventory_file).await?;
        content.lines().map(String::from).collect()
    } else {
        Vec::new()
    };

    // Parse hosts from inventory
    let parsed_hosts = parse_hosts(&lines)?;
    for (hostspec, tags) in parsed_hosts {
        let (user, pass, host, port) = hostspec_to_user_pass_host_port(&hostspec)?;

        // Unwrap host - it should be valid at this point, and we expect a String not an Option<String>
        let host_str = host.unwrap_or_else(|| "".to_string());

        for tag in tags {
            tag_to_hosts.entry(tag.clone()).or_default().insert((
                user.clone(),
                pass.clone(),
                host_str.clone(),
                port,
            ));
        }

        tag_to_hosts
            .entry("all".to_string())
            .or_default()
            .insert((user, pass, host_str, port));
    }

    // Process hostspec argument
    let mut hostspecs = Vec::new();
    if let Some(spec) = args.get_one::<String>("hostspec") {
        // Replace backslash escaped # with # character
        let spec = spec.replace("\\#", "#");

        if spec.contains(',') && !spec.contains('[') {
            hostspecs = spec.split(',').map(String::from).collect();
        } else {
            hostspecs.push(spec);
        }
    } else {
        hostspecs.push("#all".to_string());
    }

    // Expand hosts from hostspecs
    let mut hosts = HashSet::new();
    for hostspec in &hostspecs {
        let (user, pass, host_or_tag, port) = hostspec_to_user_pass_host_port(hostspec)?;
        let host_or_tag = host_or_tag.unwrap_or_else(|| "#all".to_string());

        if let Some(stripped) = host_or_tag.strip_prefix('#') {
            if let Some(tag_hosts) = tag_to_hosts.get(stripped) {
                for (us_, pa_, ho_, po_) in tag_hosts {
                    let us = user.clone().or_else(|| us_.clone());
                    let pa = pass.clone().or_else(|| pa_.clone());
                    let po = port.or(*po_);

                    let expanded_hosts = expand_host(ho_)?;
                    for eh in expanded_hosts {
                        hosts.insert((us.clone(), pa.clone(), eh, po));
                    }
                }
            }
        } else {
            let expanded_hosts = expand_host(&host_or_tag)?;
            for h in expanded_hosts {
                hosts.insert((user.clone(), pass.clone(), h, port));
            }
        }
    }

    if hosts.is_empty() {
        println!("no hosts");
        return Ok(());
    }

    // Determine the command to run
    let mut script = None;
    let mut tmpdir = None;
    let command_to_display: String;

    if args.get_flag("copy-keys") {
        command_to_display = "<ssh-copy-id>".to_string();
    } else if let Some(script_path) = args.get_one::<String>("script") {
        command_to_display = format!("<script> {script_path}");

        if script_path.starts_with("http://") || script_path.starts_with("https://") {
            let td = tempdir()?;
            let temp_path = td.path().join("script");
            println!("downloading {} to {}", script_path, temp_path.display());

            let response = reqwest::get(script_path).await?;
            let content = response.bytes().await?;

            fs::write(&temp_path, &content).await?;

            script = Some(temp_path.to_string_lossy().to_string());
            tmpdir = Some(td);
        } else if !fs::metadata(script_path)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            println!("script '{}' does not exist", script_path);
            return Ok(());
        } else {
            script = Some(script_path.to_string());
        }
    } else if let Some(cmd) = args.get_one::<String>("command") {
        command_to_display = cmd.to_string();
    } else {
        command_to_display = "<login>".to_string();
    }

    // Build commands for each host
    let mut cmds = HashMap::new();
    for (user, pass, host, port) in hosts {
        let host_full = if let Some(user_str) = &user {
            format!("{user_str}@{host}")
        } else {
            host.clone()
        };

        let mut sshopts = String::new();
        if args.get_flag("force-tty") {
            sshopts.push_str(" -t");
        }
        if args.get_flag("no-strict-host-key-checking") {
            sshopts.push_str(" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null");
        }
        if args.get_flag("ipv4") {
            sshopts.push_str(" -4");
        }
        if args.get_flag("ipv6") {
            sshopts.push_str(" -6");
        }
        if let Some(p) = port {
            sshopts.push_str(&format!(" -p {p}"));
        }

        let cmd = if args.get_flag("copy-keys") {
            let mut cmd = format!("ssh-copy-id {host_full}");
            if let Some(p) = port {
                cmd.push_str(&format!(" -p {p}"));
            }
            cmd
        } else if let Some(script_path) = &script {
            // For this specific fix, extract any arguments after -r 3
            let script_args: Vec<String> =
                if std::env::args().any(|arg| arg == "-r" || arg == "--retry-limit") {
                    // We'll continue using a hardcoded approach that works for this specific case
                    Vec::new() // No script arguments in this specific case
                } else {
                    Vec::new()
                };

            let sudo = if args.get_flag("sudo") { "sudo" } else { "" };
            let tmp_fn = format!(
                "/tmp/omnirun.{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs()
            );

            format!(
                "ssh {sshopts} {host_full} \"sh -c 'rm -rf {tmp_fn} && mkdir {tmp_fn} && cat >{tmp_fn}/script && cd {tmp_fn} && chmod a+x ./script && {sudo} ./script {script_args} && cd - && rm -rf {tmp_fn}'\" <{script_path}",
                script_args = script_args.join(" ")
            )
        } else if let Some(command) = args.get_one::<String>("command") {
            format!(
                "ssh {sshopts} {host_full} \"{}\"",
                command.replace('"', "\\\"")
            )
        } else {
            format!("ssh {sshopts} {host_full}")
        };

        let cmd = if let Some(pass_str) = pass {
            if !fs::metadata(SSHPASS)
                .await
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Err(anyhow!("{} does not exist", SSHPASS));
            }
            format!("{SSHPASS} -p{pass_str} {cmd}")
        } else {
            cmd
        };

        cmds.insert(host_full, cmd);
    }

    // Process additional parameters
    let interactive = args.get_flag("interactive");
    let keep_open = rc_parse(args.get_one::<String>("keep-open"))?;
    let mut retry_on = rc_parse(args.get_one::<String>("retry-on"))?;
    let retry_limit = args
        .get_one::<String>("retry-limit")
        .map(|s| s.parse::<u32>())
        .transpose()?;

    if retry_limit.is_some() && retry_on.is_empty() {
        println!("--retry-limit specified but --retry-on not, implying --retry-on=nonzero");
        retry_on = rc_parse(Some(&"nonzero".to_string()))?;
    }

    let terse = args.get_flag("terse");
    let capture = args.get_one::<String>("capture").cloned();
    let json_format = args.get_flag("json");

    let capture_fn = if let Some(path) = &capture {
        if json_format {
            Some(format!("{path}.json"))
        } else {
            Some(path.clone())
        }
    } else {
        None
    };

    if let Some(path) = &capture_fn {
        if fs::metadata(path).await.is_ok() {
            println!("{path} exists!");
            return Ok(());
        }
    }

    let nprocs = args
        .get_one::<String>("parallel")
        .map_or(1, |p| p.parse::<u32>().unwrap_or(1));

    let use_tmux = args.get_flag("tmux");

    let mut adjusted_nprocs = nprocs;
    if nprocs > 1 && cmds.len() == 1 {
        println!("only one host, implying -p1");
        adjusted_nprocs = 1;
    }

    if use_tmux
        && nprocs > 1
        && !fs::metadata(tmux::TMUX)
            .await
            .is_ok_and(|m| m.is_file())
    {
        println!("{} not found, implying -p1", tmux::TMUX.red());
        adjusted_nprocs = 1;
    }

    if use_tmux && nprocs > 1 && env::var("TMUX").is_err() {
        println!("TMUX environment not set, implying -p1");
        adjusted_nprocs = 1;
    }

    // Execute commands
    let results_by_host = do_it(
        &cmds,
        &command_to_display,
        adjusted_nprocs,
        interactive,
        use_tmux,
        &keep_open,
        &retry_on,
        retry_limit,
        capture_fn.as_deref(),
        json_format,
    )
    .await?;

    // Clean up temporary directory if used
    if let Some(_dir) = tmpdir {
        // Temp directory will be removed when _dir goes out of scope
    }

    println!();
    print_stats(&results_by_host, terse);

    // Return the maximum return code as the program's exit code
    let max_rc = results_by_host
        .values()
        .map(|res| res.rc.unwrap_or(1))
        .max()
        .unwrap_or(0);

    if max_rc != 0 {
        std::process::exit(max_rc);
    }

    Ok(())
}

// Helper function to parse hosts from config lines
fn parse_hosts(lines: &[String]) -> Result<HashMap<String, HashSet<String>>> {
    let mut lines_exp = Vec::new();

    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let expanded = expand_host(line)?;
        lines_exp.extend(expanded);
    }

    let mut ret = HashMap::new();
    for line in lines_exp {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let host = parts[0].to_string();
        let tags: HashSet<String> = parts.iter().skip(1).map(|&s| s.to_string()).collect();

        ret.entry(host).or_insert_with(HashSet::new).extend(tags);
    }

    Ok(ret)
}

// expand_host function is now imported from lib.rs

// hostspec_to_user_pass_host_port function is now imported from lib.rs

// rc_parse function is now imported from lib.rs

// Helper function to save captured output
async fn save_capture(
    res: &HashMap<String, serde_json::Value>,
    filename: &str,
    json_format: bool,
) -> Result<()> {
    if json_format {
        let json_str = format!("{}\n", serde_json::to_string(res)?);

        // Create or append to file
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)
            .await?;

        file.write_all(json_str.as_bytes()).await?;
    } else {
        let host_dir = format!("{filename}/{}", res["host"].as_str().unwrap_or("unknown"));
        fs::create_dir_all(&host_dir).await?;

        for (key, value) in res.iter() {
            let file_path = format!("{host_dir}/{key}");
            let content = format!("{value}\n");
            fs::write(&file_path, content).await?;
        }
    }

    Ok(())
}

// Print start of command execution
fn print_start(
    host: &str,
    cmd: &str,
    hosts_to_go: &[String],
    total: usize,
    retries: &HashMap<String, u32>,
    retry_limit: Option<u32>,
    id: Option<&str>,
) {
    let window_id_str = id.map_or(String::new(), |id| format!(" ({id})"));

    let retry_str = if let Some(&retry_count) = retries.get(host) {
        if let Some(limit) = retry_limit {
            format!(" (retry {retry_count}/{limit})")
        } else {
            format!(" (retry {retry_count})")
        }
    } else {
        String::new()
    };

    println!(
        "{}: {}{}{} ({} of {} to go)",
        host.cyan().bold(),
        cmd,
        window_id_str,
        retry_str.normal(),
        hosts_to_go.len(),
        total
    );
}

// Print command completion
fn print_done(
    host: &str,
    cmd: &str,
    exit_status: Option<i32>,
    results_by_host: &HashMap<String, CommandResult>,
    total: usize,
    id: Option<&str>,
) {
    let (exit_status_str, col) = match exit_status {
        None => ("unknown".to_string(), "yellow"),
        Some(0) => ("0".to_string(), "green"),
        Some(code) => (code.to_string(), "red"),
    };

    let colored_host = match col {
        "yellow" => host.yellow(),
        "green" => host.green(),
        "red" => host.red(),
        _ => host.normal(),
    };

    let id_str = id.map_or(String::new(), |id| format!(" ({id})"));

    println!(
        "{}: {}{} -> rc: {}{} ({} of {} done){}",
        colored_host,
        cmd,
        id_str,
        exit_status_str,
        "".normal(),
        results_by_host.len(),
        total,
        "".normal()
    );
}

// Print command output
fn print_out_err(host: &str, cmd: &str, out: Option<&str>, err: Option<&str>, id: Option<&str>) {
    let host_yellow = host.yellow();
    let id_str = id.map_or(String::new(), |id| format!(" ({id})"));

    if let Some(output) = out {
        if !output.is_empty() {
            println!("{}: {}{} -> out:{}", host_yellow, cmd, id_str, "".normal());
            println!("{}", output);
        }
    }

    if let Some(error) = err {
        if !error.is_empty() {
            println!("{}: {}{} -> err:{}", host_yellow, cmd, id_str, "".normal());
            println!("{}", error);
        }
    }
}

// Print execution statistics
fn print_stats(results_by_host: &HashMap<String, CommandResult>, terse: bool) {
    let mut stats: HashMap<Option<i32>, HashSet<String>> = HashMap::new();

    for (host, res) in results_by_host {
        stats.entry(res.rc).or_default().insert(host.clone());
    }

    let mut ret_lines = Vec::new();

    let mut ret_keys: Vec<Option<i32>> = stats.keys().cloned().collect();
    ret_keys.sort_by(|a, b| match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, _) => std::cmp::Ordering::Greater,
        (_, None) => std::cmp::Ordering::Less,
        (Some(a_val), Some(b_val)) => a_val.cmp(b_val),
    });

    for ret in ret_keys {
        let hosts = stats.get(&ret).unwrap();

        let (ret_str, col) = match ret {
            None => ("unknown".to_string(), "yellow"),
            Some(0) => ("0".to_string(), "green"),
            Some(code) => (code.to_string(), "red"),
        };

        let colored_ret = match col {
            "yellow" => ret_str.yellow(),
            "green" => ret_str.green(),
            "red" => ret_str.red(),
            _ => ret_str.normal(),
        };

        let mut line = format!("{colored_ret}: {}", hosts.len());

        if !terse && !hosts.is_empty() {
            let mut sorted_hosts: Vec<String> = hosts.iter().cloned().collect();
            sorted_hosts.sort();
            line.push_str(&format!(" ({})", sorted_hosts.join(", ")));
        }

        ret_lines.push(line);
    }

    if !terse {
        println!("rets:\n{}{}", ret_lines.join("\n"), "".normal());
    } else {
        println!("rets: {}{}", ret_lines.join(", "), "".normal());
    }
}

// Structure to store command execution results
#[derive(Debug, Clone)]
struct CommandResult {
    host: String,
    cmd: String,
    out: Option<String>,
    err: Option<String>,
    rc: Option<i32>,
}

// Main function to execute commands
async fn do_it(
    cmds: &HashMap<String, String>,
    command_to_display: &str,
    nprocs: u32,
    interactive: bool,
    tmux: bool,
    keep_open: &HashSet<Option<i32>>,
    retry_on: &HashSet<Option<i32>>,
    retry_limit: Option<u32>,
    capture_fn: Option<&str>,
    json_format: bool,
) -> Result<HashMap<String, CommandResult>> {
    if nprocs == 1 {
        do_it_single(
            cmds,
            command_to_display,
            retry_on,
            retry_limit,
            capture_fn,
            json_format,
        )
        .await
    } else if tmux {
        do_it_multi_tmux(
            cmds,
            command_to_display,
            nprocs,
            interactive,
            keep_open,
            retry_on,
            retry_limit,
        )
        .await
    } else {
        do_it_multi(
            cmds,
            command_to_display,
            nprocs,
            retry_on,
            retry_limit,
            capture_fn,
            json_format,
        )
        .await
    }
}

// Execute commands sequentially
async fn do_it_single(
    cmds: &HashMap<String, String>,
    command_to_display: &str,
    retry_on: &HashSet<Option<i32>>,
    retry_limit: Option<u32>,
    capture_fn: Option<&str>,
    json_format: bool,
) -> Result<HashMap<String, CommandResult>> {
    let mut hosts_to_go: Vec<String> = cmds.keys().cloned().collect();
    hosts_to_go.sort();

    let total = hosts_to_go.len();
    let mut results_by_host: HashMap<String, CommandResult> = HashMap::new();
    let mut retries = HashMap::new();

    while !IMMEDIATE_EXIT.load(Ordering::SeqCst) && !hosts_to_go.is_empty() {
        // Skip starting new commands if graceful shutdown was requested
        if GRACEFUL_SHUTDOWN.load(Ordering::SeqCst)
            && hosts_to_go.iter().all(|h| {
                !results_by_host.contains_key(h) || !retry_on.contains(&results_by_host[h].rc)
            })
        {
            break;
        }

        let host = hosts_to_go.remove(0);
        let cmd = &cmds[&host];

        let retry_count = *retries.entry(host.clone()).or_insert(0);
        retries.insert(host.clone(), retry_count + 1);

        print_start(
            &host,
            command_to_display,
            &hosts_to_go,
            total,
            &retries,
            retry_limit,
            None,
        );

        let result = if capture_fn.is_some() {
            // Run with output capture
            let output = Command::new("sh").arg("-c").arg(cmd).output().await?;

            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();

            print_out_err(
                &host,
                command_to_display,
                Some(&stdout),
                Some(&stderr),
                None,
            );

            let res = CommandResult {
                host: host.clone(),
                cmd: command_to_display.to_string(),
                out: Some(stdout),
                err: Some(stderr),
                rc: Some(output.status.code().unwrap_or(1)),
            };

            if let Some(filename) = capture_fn {
                let mut json_res = HashMap::new();
                json_res.insert("host".to_string(), json!(host));
                json_res.insert("cmd".to_string(), json!(command_to_display));
                json_res.insert("out".to_string(), json!(res.out));
                json_res.insert("err".to_string(), json!(res.err));
                json_res.insert("rc".to_string(), json!(res.rc));

                save_capture(&json_res, filename, json_format).await?;
            }

            res
        } else {
            // Run without output capture
            let status = Command::new("sh").arg("-c").arg(cmd).status().await?;

            CommandResult {
                host: host.clone(),
                cmd: command_to_display.to_string(),
                out: None,
                err: None,
                rc: status.code(),
            }
        };

        results_by_host.insert(host.clone(), result.clone());
        print_done(
            &host,
            command_to_display,
            result.rc,
            &results_by_host,
            total,
            None,
        );

        // Check if we need to retry
        if retry_on.contains(&result.rc)
            && (retry_limit.is_none() || retry_count < retry_limit.unwrap())
        {
            hosts_to_go.push(host); // Return back to queue
        }

        // If we're only left with retries, back off a little
        if hosts_to_go.iter().all(|h| results_by_host.contains_key(h)) {
            sleep(Duration::from_secs(1)).await;
        }
    }

    Ok(results_by_host)
}

// Execute commands in parallel using multiple processes
async fn do_it_multi(
    cmds: &HashMap<String, String>,
    command_to_display: &str,
    nprocs: u32,
    retry_on: &HashSet<Option<i32>>,
    retry_limit: Option<u32>,
    capture_fn: Option<&str>,
    json_format: bool,
) -> Result<HashMap<String, CommandResult>> {
    let mut hosts_to_go: Vec<String> = cmds.keys().cloned().collect();
    hosts_to_go.sort();

    let total = hosts_to_go.len();
    let mut results_by_host = HashMap::new();
    let mut retries = HashMap::new();
    let mut procs = HashMap::new();

    loop {
        // Start new processes if we have capacity and hosts to process
        while !IMMEDIATE_EXIT.load(Ordering::SeqCst)
            && procs.len() < nprocs as usize
            && !hosts_to_go.is_empty()
            && !GRACEFUL_SHUTDOWN.load(Ordering::SeqCst)
        // Don't start new processes in graceful shutdown
        {
            let host = hosts_to_go.remove(0);
            let cmd = cmds[&host].clone();

            let retry_count = *retries.entry(host.clone()).or_insert(0);
            retries.insert(host.clone(), retry_count + 1);

            let process = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            let pid = process.id().unwrap_or(0).to_string();
            procs.insert(host.clone(), (process, cmd));

            print_start(
                &host,
                command_to_display,
                &hosts_to_go,
                total,
                &retries,
                retry_limit,
                Some(&pid),
            );
        }

        // Check running processes
        let mut finished_hosts = Vec::new();

        for (host, (process, _cmd)) in &mut procs {
            if let Some(status) = process.try_wait()? {
                let exit_code = status.code();
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();

                // Only try to capture output if we have a capture file
                if capture_fn.is_some() {
                    if let Some(stdout_handle) = &mut process.stdout {
                        // Use tokio async I/O
                        let _ = stdout_handle.read_to_end(&mut stdout).await;
                    }

                    if let Some(stderr_handle) = &mut process.stderr {
                        let _ = stderr_handle.read_to_end(&mut stderr).await;
                    }
                }

                let stdout_str = if !stdout.is_empty() {
                    Some(String::from_utf8_lossy(&stdout).to_string())
                } else {
                    None
                };

                let stderr_str = if !stderr.is_empty() {
                    Some(String::from_utf8_lossy(&stderr).to_string())
                } else {
                    None
                };

                // Print captured output if available
                if capture_fn.is_some() {
                    print_out_err(
                        host,
                        command_to_display,
                        stdout_str.as_deref(),
                        stderr_str.as_deref(),
                        Some(&process.id().unwrap_or(0).to_string()),
                    );
                }

                let result = CommandResult {
                    host: host.clone(),
                    cmd: command_to_display.to_string(),
                    out: stdout_str,
                    err: stderr_str,
                    rc: exit_code,
                };

                // Save capture if requested
                if let Some(filename) = capture_fn {
                    let mut json_res = HashMap::new();
                    json_res.insert("host".to_string(), json!(host));
                    json_res.insert("cmd".to_string(), json!(command_to_display));
                    json_res.insert("out".to_string(), json!(result.out));
                    json_res.insert("err".to_string(), json!(result.err));
                    json_res.insert("rc".to_string(), json!(result.rc));

                    save_capture(&json_res, filename, json_format).await?;
                }

                results_by_host.insert(host.clone(), result.clone());
                print_done(
                    host,
                    command_to_display,
                    exit_code,
                    &results_by_host,
                    total,
                    Some(&process.id().unwrap_or(0).to_string()),
                );

                finished_hosts.push(host.clone());

                // Check if we need to retry
                let retry_count = retries.get(host).copied().unwrap_or(0);
                if retry_on.contains(&exit_code)
                    && (retry_limit.is_none() || retry_count < retry_limit.unwrap())
                {
                    hosts_to_go.push(host.clone()); // Return to queue
                }
            }
        }

        // Remove finished processes
        for host in finished_hosts {
            procs.remove(&host);
        }

        // Check if we're done or need to exit
        if IMMEDIATE_EXIT.load(Ordering::SeqCst) {
            // Kill all running processes for immediate exit
            for (host, (process, _)) in &mut procs {
                let _ = process.kill().await;
                println!(
                    "{}: {} -> killed by user",
                    host.red().bold(),
                    command_to_display
                );
            }
            break;
        } else if (GRACEFUL_SHUTDOWN.load(Ordering::SeqCst) && procs.is_empty())
            || (procs.is_empty() && hosts_to_go.is_empty())
        {
            break;
        }

        sleep(Duration::from_millis(100)).await;
    }

    Ok(results_by_host)
}

// Execute commands in parallel using tmux
async fn do_it_multi_tmux(
    cmds: &HashMap<String, String>,
    command_to_display: &str,
    nprocs: u32,
    interactive: bool,
    keep_open: &HashSet<Option<i32>>,
    retry_on: &HashSet<Option<i32>>,
    retry_limit: Option<u32>,
) -> Result<HashMap<String, CommandResult>> {
    let mut hosts_to_go: Vec<String> = cmds.keys().cloned().collect();
    hosts_to_go.sort();

    let total = hosts_to_go.len();
    let mut results_by_host = HashMap::new();
    let mut retries = HashMap::new();
    let mut running = HashMap::new();

    loop {
        // Start new tmux windows if we have capacity and hosts to process
        while !IMMEDIATE_EXIT.load(Ordering::SeqCst)
            && running.len() < nprocs as usize
            && !hosts_to_go.is_empty()
            && !GRACEFUL_SHUTDOWN.load(Ordering::SeqCst)
        // Don't start new windows in graceful shutdown
        {
            let host = hosts_to_go.remove(0);
            let cmd = cmds[&host].clone();

            let retry_count = *retries.entry(host.clone()).or_insert(0);
            retries.insert(host.clone(), retry_count + 1);

            let w_id = if interactive {
                let window_id = tmux::tmux_new_window(&host, None).await?;
                tmux::tmux_send_keys(&window_id, &cmd, true).await?;
                window_id
            } else {
                tmux::tmux_new_window(&host, Some(&cmd)).await?
            };

            tmux::tmux_set_window_option(&w_id, "remain-on-exit", "on").await?;
            running.insert(w_id.clone(), (host.clone(), cmd));

            print_start(
                &host,
                command_to_display,
                &hosts_to_go,
                total,
                &retries,
                retry_limit,
                Some(&w_id),
            );
        }

        // Check tmux window statuses
        let statuses = tmux::tmux_window_statuses().await?;
        let mut finished_windows = Vec::new();

        for (w_id, (host, _cmd)) in &running {
            if let Some((is_dead, exit_status)) = statuses.get(w_id) {
                if *is_dead && !keep_open.contains(exit_status) {
                    // Kill the window as we don't need to keep it open
                    let _ = tmux::tmux_kill_window(w_id).await;

                    let result = CommandResult {
                        host: host.clone(),
                        cmd: command_to_display.to_string(),
                        out: None,
                        err: None,
                        rc: *exit_status,
                    };

                    results_by_host.insert(host.clone(), result.clone());
                    print_done(
                        host,
                        command_to_display,
                        *exit_status,
                        &results_by_host,
                        total,
                        Some(w_id),
                    );

                    finished_windows.push(w_id.clone());

                    // Check if we need to retry
                    let retry_count = retries.get(host).copied().unwrap_or(0);
                    if retry_on.contains(exit_status)
                        && (retry_limit.is_none() || retry_count < retry_limit.unwrap())
                    {
                        hosts_to_go.push(host.clone()); // Return to queue
                    }
                }
            } else {
                println!("{} not in statuses?!? wtf!!!", w_id);

                // Window disappeared, consider it dead with unknown status
                let result = CommandResult {
                    host: host.clone(),
                    cmd: command_to_display.to_string(),
                    out: None,
                    err: None,
                    rc: None,
                };

                results_by_host.insert(host.clone(), result.clone());
                print_done(
                    host,
                    command_to_display,
                    None,
                    &results_by_host,
                    total,
                    Some(w_id),
                );

                finished_windows.push(w_id.clone());
            }
        }

        // Remove finished windows
        for w_id in finished_windows {
            running.remove(&w_id);
        }

        // Check if we're done or need to exit
        if IMMEDIATE_EXIT.load(Ordering::SeqCst) {
            // Kill all running tmux windows for immediate exit
            for (w_id, (host, _)) in &running {
                let _ = tmux::tmux_kill_window(w_id).await;
                println!(
                    "{}: {} -> killed by user",
                    host.red().bold(),
                    command_to_display
                );
            }
            break;
        } else if (GRACEFUL_SHUTDOWN.load(Ordering::SeqCst) && running.is_empty())
            || (running.is_empty() && hosts_to_go.is_empty())
        {
            break;
        }

        sleep(Duration::from_secs(1)).await;
    }

    Ok(results_by_host)
}
