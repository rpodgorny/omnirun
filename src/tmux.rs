use anyhow::{anyhow, Result};
use std::collections::HashMap;
use tokio::process::Command;

pub const TMUX: &str = "/usr/bin/tmux";

pub async fn tmux_window_statuses() -> Result<HashMap<String, (bool, Option<i32>)>> {
    let output = Command::new(TMUX)
        .args([
            "list-windows",
            "-F",
            "#{window_id} #{pane_dead} #{pane_dead_status}",
        ])
        .output()
        .await?;

    let output_str = String::from_utf8(output.stdout)?;
    let mut ret = HashMap::new();

    for line in output_str.split('\n') {
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        let w_id = parts[0].to_string();
        let pane_dead = match parts[1] {
            "0" => false,
            "1" => true,
            _ => return Err(anyhow!("Unexpected pane_dead value: {}", parts[1])),
        };

        // no status is shown for live panes (or when using old version of tmux)
        let pane_dead_status = if parts.len() > 2 {
            Some(parts[2].parse::<i32>()?)
        } else {
            None
        };

        ret.insert(w_id, (pane_dead, pane_dead_status));
    }

    Ok(ret)
}

pub async fn tmux_new_window(name: &str, cmd: Option<&str>) -> Result<String> {
    let mut args = vec!["new-window", "-n", name, "-P", "-F", "#{window_id}", "-d"];

    if let Some(cmd_str) = cmd {
        args.push(cmd_str);
    }

    let output = Command::new(TMUX).args(&args).output().await?;

    let output_str = String::from_utf8(output.stdout)?;
    let w_id = output_str.split('\n').next().unwrap_or("").to_string();

    if w_id.is_empty() {
        return Err(anyhow!("Failed to get window ID"));
    }

    Ok(w_id)
}

pub async fn tmux_kill_window(w_id: &str) -> Result<()> {
    // TODO: this has crashed for me once so i added the try/except. maybe i should solve it elsewhere, too.
    let result = Command::new(TMUX)
        .args(["kill-window", "-t", &format!(":{w_id}")])
        .status()
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) => {
            // Just log the error but continue
            eprintln!("Error killing tmux window: {}", e);
            Ok(())
        }
    }
}

pub async fn tmux_send_keys(w_id: &str, cmd: &str, enter: bool) -> Result<()> {
    let mut command = Command::new(TMUX);
    command.args(["send-keys", "-t", &format!(":{w_id}"), "-l", cmd]);

    if enter {
        command.args([";", "send-keys", "-t", &format!(":{w_id}"), "Enter"]);
    }

    command.output().await?;
    Ok(())
}

pub async fn tmux_respawn_pane(w_id: &str, cmd: &str) -> Result<()> {
    Command::new(TMUX)
        .args(["respawn-pane", "-t", &format!(":{w_id}"), "-k", cmd])
        .output()
        .await?;

    Ok(())
}

// TODO: this generates a lot of whitespace and tmux-related strings (-> so far unusable)
pub async fn tmux_capture_pane(w_id: &str) -> Result<String> {
    let output = Command::new(TMUX)
        .args([
            "capture-pane",
            "-t",
            &format!(":{w_id}"),
            "-p",
            "-J",
            "-S",
            "-",
            "-E",
            "-",
        ])
        .output()
        .await?;

    Ok(String::from_utf8(output.stdout)?)
}

pub async fn tmux_set_window_option(w_id: &str, option: &str, value: &str) -> Result<()> {
    // TODO: why is the window_id format different here?
    Command::new(TMUX)
        .args(["set-window-option", "-t", w_id, option, value])
        .status()
        .await?;

    Ok(())
}

