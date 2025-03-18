use anyhow::{anyhow, Result};
use std::collections::HashSet;

pub mod tmux;
pub mod version;

/// Expands hostname patterns that contain numeric ranges in square brackets.
///
/// For example:
/// - "192.168.100.[1-100]" will expand to 100 hosts from 192.168.100.1 to 192.168.100.100
/// - "server[1-3,5,7-9].example.com" will expand to server1.example.com, server2.example.com, etc.
///
/// If the input doesn't contain brackets with ranges, it will return a vector with just the input.
pub fn expand_host(s: &str) -> Result<Vec<String>> {
    if !s.contains('[') || !s.contains('-') || !s.contains(']') {
        return Ok(vec![s.to_string()]);
    }

    let parts: Vec<&str> = s.split('[').collect();
    let pre = parts[0];

    let parts: Vec<&str> = parts[1].split(']').collect();
    let in_brackets = parts[0];
    let post = parts[1];

    let mut ret = Vec::new();
    for i in in_brackets.split(',') {
        let i = i.trim();
        if i.is_empty() {
            continue
        }

        if i.contains('-') {
            let range: Vec<&str> = i.split('-').collect();
            if range.len() != 2 {
                return Err(anyhow!("Invalid range format: {i}"));
            }

            let from: i32 = range[0].parse()?;
            let to: i32 = range[1].parse()?;

            for j in from..=to {
                ret.push(format!("{pre}{j}{post}"));
            }
        } else {
            ret.push(format!("{pre}{i}{post}"));
        }
    }

    Ok(ret)
}

/// Parses a host specification string into its components.
///
/// Input format: [<username>[:<password>]@]<hostname>[:<port>]
///
/// Returns a tuple of (username, password, hostname, port) where each component
/// is an Option that will be None if that part wasn't specified.
pub fn hostspec_to_user_pass_host_port(
    s: &str,
) -> Result<(Option<String>, Option<String>, Option<String>, Option<u16>)> {
    let mut user = None;
    let mut pass = None;
    let mut host = None;
    let mut port = None;

    if s.contains('@') {
        let parts: Vec<&str> = s.split('@').collect();
        let user_pass = parts[0];

        if parts.len() > 1 {
            host = Some(parts[1].to_string());
        }

        if user_pass.contains(':') {
            let up_parts: Vec<&str> = user_pass.split(':').collect();
            user = Some(up_parts[0].to_string());

            if up_parts.len() > 1 && !up_parts[1].is_empty() {
                pass = Some(up_parts[1].to_string());
            }
        } else {
            user = Some(user_pass.to_string());
        }
    } else if !s.is_empty() {
        host = Some(s.to_string());
    }

    // Create a new host string if it contains a port
    let mut host_ = host.clone();

    if let Some(ref host_str) = host {
        if host_str.contains(':') {
            let parts: Vec<&str> = host_str.split(':').collect();

            host_ = Some(parts[0].to_string());

            if parts.len() > 1 {
                port = Some(parts[1].parse()?);
            }
        }
    }

    Ok((user, pass, host_, port))
}

/// Parses return code specifications used for retry/keep-open options.
///
/// Input format is a comma-separated list of:
/// - numeric values (e.g. 0,1,2)
/// - "unknown" (represented as None)
/// - "nonzero" (shorthand for all codes 1-255)
///
/// Returns a HashSet of Option<i32> where None represents "unknown" status.
pub fn rc_parse(s: Option<&String>) -> Result<HashSet<Option<i32>>> {
    let mut ret = HashSet::new();

    if let Some(codes) = s {
        let rc_parts: Vec<&str> = codes.split(',').collect();

        for part in rc_parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if part == "unknown" {
                ret.insert(None);
            } else if part == "nonzero" {
                for i in 1..256 {
                    ret.insert(Some(i));
                }
            } else {
                ret.insert(Some(part.parse()?));
            }
        }
    }

    Ok(ret)
}

