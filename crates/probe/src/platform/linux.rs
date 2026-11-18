//! Linux: procfs. Sockets are matched to processes through their inode
//! (/proc/net/{tcp,udp}[6] -> /proc/<pid>/fd), like `ss -p`.

use std::fs;

use super::{OsInfo, PidBasic};
use crate::net::{FlowKey, TCP};

pub fn basic(pid: i32) -> Option<PidBasic> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // comm is in parentheses and may contain spaces.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat[open + 1..close].to_string();
    let f: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    let ppid = f.get(1)?.parse().ok()?;
    let start_ticks: u64 = f.get(19)?.parse().ok()?;
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let btime = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse::<u64>().ok()))?;
    let uid = fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:").and_then(|v| v.split_whitespace().next()?.parse().ok()))?;
    Some(PidBasic {
        ppid,
        uid: Some(uid),
        start_us: btime * 1_000_000 + start_ticks * 1_000_000 / ticks,
        name,
    })
}

pub fn exe_path(pid: i32) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid)).ok().map(|p| p.to_string_lossy().into_owned())
}

pub fn args(pid: i32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    Some(raw.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
}

pub fn responsible_pid(_pid: i32) -> Option<i32> {
    None
}

pub fn mapped_files(pid: i32) -> Vec<String> {
    let mut out: Vec<String> = fs::read_to_string(format!("/proc/{}/maps", pid))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(5).filter(|p| p.starts_with('/')).map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn socket_owner(key: &FlowKey) -> Option<i32> {
    let tables: &[&str] = if key.proto == TCP { &["tcp", "tcp6"] } else { &["udp", "udp6"] };
    let port = format!(":{:04X}", key.sport);
    let mut inode = None;
    for t in tables {
        let Ok(s) = fs::read_to_string(format!("/proc/net/{}", t)) else { continue };
        for l in s.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() > 9 && f[1].ends_with(&port) {
                inode = Some(f[9].to_string());
                break;
            }
        }
        if inode.is_some() {
            break;
        }
    }
    let target = format!("socket:[{}]", inode?);
    for e in fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(fds) = fs::read_dir(e.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            if fs::read_link(fd.path()).map_or(false, |l| l.to_string_lossy() == target) {
                return Some(pid);
            }
        }
    }
    None
}

pub fn os_info() -> OsInfo {
    let rel = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get = |k: &str| {
        rel.lines()
            .find_map(|l| l.strip_prefix(k).map(|v| v.trim_matches('"').to_string()))
    };
    OsInfo {
        os: "linux".into(),
        version: get("PRETTY_NAME="),
        build: get("VERSION_ID="),
        kernel: fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|s| s.trim().to_string()),
        model: None,
        arch: std::env::consts::ARCH.into(),
    }
}

pub const DEFAULT_DEVICE: &str = "any";
