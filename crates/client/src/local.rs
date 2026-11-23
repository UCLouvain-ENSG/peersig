//! What the probe left on this computer: its status file and daily logs.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::Value;

use peersig_proto::EpochSpec;

#[derive(Serialize, Clone, Default, Debug)]
pub struct ProbeStatus {
    /// The status file was updated in the last 30 s.
    pub running: bool,
    pub paused: bool,
    /// Per-packet process data (macOS PKTAP).
    pub pktap: bool,
    pub packets: u64,
    pub hellos: u64,
    pub last_hello: Option<String>,
    pub started: Option<String>,
    pub tool: Option<String>,
    pub file: Option<String>,
    /// Why the probe cannot capture yet (it retries meanwhile).
    pub error: Option<String>,
}

pub fn status(dir: &Path) -> ProbeStatus {
    let path = dir.join("status.json");
    let Ok(text) = std::fs::read_to_string(&path) else { return ProbeStatus::default() };
    let Ok(v) = serde_json::from_str::<Value>(&text) else { return ProbeStatus::default() };
    let fresh = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|d| d.as_secs() < 30);
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let hellos = v.get("hellos").map(|h| ["tcp", "quic", "dtls"].iter().filter_map(|k| h.get(*k)?.as_u64()).sum()).unwrap_or(0);
    let error = if fresh { s("error") } else { None };
    ProbeStatus {
        running: fresh && v.get("stopped").is_none() && error.is_none(),
        error,
        paused: v.get("paused").and_then(|x| x.as_bool()).unwrap_or(false),
        pktap: v.get("pktap").and_then(|x| x.as_bool()).unwrap_or(false),
        packets: v.get("packets").and_then(|x| x.as_u64()).unwrap_or(0),
        hellos,
        last_hello: s("last_hello"),
        started: s("started"),
        tool: s("tool"),
        file: s("file"),
    }
}

use peersig_proto::logs::Index;

/// The logs' index (`peersig_proto::logs::Index`), shared by the window's
/// commands and the worker. It has a lock of its own, not the core's: the
/// first read of two weeks of logs can take seconds, and the window and
/// the tray must not wait for it.
#[derive(Default)]
pub struct Logs {
    index: Option<(PathBuf, Index)>,
}

pub type SharedLogs = Arc<Mutex<Logs>>;

impl Logs {
    /// Reads what is new in `dir`'s logs, then runs `f` on them. A new
    /// folder, period length or sharing choice starts a new index.
    pub fn with<T>(&mut self, dir: &Path, spec: EpochSpec, share_domains: bool, f: impl FnOnce(&Index) -> T) -> T {
        let reuse = matches!(&self.index, Some((d, i)) if d == dir && i.is_for(spec, share_domains));
        if !reuse {
            self.index = Some((dir.to_path_buf(), Index::new(spec, share_domains)));
        }
        let (_, index) = self.index.as_mut().expect("just set");
        index.update(dir);
        f(index)
    }
}

/// Words that would name the person in an item: the account's name and
/// the person's full name, as the system knows them
/// (`peersig_proto::sensitive::own_word`: 4 letters or more). They stay on
/// this device.
pub fn own_words() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for var in ["USER", "USERNAME"] {
        if let Ok(v) = std::env::var(var) {
            names.push(v);
        }
    }
    if let Some(full) = full_name() {
        names.extend(full.split(|c: char| !c.is_alphanumeric()).map(String::from));
        names.push(full);
    }
    let mut out: Vec<String> = Vec::new();
    for w in names.iter().filter_map(|n| peersig_proto::sensitive::own_word(n)) {
        if !out.contains(&w) {
            out.push(w);
        }
    }
    out
}

#[cfg(target_os = "macos")]
fn full_name() -> Option<String> {
    let out = std::process::Command::new("/usr/bin/id").arg("-F").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

/// The comment field of the account's line in /etc/passwd.
#[cfg(all(unix, not(target_os = "macos"), not(target_os = "android")))]
fn full_name() -> Option<String> {
    let user = std::env::var("USER").ok()?;
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    let line = passwd.lines().find(|l| l.split(':').next() == Some(user.as_str()))?;
    let gecos = line.split(':').nth(4)?.split(',').next()?.trim().to_string();
    (!gecos.is_empty()).then_some(gecos)
}

#[cfg(any(windows, target_os = "android"))]
fn full_name() -> Option<String> {
    None
}
