//! What the probe left on this computer: its status file and daily logs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::Value;

use peersig_proto::item::{Observed, Skipped};
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

use peersig_proto::logs::collect;
use peersig_proto::logs::files as logs;

/// `collect` is a full read of a period's logs: cache it per (period
/// length, epoch, sharing) until the files change.
#[derive(Default)]
pub struct Cache {
    entries: HashMap<(i64, u32, bool), (Vec<(PathBuf, u64)>, Vec<Observed>, Skipped)>,
}

fn fingerprint(dir: &Path) -> Vec<(PathBuf, u64)> {
    logs(dir).into_iter().map(|p| {
        let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        (p, len)
    }).collect()
}

impl Cache {
    pub fn get(&mut self, dir: &Path, spec: EpochSpec, epoch: u32, share_domains: bool) -> (Vec<Observed>, Skipped) {
        let fp = fingerprint(dir);
        let key = (spec.length, epoch, share_domains);
        if let Some((f, o, s)) = self.entries.get(&key) {
            if *f == fp {
                return (o.clone(), s.clone());
            }
        }
        let (o, s) = collect(dir, spec, epoch, share_domains);
        self.entries.retain(|(l, e, _), _| *l == spec.length && e + 2 >= epoch);
        self.entries.insert(key, (fp, o.clone(), s.clone()));
        (o, s)
    }
}
