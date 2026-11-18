//! What the probe left on this computer: its status file and daily logs.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::Value;

use peersig_proto::item::{Collector, Observed, Skipped};
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

/// Daily log files, oldest first.
fn logs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("peersig-") && n.ends_with(".jsonl")))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Items of `epoch` found in the logs. Files are read whole, in order, so
/// each `hello` follows the `start` record that gives the OS.
pub fn collect(dir: &Path, spec: EpochSpec, epoch: u32, share_domains: bool) -> (Vec<Observed>, Skipped) {
    let mut c = Collector::new(spec, epoch, share_domains);
    // A file named after a day entirely outside the epoch is skipped.
    let (from, to) = (spec.start(epoch) - 86400, spec.end(epoch) + 86400);
    for path in logs(dir) {
        let day = path.file_stem().and_then(|n| n.to_str()).and_then(|n| n.strip_prefix("peersig-")).unwrap_or("");
        if let Ok(d) = chrono::NaiveDate::parse_from_str(day, "%Y%m%d") {
            let t = d.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp();
            if t < from || t > to {
                continue;
            }
        }
        let Ok(f) = File::open(&path) else { continue };
        for line in BufReader::new(f).lines().map_while(Result::ok) {
            // Only the record types items come from.
            if !(line.contains(r#""type":"hello""#) || line.contains(r#""type":"domain""#) || line.contains(r#""type":"start""#)) {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                c.record(&v);
            }
        }
    }
    c.finish()
}

/// `collect` is a full read of a week of logs: cache it per (epoch, sharing)
/// until the files change.
#[derive(Default)]
pub struct Cache {
    entries: HashMap<(u32, bool), (Vec<(PathBuf, u64)>, Vec<Observed>, Skipped)>,
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
        if let Some((f, o, s)) = self.entries.get(&(epoch, share_domains)) {
            if *f == fp {
                return (o.clone(), s.clone());
            }
        }
        let (o, s) = collect(dir, spec, epoch, share_domains);
        self.entries.retain(|(e, _), _| e + 2 >= epoch);
        self.entries.insert((epoch, share_domains), (fp, o.clone(), s.clone()));
        (o, s)
    }
}
