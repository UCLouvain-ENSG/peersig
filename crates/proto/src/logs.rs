//! The probe's daily logs (`peersig-<YYYYMMDD>.jsonl` in its directory),
//! read into the items of one period: a week for a participant, a day for
//! an observer. Used by the app and by the headless `peersig`.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::item::{Collector, Observed, Skipped};
use crate::EpochSpec;

/// Daily log files, oldest first.
pub fn files(dir: &Path) -> Vec<PathBuf> {
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
/// each `hello` follows the `start` record that gives the OS (the probe
/// writes one at the top of every daily file).
pub fn collect(dir: &Path, spec: EpochSpec, epoch: u32, share_domains: bool) -> (Vec<Observed>, Skipped) {
    let mut c = Collector::new(spec, epoch, share_domains);
    // A file named after a day entirely outside the epoch is skipped.
    let (from, to) = (spec.start(epoch) - 86400, spec.end(epoch) + 86400);
    for path in files(dir) {
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
