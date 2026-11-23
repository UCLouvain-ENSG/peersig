//! The probe's daily logs (`peersig-<YYYYMMDD>.jsonl` in its directory),
//! read into the items of one period: a week for a participant, a day for
//! an observer. Used by the app and by the headless `peersig`.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::item::{os_label, ts, Collector, Observed, Skipped};
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

/// The system the latest `start` record names, as items carry it:
/// `Ok("linux debian 12")`, or `Err(what the probe recorded)` when no
/// label can be made of it, and then no ClientHello becomes an item.
/// `None` before the probe has written a record.
pub fn system(dir: &Path) -> Option<Result<String, String>> {
    let f = File::open(files(dir).pop()?).ok()?;
    let mut os = None;
    for line in BufReader::new(f).lines().map_while(Result::ok) {
        if line.contains(r#""type":"start""#) {
            if let Some(v) = serde_json::from_str::<Value>(&line).ok().and_then(|v| v.get("os").cloned()) {
                os = Some(v);
            }
        }
    }
    let os = os?;
    Some(crate::item::os_label(&os).ok_or_else(|| os.to_string()))
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

/// The logs, read once, for an app that looks at them again and again
/// (`collect` reads one period for one command). Each file's records are
/// kept as the items of their periods, and a file that grew is read again
/// only from where it was: a week of logs can be hundreds of megabytes.
pub struct Index {
    spec: EpochSpec,
    share_domains: bool,
    files: BTreeMap<PathBuf, Indexed>,
}

/// What one daily file held so far.
struct Indexed {
    /// Bytes read: whole lines only, a line being written is read next time.
    read: u64,
    /// The system of the last `start` record so far (to begin with, the
    /// previous file's: records follow the `start` that gives their OS).
    os: Option<String>,
    periods: BTreeMap<u32, Collector>,
    /// ClientHellos in the file, whatever their period.
    hellos: u64,
}

impl Indexed {
    fn new(os: Option<String>) -> Indexed {
        Indexed { read: 0, os, periods: BTreeMap::new(), hellos: 0 }
    }

    fn read_more(&mut self, path: &Path, spec: EpochSpec, share_domains: bool) {
        let Ok(mut f) = File::open(path) else { return };
        if f.seek(SeekFrom::Start(self.read)).is_err() {
            return;
        }
        let mut r = BufReader::with_capacity(1 << 16, f);
        let mut line = Vec::new();
        loop {
            line.clear();
            match r.read_until(b'\n', &mut line) {
                Ok(n) if n > 0 && line.ends_with(b"\n") => self.read += n as u64,
                _ => break,
            }
            if let Ok(text) = std::str::from_utf8(&line) {
                self.record(text, spec, share_domains);
            }
        }
    }

    fn record(&mut self, line: &str, spec: EpochSpec, share_domains: bool) {
        // Only the record types items come from.
        if !(line.contains(r#""type":"hello""#) || line.contains(r#""type":"domain""#) || line.contains(r#""type":"start""#)) {
            return;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else { return };
        let field = match v.get("type").and_then(|t| t.as_str()) {
            Some("start") => {
                if let Some(os) = v.get("os").and_then(os_label) {
                    self.os = Some(os);
                }
                return;
            }
            Some("hello") => {
                self.hellos += 1;
                "ts"
            }
            Some("domain") => "last",
            _ => return,
        };
        let Some(e) = ts(&v, field).and_then(|t| spec.at(t)) else { return };
        let c = self.periods.entry(e).or_insert_with(|| Collector::new(spec, e, share_domains));
        c.set_os(&self.os);
        c.record(&v);
    }
}

impl Index {
    pub fn new(spec: EpochSpec, share_domains: bool) -> Index {
        Index { spec, share_domains, files: BTreeMap::new() }
    }

    /// Whether this index answers for these periods and this choice.
    pub fn is_for(&self, spec: EpochSpec, share_domains: bool) -> bool {
        self.spec == spec && self.share_domains == share_domains
    }

    /// Reads what was written since the last time, and forgets the files
    /// that are gone.
    pub fn update(&mut self, dir: &Path) {
        let paths = files(dir);
        self.files.retain(|p, _| paths.contains(p));
        let mut os: Option<String> = None;
        for p in paths {
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let f = self.files.entry(p.clone()).or_insert_with(|| Indexed::new(os.clone()));
            // Shorter than what was read: another file now, read it again.
            if len < f.read {
                *f = Indexed::new(os.clone());
            }
            if len > f.read {
                f.read_more(&p, self.spec, self.share_domains);
            }
            os = f.os.clone();
        }
    }

    /// Items of `epoch`, as `collect` finds them.
    pub fn items(&self, epoch: u32) -> (Vec<Observed>, Skipped) {
        let mut all = Collector::new(self.spec, epoch, self.share_domains);
        for f in self.files.values() {
            if let Some(c) = f.periods.get(&epoch) {
                all.absorb(c);
            }
        }
        all.finish()
    }

    /// ClientHellos of `epoch`, with an application or not.
    pub fn hellos(&self, epoch: u32) -> u64 {
        self.files.values().filter_map(|f| f.periods.get(&epoch)).map(|c| c.hellos).sum()
    }

    /// ClientHellos in each daily file, by its day (`20261123`).
    pub fn hellos_per_file(&self) -> Vec<(String, u64)> {
        self.files
            .iter()
            .filter_map(|(p, f)| {
                let day = p.file_stem()?.to_str()?.strip_prefix("peersig-")?;
                Some((day.to_string(), f.hellos))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn line(f: &mut File, v: serde_json::Value) {
        writeln!(f, "{}", v).unwrap();
    }

    fn hello(ts: &str, app: &str, ja4: &str) -> serde_json::Value {
        serde_json::json!({"type":"hello","ts":ts,"transport":"tcp","ja4":ja4,"proc":app.to_lowercase(),
            "src":"10.0.0.2:5000","dst":"1.2.3.4:443","app":{"name":app,"version":"1.0","kind":"app"}})
    }

    fn keys(v: &(Vec<Observed>, Skipped)) -> Vec<(String, u64)> {
        v.0.iter().map(|o| (o.key.clone(), o.count)).collect()
    }

    /// The index finds what `collect` finds, reads a file that grew from
    /// where it was, leaves a line being written for later, and counts the
    /// ClientHellos of each period and file.
    #[test]
    fn index_reads_what_is_new() {
        let dir = std::env::temp_dir().join(format!("peersig-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let spec = EpochSpec { origin: 1794787200, length: EpochSpec::WEEK }; // Mon 16 Nov 2026, UTC
        let (a, b) = ("t13d1516h2_8daaf6152771_e5627efa2ab1", "t13d1516h2_8daaf6152771_000000000001");
        let mut f1 = File::create(dir.join("peersig-20261122.jsonl")).unwrap();
        line(&mut f1, serde_json::json!({"type":"start","os":{"os":"macos","version":"27.0.1"}}));
        line(&mut f1, hello("2026-11-22T12:00:00Z", "Slack", a));
        line(&mut f1, hello("2026-11-22T13:00:00Z", "Slack", a));
        line(&mut f1, serde_json::json!({"type":"hello","ts":"2026-11-22T13:00:00Z","transport":"tcp","ja4":a,"app":{"name":"unknown","kind":"unknown"}}));
        line(&mut f1, serde_json::json!({"type":"stats","packets":3}));
        // Local midnight is 23:00 UTC: this one is in the next week.
        line(&mut f1, hello("2026-11-23T00:30:00Z", "Zoom", b));
        drop(f1);
        let mut idx = Index::new(spec, true);
        idx.update(&dir);
        for e in [0, 1] {
            assert_eq!(keys(&idx.items(e)), keys(&collect(&dir, spec, e, true)), "epoch {}", e);
        }
        assert_eq!(idx.items(0).0.len(), 1);
        assert_eq!(idx.items(0).0[0].count, 2);
        assert_eq!(idx.items(0).1.unattributed, 1);
        assert_eq!((idx.hellos(0), idx.hellos(1)), (3, 1));

        // A new file without a `start` record of its own (the previous
        // one's system), and a last line still being written.
        let p2 = dir.join("peersig-20261123.jsonl");
        let mut f2 = File::create(&p2).unwrap();
        line(&mut f2, hello("2026-11-23T08:00:00Z", "Zoom", b));
        write!(f2, "{}", &hello("2026-11-23T09:00:00Z", "Zoom", b).to_string()[..40]).unwrap();
        f2.flush().unwrap();
        idx.update(&dir);
        assert_eq!(idx.hellos(1), 2, "the partial line waits");
        let rest = &hello("2026-11-23T09:00:00Z", "Zoom", b).to_string()[40..];
        writeln!(f2, "{}", rest).unwrap();
        line(&mut f2, hello("2026-11-23T10:00:00Z", "Slack", a));
        drop(f2);
        idx.update(&dir);
        assert_eq!(idx.hellos(1), 4);
        for e in [0, 1] {
            assert_eq!(keys(&idx.items(e)), keys(&collect(&dir, spec, e, true)), "epoch {}", e);
        }
        let zoom = idx.items(1).0.into_iter().find(|o| o.key.contains("Zoom")).unwrap();
        assert_eq!(zoom.count, 3);
        assert!(zoom.key.contains("macos 27"));
        assert_eq!(idx.hellos_per_file(), vec![("20261122".to_string(), 4), ("20261123".to_string(), 3)]);

        // A file deleted (the probe keeps two weeks) is forgotten.
        std::fs::remove_file(dir.join("peersig-20261122.jsonl")).unwrap();
        idx.update(&dir);
        assert_eq!(idx.hellos(0), 0);
        assert_eq!(idx.hellos_per_file().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
