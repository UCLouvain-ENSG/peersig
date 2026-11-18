//! `/etc/peersig/observer.conf`: the observer's settings, as `KEY=VALUE`
//! lines (no quotes, no expansion, `#` comments), the variables the
//! options read (`PEERSIG_CODE`, `PEERSIG_SERVER`, `PEERSIG_SHARE_DOMAINS`,
//! `PEERSIG_LOGS`). `peersig-observer configure` writes it; every command
//! reads it first, so that options and the environment override it.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub const DEFAULT_PATH: &str = "/etc/peersig/observer.conf";
/// The variables the file may set.
pub const KEYS: [&str; 4] = ["PEERSIG_SERVER", "PEERSIG_CODE", "PEERSIG_SHARE_DOMAINS", "PEERSIG_LOGS"];

pub fn parse(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| KEYS.contains(&k.as_str()))
        .collect()
}

/// `--config <path>` or `--config=<path>` on the command line, then
/// `PEERSIG_CONFIG`, then the default.
pub fn path_from(args: &[OsString]) -> PathBuf {
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        let a = a.to_string_lossy();
        if a == "--config" {
            if let Some(p) = it.next() {
                return PathBuf::from(p);
            }
        } else if let Some(p) = a.strip_prefix("--config=") {
            return PathBuf::from(p);
        }
    }
    std::env::var_os("PEERSIG_CONFIG").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(DEFAULT_PATH))
}

/// What reading the file gave.
pub enum Loaded {
    /// No such file.
    Missing,
    /// Read: its settings are in the environment, under what was there.
    Read,
    /// The file exists but this user cannot read it.
    Unreadable(String),
}

/// Puts the file's settings in the environment, under those already there.
/// Runs before the options are parsed, while the program has one thread.
pub fn load(path: &Path) -> Loaded {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Loaded::Missing,
        Err(e) => return Loaded::Unreadable(format!("cannot read {}: {}", path.display(), e)),
    };
    for (k, v) in parse(&text) {
        if std::env::var_os(&k).is_none() {
            std::env::set_var(&k, v);
        }
    }
    Loaded::Read
}

/// The settings `configure` writes.
pub struct Settings {
    pub server: String,
    pub code: String,
    pub share_domains: bool,
    pub logs: PathBuf,
}

/// Writes the file, readable by root and the `peersig` group only (the
/// code lets anyone holding it publish as this observer).
pub fn write(path: &Path, s: &Settings) -> Result<()> {
    let dir = path.parent().context("no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let text = format!(
        "# PeerSig dedicated observer (docs/observers.md), written by `peersig-observer configure`.\n\
         # KEY=VALUE, no quotes. Readable by root and the peersig group only: the code lets\n\
         # whoever holds it report as this observer.\n\
         PEERSIG_SERVER={}\nPEERSIG_CODE={}\nPEERSIG_SHARE_DOMAINS={}\nPEERSIG_LOGS={}\n",
        s.server,
        s.code,
        s.share_domains,
        s.logs.display()
    );
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o640);
        let mut f = o.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
    }
    // Whatever the umask: the service reads it through its group.
    #[cfg(unix)]
    std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o640))?;
    #[cfg(unix)]
    if let Some(gid) = group_id("peersig") {
        std::os::unix::fs::chown(&tmp, None, Some(gid)).with_context(|| format!("giving {} to the peersig group", tmp.display()))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// A group's id, from /etc/group.
#[cfg(unix)]
pub fn group_id(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/etc/group").ok()?;
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_writes() {
        let v = parse("# c\nPEERSIG_CODE = OBS-1\n\nPEERSIG_SHARE_DOMAINS=true\nOTHER=x\nnot a line\n");
        assert_eq!(v, [("PEERSIG_CODE".to_string(), "OBS-1".to_string()), ("PEERSIG_SHARE_DOMAINS".into(), "true".into())]);
        let args = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(path_from(&args(&["x", "status", "--config", "/tmp/a.conf"])), PathBuf::from("/tmp/a.conf"));
        assert_eq!(path_from(&args(&["x", "--config=/tmp/b.conf", "run"])), PathBuf::from("/tmp/b.conf"));

        let dir = std::env::temp_dir().join(format!("peersig-observer-conf-{}", std::process::id()));
        let p = dir.join("sub/observer.conf");
        let s = Settings { server: "https://peersig.org".into(), code: "OBS-K7QF-2M9D-XW4P".into(), share_domains: true, logs: "/var/lib/peersig/logs".into() };
        write(&p, &s).unwrap();
        write(&p, &s).unwrap();
        let back = parse(&std::fs::read_to_string(&p).unwrap());
        assert_eq!(back.len(), 4);
        assert!(back.contains(&("PEERSIG_CODE".into(), "OBS-K7QF-2M9D-XW4P".into())));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o640);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
