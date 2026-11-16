//! Daemon mode (`run --dir`): one log file per day, deleted after
//! `--keep-days`; a `status.json` heartbeat the PeerSig app shows; and a
//! `paused` file the app creates to stop the capture.
//!
//! Files belong to the participant (`--owner`, or the user who ran sudo)
//! and nobody else can read them.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub struct LogDir {
    dir: PathBuf,
    owner: Option<(u32, u32)>,
    keep_days: u32,
    day: String,
}

fn today() -> String {
    chrono::Local::now().format("%Y%m%d").to_string()
}

/// uid and gid of a user name or numeric uid.
#[cfg(unix)]
pub fn resolve_owner(who: Option<&str>) -> Result<Option<(u32, u32)>> {
    if let Some(who) = who {
        let pw = match who.parse::<u32>() {
            Ok(uid) => unsafe { libc::getpwuid(uid) },
            Err(_) => {
                let c = std::ffi::CString::new(who)?;
                unsafe { libc::getpwnam(c.as_ptr()) }
            }
        };
        anyhow::ensure!(!pw.is_null(), "no user {}", who);
        let pw = unsafe { &*pw };
        return Ok(Some((pw.pw_uid, pw.pw_gid)));
    }
    match (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        (Ok(u), Ok(g)) => Ok(u.parse().ok().zip(g.parse().ok())),
        _ => Ok(None),
    }
}

#[cfg(not(unix))]
pub fn resolve_owner(_who: Option<&str>) -> Result<Option<(u32, u32)>> {
    Ok(None)
}

impl LogDir {
    pub fn new(dir: &Path, owner: Option<(u32, u32)>, keep_days: u32) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
        let d = LogDir { dir: dir.to_path_buf(), owner, keep_days, day: String::new() };
        d.own(dir, 0o700);
        Ok(d)
    }

    #[cfg(unix)]
    fn own(&self, path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
        if let Some((uid, gid)) = self.owner {
            if let Ok(c) = std::ffi::CString::new(path.as_os_str().to_string_lossy().as_bytes()) {
                unsafe { libc::chown(c.as_ptr(), uid, gid) };
            }
        }
    }

    #[cfg(not(unix))]
    fn own(&self, _path: &Path, _mode: u32) {}

    pub fn needs_rotation(&self) -> bool {
        self.day != today()
    }

    /// Today's file, appended to (a restart the same day continues it).
    pub fn open_today(&mut self) -> Result<(Box<dyn Write + Send>, PathBuf)> {
        self.day = today();
        let path = self.dir.join(format!("peersig-{}.jsonl", self.day));
        let f = OpenOptions::new().create(true).append(true).open(&path).with_context(|| path.display().to_string())?;
        self.own(&path, 0o600);
        Ok((Box::new(BufWriter::with_capacity(1 << 16, f)), path))
    }

    /// Deletes daily files older than `keep_days`.
    pub fn prune(&self) {
        let cutoff = (chrono::Local::now() - chrono::Duration::days(self.keep_days as i64)).format("%Y%m%d").to_string();
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(day) = name.strip_prefix("peersig-").and_then(|n| n.strip_suffix(".jsonl")) {
                if day.len() == 8 && day < cutoff.as_str() {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
    }

    pub fn paused(&self) -> bool {
        self.dir.join("paused").exists()
    }

    /// Replaces status.json atomically.
    pub fn write_status(&self, v: &serde_json::Value) {
        let tmp = self.dir.join("status.json.tmp");
        let ok = File::create(&tmp).and_then(|mut f| f.write_all(serde_json::to_string_pretty(v).unwrap_or_default().as_bytes()));
        if ok.is_ok() {
            self.own(&tmp, 0o644);
            let _ = fs::rename(&tmp, self.dir.join("status.json"));
        }
    }
}
