//! Daemon mode (`run --dir`): one log file per day, deleted after
//! `--keep-days`; a `status.json` heartbeat the PeerSig app shows; and a
//! `paused` file the app creates to stop the capture.
//!
//! Files belong to the participant (`--owner`, or the user who ran sudo)
//! and nobody else can read them. On Windows, where the probe runs as
//! LocalSystem, the directory gets a protected ACL instead: SYSTEM and
//! Administrators, and the participant's SID (list, read, create the
//! `paused` file; read and delete the logs). Files are opened without
//! following links, so the service cannot be made to write elsewhere.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Who the files are for: uid and gid on Unix, a SID on Windows.
#[cfg(unix)]
pub type Owner = (u32, u32);
#[cfg(windows)]
pub type Owner = String;
#[cfg(not(any(unix, windows)))]
pub type Owner = ();

pub struct LogDir {
    dir: PathBuf,
    owner: Option<Owner>,
    keep_days: u32,
    day: String,
}

fn today() -> String {
    chrono::Local::now().format("%Y%m%d").to_string()
}

/// uid and gid of a user name or numeric uid.
#[cfg(unix)]
pub fn resolve_owner(who: Option<&str>) -> Result<Option<Owner>> {
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

/// The participant's SID (`S-1-5-21-...`), as the app passes it.
#[cfg(windows)]
pub fn resolve_owner(who: Option<&str>) -> Result<Option<Owner>> {
    let Some(who) = who else { return Ok(None) };
    anyhow::ensure!(win::valid_sid(who), "--owner {:?}: not a SID (S-1-5-21-...)", who);
    Ok(Some(who.to_string()))
}

#[cfg(not(any(unix, windows)))]
pub fn resolve_owner(_who: Option<&str>) -> Result<Option<Owner>> {
    Ok(None)
}

/// Opens a file for the probe to write, refusing links: on Windows a
/// reparse point (symbolic link, junction) or a file with other hard
/// links, which could point anywhere on the system. `append` continues a
/// file; otherwise it is created anew.
pub fn open_private(path: &Path, append: bool) -> std::io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, not its target.
        const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        let mut o = OpenOptions::new();
        o.custom_flags(OPEN_REPARSE_POINT);
        if append {
            o.create(true).append(true);
        } else {
            // A link left in the way is removed (the link, not its target).
            let _ = fs::remove_file(path);
            o.write(true).create_new(true);
        }
        let f = o.open(path)?;
        if !win::plain_file(&f) {
            return Err(std::io::Error::other(format!("{} is a link: not writing to it", path.display())));
        }
        Ok(f)
    }
    #[cfg(not(windows))]
    {
        if append {
            OpenOptions::new().create(true).append(true).open(path)
        } else {
            File::create(path)
        }
    }
}

impl LogDir {
    pub fn new(dir: &Path, owner: Option<Owner>, keep_days: u32) -> Result<Self> {
        #[cfg(windows)]
        for p in [Some(dir), dir.parent()].into_iter().flatten() {
            anyhow::ensure!(!win::is_reparse_point(p), "{} is a link or junction: not using it", p.display());
        }
        fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
        let d = LogDir { dir: dir.to_path_buf(), owner, keep_days, day: String::new() };
        #[cfg(windows)]
        if let Some(sid) = &d.owner {
            win::secure_dir(dir, sid).with_context(|| format!("setting the access rights of {}", dir.display()))?;
        }
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

    /// Windows: files inherit the directory's ACL.
    #[cfg(not(unix))]
    fn own(&self, _path: &Path, _mode: u32) {
        let _ = &self.owner;
    }

    pub fn needs_rotation(&self) -> bool {
        self.day != today()
    }

    /// Today's file, appended to (a restart the same day continues it).
    pub fn open_today(&mut self) -> Result<(Box<dyn Write + Send>, PathBuf)> {
        self.day = today();
        let path = self.dir.join(format!("peersig-{}.jsonl", self.day));
        let f = open_private(&path, true).with_context(|| path.display().to_string())?;
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
        let ok = open_private(&tmp, false).and_then(|mut f| f.write_all(serde_json::to_string_pretty(v).unwrap_or_default().as_bytes()));
        if ok.is_ok() {
            self.own(&tmp, 0o644);
            let _ = fs::rename(&tmp, self.dir.join("status.json"));
        }
    }
}

#[cfg(windows)]
mod win {
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{LocalFree, ERROR_INVALID_OWNER};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        IsValidSid, SetFileSecurityW, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        INVALID_FILE_ATTRIBUTES,
    };

    use crate::platform::wide;

    /// `S-1-...` made of digits and dashes, and a SID Windows accepts. The
    /// string goes into an SDDL string, so nothing else may be in it.
    pub fn valid_sid(s: &str) -> bool {
        if !s.starts_with("S-1-") || s.len() > 184 || !s.bytes().all(|b| b.is_ascii_digit() || b == b'-' || b == b'S') {
            return false;
        }
        let mut sid: PSID = null_mut();
        let ok = unsafe { ConvertStringSidToSidW(wide(s).as_ptr(), &mut sid) } != 0;
        let valid = ok && unsafe { IsValidSid(sid) } != 0;
        if !sid.is_null() {
            unsafe { LocalFree(sid as _) };
        }
        valid
    }

    pub fn is_reparse_point(p: &Path) -> bool {
        let a = unsafe { GetFileAttributesW(wide(p).as_ptr()) };
        a != INVALID_FILE_ATTRIBUTES && a & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    /// Not a reparse point, and no other hard link to it.
    pub fn plain_file(f: &std::fs::File) -> bool {
        let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut i) } == 0 {
            return false;
        }
        i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 && i.nNumberOfLinks == 1
    }

    /// The log directory's ACL, not inherited: SYSTEM and Administrators
    /// have full control; the participant may list it and add files (the
    /// `paused` file), and may read, change and delete the files in it.
    /// The owner becomes SYSTEM when the probe runs as SYSTEM.
    pub fn secure_dir(dir: &Path, sid: &str) -> std::io::Result<()> {
        let dacl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200ab;;;{sid})(A;OIIO;0x1301bf;;;{sid})");
        let set = |sddl: &str, info: u32| -> std::io::Result<()> {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(sddl).as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let ok = unsafe { SetFileSecurityW(wide(dir).as_ptr(), info, sd) } != 0;
            let err = std::io::Error::last_os_error();
            unsafe { LocalFree(sd as _) };
            if ok {
                Ok(())
            } else {
                Err(err)
            }
        };
        let dacl_info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        match set(&format!("O:SY{}", dacl), OWNER_SECURITY_INFORMATION | dacl_info) {
            // Not running as SYSTEM: keep the owner, set the ACL.
            Err(e) if e.raw_os_error() == Some(ERROR_INVALID_OWNER as i32) => set(&dacl, dacl_info),
            r => r,
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn sids() {
        assert!(win::valid_sid("S-1-5-21-1004336348-1177238915-682003330-512"));
        assert!(win::valid_sid("S-1-5-18"));
        assert!(!win::valid_sid("S-1-5-21-1)(A;;FA;;;WD"));
        assert!(!win::valid_sid("alice"));
    }

    /// The log directory of a run under this account: files can be
    /// written, read back, and links are refused.
    #[test]
    fn private_files() {
        let dir = std::env::temp_dir().join(format!("peersig-logdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let me = std::process::Command::new(r"C:\Windows\System32\whoami.exe").args(["/user", "/fo", "csv", "/nh"]).output().unwrap();
        let sid = String::from_utf8_lossy(&me.stdout).trim().rsplit(',').next().unwrap().trim_matches('"').to_string();
        let mut l = LogDir::new(&dir, resolve_owner(Some(&sid)).unwrap(), 14).unwrap();
        let (mut w, path) = l.open_today().unwrap();
        w.write_all(b"{}\n").unwrap();
        drop(w);
        assert_eq!(fs::read_to_string(&path).unwrap(), "{}\n");
        l.write_status(&serde_json::json!({"ok": true}));
        assert!(fs::read_to_string(dir.join("status.json")).unwrap().contains("ok"));
        // A hard link to another file is refused.
        let other = dir.join("other.txt");
        fs::write(&other, b"x").unwrap();
        let link = dir.join("peersig-link.jsonl");
        fs::hard_link(&other, &link).unwrap();
        assert!(open_private(&link, true).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
