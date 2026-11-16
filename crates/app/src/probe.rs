//! Starting and stopping the capture probe.
//!
//! macOS: the probe needs root for the PKTAP interface (which tags each
//! packet with its process). The app installs it as a LaunchDaemon, after
//! the system asks for an administrator password. The binary is copied to
//! a root-owned path first, so a user process cannot swap what root runs.
//!
//! Linux: the probe gets packet-capture capabilities (set by the .deb, or
//! once through pkexec) and runs as the user, as a child of the app.
//!
//! Pausing creates a `paused` file in the log directory: the probe closes
//! the capture device until it is removed.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

pub const LABEL: &str = "be.uclouvain.peersig.probe";

/// The probe shipped with the app (next to the app's executable).
pub fn bundled() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("no parent dir")?;
    let name = if cfg!(windows) { "peersig-probe.exe" } else { "peersig-probe" };
    let p = dir.join(name);
    if !p.exists() {
        bail!("{} not found next to the app", p.display());
    }
    Ok(p)
}

pub fn default_logs_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/PeerSig/logs")
    } else {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("peersig/logs")
    }
}

pub fn set_paused(logs: &Path, paused: bool) -> Result<()> {
    let f = logs.join("paused");
    if paused {
        std::fs::write(&f, b"paused by the PeerSig app\n").with_context(|| f.display().to_string())?;
    } else if f.exists() {
        std::fs::remove_file(&f).with_context(|| f.display().to_string())?;
    }
    Ok(())
}

pub fn is_paused(logs: &Path) -> bool {
    logs.join("paused").exists()
}

/// Whether the capture service is set up (macOS: the LaunchDaemon exists).
pub fn installed() -> bool {
    if cfg!(target_os = "macos") {
        Path::new(&format!("/Library/LaunchDaemons/{}.plist", LABEL)).exists()
    } else {
        true
    }
}

#[cfg(target_os = "macos")]
fn run_as_admin(script: &str, prompt: &str) -> Result<()> {
    // The script goes in a private temporary file; osascript asks for the password.
    let dir = std::env::temp_dir().join(format!("peersig-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let path = dir.join("setup.sh");
    std::fs::write(&path, script)?;
    let apple = format!(
        "do shell script \"/bin/sh '{}'\" with prompt \"{}\" with administrator privileges",
        path.display(),
        prompt.replace('"', "'")
    );
    let out = Command::new("/usr/bin/osascript").arg("-e").arg(apple).output()?;
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Installs and starts the LaunchDaemon (macOS), running as root and
/// writing files owned by the current user.
#[cfg(target_os = "macos")]
pub fn install(logs: &Path) -> Result<()> {
    let probe = bundled()?;
    let user = std::env::var("USER").context("USER")?;
    if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        bail!("unexpected user name {:?}", user);
    }
    let helper = format!("/Library/PrivilegedHelperTools/{}", LABEL);
    let plist = format!("/Library/LaunchDaemons/{}.plist", LABEL);
    let logs = logs.display().to_string();
    let script = format!(
        r#"set -e
install -d -m 755 -o root -g wheel /Library/PrivilegedHelperTools
install -m 755 -o root -g wheel '{probe}' '{helper}'
install -d -m 755 -o root -g wheel '/Library/Application Support/PeerSig'
cat > '{plist}' <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{helper}</string><string>run</string><string>--dir</string><string>{logs}</string>
    <string>--owner</string><string>{user}</string><string>--quiet</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>/Library/Application Support/PeerSig/probe.log</string>
</dict>
</plist>
PLIST
chown root:wheel '{plist}'
chmod 644 '{plist}'
launchctl bootout system/{label} 2>/dev/null || true
launchctl bootstrap system '{plist}'
"#,
        probe = probe.display(),
        helper = helper,
        plist = plist,
        label = LABEL,
        logs = logs,
        user = user,
    );
    run_as_admin(&script, "PeerSig needs to install its capture service, which watches the TLS handshakes your computer sends.")
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<()> {
    let script = format!(
        "launchctl bootout system/{label} 2>/dev/null || true\nrm -f '/Library/LaunchDaemons/{label}.plist' '/Library/PrivilegedHelperTools/{label}'\n",
        label = LABEL
    );
    run_as_admin(&script, "PeerSig will remove its capture service.")
}

/// Linux: gives the probe capture capabilities once (pkexec asks for a password).
#[cfg(target_os = "linux")]
pub fn install(_logs: &Path) -> Result<()> {
    let probe = bundled()?;
    let caps = Command::new("getcap").arg(&probe).output().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    if caps.contains("cap_net_raw") {
        return Ok(());
    }
    let st = Command::new("pkexec")
        .args(["setcap", "cap_net_raw,cap_net_admin,cap_dac_read_search,cap_sys_ptrace+eip"])
        .arg(&probe)
        .status()?;
    if !st.success() {
        bail!("setcap failed: the probe needs packet capture rights");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<()> {
    Ok(())
}

/// Linux: the probe runs as a child of the app.
#[cfg(target_os = "linux")]
pub fn spawn(logs: &Path) -> Result<std::process::Child> {
    std::fs::create_dir_all(logs)?;
    Ok(Command::new(bundled()?).args(["run", "--interface", "any", "--quiet", "--dir"]).arg(logs).spawn()?)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn install(_logs: &Path) -> Result<()> {
    bail!("capture is not available on this system yet")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn uninstall() -> Result<()> {
    Ok(())
}

/// Opens a folder or URL with the system's default handler.
pub fn open(target: &str) -> Result<()> {
    let cmd = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(windows) {
        "explorer"
    } else {
        "xdg-open"
    };
    Command::new(cmd).arg(target).spawn()?;
    Ok(())
}
