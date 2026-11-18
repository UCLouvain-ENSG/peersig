//! Starting and stopping the capture probe.
//!
//! macOS: the probe needs root for the PKTAP interface (which tags each
//! packet with its process). The app installs it as a LaunchDaemon, after
//! the system asks for an administrator password. The binary is copied to
//! a root-owned path first, so a user process cannot swap what root runs.
//!
//! Linux: the probe gets packet-capture capabilities (set by the .deb or
//! the .rpm, or once through pkexec) and runs as the user, as a child of
//! the app.
//!
//! Windows: the probe runs as a LocalSystem service (`PeerSigProbe`), which
//! can read every process, the way the LaunchDaemon runs as root. Windows
//! asks for an administrator's consent (UAC) to install it. The binary is
//! copied to Program Files first, where users cannot change it. It
//! captures with the packet capture built into Windows (NDIS, through
//! ETW): nothing else to install.
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
    } else if cfg!(windows) {
        program_data().join("PeerSig").join("logs")
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

/// Whether the capture service is set up (macOS: the LaunchDaemon exists;
/// Windows: the service's copy of the probe exists).
pub fn installed() -> bool {
    if cfg!(target_os = "macos") {
        Path::new(&format!("/Library/LaunchDaemons/{}.plist", LABEL)).exists()
    } else if cfg!(windows) {
        service_exe().exists()
    } else {
        true
    }
}

fn env_dir(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(default))
}

/// `%ProgramData%`: machine-wide data (the service's logs).
fn program_data() -> PathBuf {
    env_dir("ProgramData", r"C:\ProgramData")
}

/// Windows: where the service runs the probe from (only administrators
/// can write there).
pub fn service_exe() -> PathBuf {
    env_dir("ProgramFiles", r"C:\Program Files").join("PeerSig").join("capture").join("peersig-probe.exe")
}

/// Windows service name, as in the probe's `service` module.
#[cfg(any(windows, test))]
const SERVICE: &str = "PeerSigProbe";

/// A PowerShell single-quoted string.
#[cfg(any(windows, test))]
fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The SID of the account running the app (`S-1-5-21-...`): the logs are
/// made readable by it. Taken from the app's own (unelevated) token, not
/// from the elevated script, which may run as another administrator.
#[cfg(windows)]
fn user_sid() -> Result<String> {
    use std::os::windows::process::CommandExt;
    let whoami = env_dir("SystemRoot", r"C:\Windows").join(r"System32\whoami.exe");
    let out = Command::new(whoami).args(["/user", "/fo", "csv", "/nh"]).creation_flags(CREATE_NO_WINDOW).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let sid = text.trim().rsplit(',').next().unwrap_or("").trim_matches('"').to_string();
    if !sid.starts_with("S-1-") || !sid[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        bail!("cannot tell this account's SID ({:?})", text.trim());
    }
    Ok(sid)
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Runs a PowerShell script elevated: Windows asks for an administrator's
/// consent. The script travels encoded on the command line, not in a file
/// a user process could change before it runs. Its exit code tells which
/// step failed (`steps`, from 2).
#[cfg(windows)]
fn run_elevated(script: &str, steps: &[&str]) -> Result<()> {
    use base64::Engine;
    use std::os::windows::process::CommandExt;
    // -EncodedCommand takes base64 of UTF-16.
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let ps = env_dir("SystemRoot", r"C:\Windows").join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    let outer = format!(
        "$p = Start-Process -FilePath {} -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand','{}'; exit $p.ExitCode",
        ps_quote(&ps.display().to_string()),
        base64::engine::general_purpose::STANDARD.encode(&utf16)
    );
    let out = Command::new(&ps)
        .args(["-NoProfile", "-NonInteractive", "-Command", &outer])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;
    match out.status.code() {
        Some(0) => Ok(()),
        Some(c) if c >= 2 && ((c - 2) as usize) < steps.len() => bail!("{}", steps[(c - 2) as usize]),
        _ => {
            let err = String::from_utf8_lossy(&out.stderr);
            if err.contains("canceled") || err.contains("annul") {
                bail!("The administrator's consent was not given.")
            }
            bail!("{}", err.lines().find(|l| !l.trim().is_empty()).unwrap_or("the setup script failed").trim())
        }
    }
}

/// Installs and starts the capture service (Windows), running as
/// LocalSystem and writing logs readable by the current user.
#[cfg(windows)]
pub fn install(logs: &Path) -> Result<()> {
    let probe = bundled()?;
    // The service writes as SYSTEM: only into the directory this script
    // protects, never one a user chose.
    if logs != default_logs_dir() {
        bail!("The capture service writes its logs to {}; reset the logs folder to it.", default_logs_dir().display());
    }
    let sid = user_sid()?;
    let script = install_script(&probe, &service_exe(), &program_data().join("PeerSig"), logs, &sid);
    run_elevated(
        &script,
        &[
            "Could not stop the previous capture service.",
            "Could not copy the capture service to Program Files.",
            "Could not protect the PeerSig data folder.",
            "Could not register the capture service.",
            "The capture service was installed but did not start.",
        ],
    )
}

/// The elevated install script (Windows): replace the service, copy the
/// probe to Program Files, protect %ProgramData%\PeerSig, register and
/// start the service. Exit codes 2 to 6 say which step failed.
#[cfg(any(windows, test))]
fn install_script(probe: &Path, exe: &Path, data: &Path, logs: &Path, sid: &str) -> String {
    let cmd = format!("\"{}\" service --dir \"{}\" --owner {} --quiet", exe.display(), logs.display(), sid);
    format!(
        r#"$ErrorActionPreference = 'Stop'
$name = {name}
$exe = {exe}
$data = {data}
function Step($code, [scriptblock]$b) {{ try {{ & $b }} catch {{ exit $code }} }}
Step 2 {{
  if (Get-Service -Name $name -ErrorAction SilentlyContinue) {{
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    & sc.exe delete $name | Out-Null
    Start-Sleep -Seconds 2
  }}
}}
Step 3 {{
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $exe) | Out-Null
  Copy-Item -LiteralPath {probe} -Destination $exe -Force
}}
# %ProgramData%\PeerSig: only SYSTEM and administrators may change it. Any
# user could have made it before: take it back, and refuse a link.
Step 4 {{
  if (Test-Path -LiteralPath $data) {{
    if ((Get-Item -LiteralPath $data -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {{ throw 'link' }}
    & takeown.exe /F $data /A | Out-Null
    if ($LASTEXITCODE -ne 0) {{ throw 'takeown' }}
  }} else {{
    New-Item -ItemType Directory -Path $data | Out-Null
  }}
  # Drop every rule, then allow SYSTEM and administrators, and let the
  # participant read (probe.log; the logs folder has its own rules).
  & icacls.exe $data /reset | Out-Null
  & icacls.exe $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*{sid}:(OI)(CI)RX' | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'icacls' }}
}}
Step 5 {{
  New-Service -Name $name -BinaryPathName {cmd} -DisplayName 'PeerSig capture' -Description 'Notes which applications send which TLS fingerprints (JA4), for the PeerSig study. Its logs stay on this computer.' -StartupType Automatic | Out-Null
  # Restarted when it crashes, and when it stops with an error.
  & sc.exe failure $name reset= 86400 actions= restart/5000/restart/5000/restart/60000 | Out-Null
  & sc.exe failureflag $name 1 | Out-Null
}}
Step 6 {{ Start-Service -Name $name }}
exit 0
"#,
        name = ps_quote(SERVICE),
        exe = ps_quote(&exe.display().to_string()),
        data = ps_quote(&data.display().to_string()),
        probe = ps_quote(&probe.display().to_string()),
        sid = sid,
        cmd = ps_quote(&cmd),
    )
}

#[cfg(windows)]
pub fn uninstall() -> Result<()> {
    let dir = service_exe().parent().map(Path::to_path_buf).unwrap_or_default();
    run_elevated(&uninstall_script(&dir), &["Could not remove the capture service."])
}

/// Stops and deletes the service and its copy of the probe; the logs stay.
#[cfg(any(windows, test))]
fn uninstall_script(dir: &Path) -> String {
    format!(
        r#"$name = {name}
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {{
  Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
  & sc.exe delete $name | Out-Null
  if ($LASTEXITCODE -ne 0) {{ exit 2 }}
}}
Start-Sleep -Seconds 1
Remove-Item -LiteralPath {dir} -Recurse -Force -ErrorAction SilentlyContinue
exit 0
"#,
        name = ps_quote(SERVICE),
        dir = ps_quote(&dir.display().to_string()),
    )
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

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub fn install(_logs: &Path) -> Result<()> {
    bail!("capture is not available on this system yet")
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_scripts() {
        assert_eq!(ps_quote(r"C:\Users\O'Brien\x.exe"), r"'C:\Users\O''Brien\x.exe'");
        let s = install_script(
            Path::new(r"C:\Users\O'Brien\AppData\Local\PeerSig\peersig-probe.exe"),
            Path::new(r"C:\Program Files\PeerSig\capture\peersig-probe.exe"),
            Path::new(r"C:\ProgramData\PeerSig"),
            Path::new(r"C:\ProgramData\PeerSig\logs"),
            "S-1-5-21-1-2-3-1001",
        );
        assert!(s.contains(r"Copy-Item -LiteralPath 'C:\Users\O''Brien\AppData\Local\PeerSig\peersig-probe.exe'"), "{}", s);
        assert!(s.contains(r#"-BinaryPathName '"C:\Program Files\PeerSig\capture\peersig-probe.exe" service --dir "C:\ProgramData\PeerSig\logs" --owner S-1-5-21-1-2-3-1001 --quiet'"#), "{}", s);
        assert!(s.contains("'*S-1-5-21-1-2-3-1001:(OI)(CI)RX'"));
        assert!(uninstall_script(Path::new(r"C:\Program Files\PeerSig\capture")).contains(r"Remove-Item -LiteralPath 'C:\Program Files\PeerSig\capture'"));
    }
}
