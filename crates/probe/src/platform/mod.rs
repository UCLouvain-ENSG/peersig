//! OS-specific process queries. macOS is complete; Linux has the procfs
//! basics (no per-packet process metadata: the socket owner is looked up
//! when a ClientHello is seen); Windows looks the socket owner up in the
//! TCP and UDP tables, and names svchost processes by their services.

use serde::Serialize;

#[derive(Debug, Clone)]
pub struct PidBasic {
    pub ppid: i32,
    /// None on Windows (accounts are SIDs).
    pub uid: Option<u32>,
    /// Process start time, microseconds since the epoch (with the pid, the
    /// process identity: pids are reused).
    pub start_us: u64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub os: String,
    pub version: Option<String>,
    pub build: Option<String>,
    pub kernel: Option<String>,
    pub model: Option<String>,
    pub arch: String,
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod other;
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
pub use other::*;

/// Services hosted by a process: only Windows has them (svchost).
#[cfg(not(windows))]
pub fn services(_pid: i32) -> Vec<String> {
    Vec::new()
}
