//! OS-specific process queries. macOS is complete; Linux has the procfs
//! basics (no per-packet process metadata: the socket owner is looked up
//! when a ClientHello is seen); Windows looks the socket owner up in the
//! TCP and UDP tables, and names svchost processes by their services.

use std::collections::HashSet;
use std::net::IpAddr;

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

/// An IPv4 address seen through a dual-stack socket (`::ffff:192.0.2.1`)
/// as the IPv4 address it is.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// This machine's own addresses, to tell its traffic from the traffic it
/// forwards or bridges (a router, a Wi-Fi access point, virtual machines):
/// no local process sent that. None where they are not listed (Windows),
/// and then every packet is taken as the machine's own.
#[cfg(unix)]
pub fn local_addrs() -> Option<HashSet<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return None;
    }
    let mut out = HashSet::new();
    let mut cur = head;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            match unsafe { (*ifa.ifa_addr).sa_family } as i32 {
                libc::AF_INET => {
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    out.insert(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                }
                libc::AF_INET6 => {
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    out.insert(canonical(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr))));
                }
                _ => {}
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    Some(out)
}

#[cfg(not(unix))]
pub fn local_addrs() -> Option<HashSet<IpAddr>> {
    None
}

#[derive(Debug, Clone, Serialize)]
pub struct OsInfo {
    pub os: String,
    /// Linux: the distribution, os-release's `ID` (`ubuntu`, `fedora`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub distro: Option<String>,
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn own_addresses() {
        let own = local_addrs().unwrap();
        assert!(own.contains(&"127.0.0.1".parse().unwrap()), "{:?}", own);
        assert!(!own.contains(&"192.0.2.7".parse().unwrap()));
        assert_eq!(canonical("::ffff:192.0.2.7".parse().unwrap()), "192.0.2.7".parse::<IpAddr>().unwrap());
    }
}
