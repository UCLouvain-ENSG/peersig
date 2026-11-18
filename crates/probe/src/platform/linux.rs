//! Linux: procfs. Sockets are matched to processes through their inode
//! (/proc/net/{tcp,udp}[6] -> /proc/<pid>/fd), like `ss -p`.

use std::fs;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{canonical, OsInfo, PidBasic};
use crate::net::{FlowKey, TCP};

pub fn basic(pid: i32) -> Option<PidBasic> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    // comm is in parentheses and may contain spaces.
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let name = stat[open + 1..close].to_string();
    let f: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    let ppid = f.get(1)?.parse().ok()?;
    let start_ticks: u64 = f.get(19)?.parse().ok()?;
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
    let btime = fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse::<u64>().ok()))?;
    let uid = fs::read_to_string(format!("/proc/{}/status", pid))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:").and_then(|v| v.split_whitespace().next()?.parse().ok()))?;
    Some(PidBasic {
        ppid,
        uid: Some(uid),
        start_us: btime * 1_000_000 + start_ticks * 1_000_000 / ticks,
        name,
    })
}

pub fn exe_path(pid: i32) -> Option<String> {
    fs::read_link(format!("/proc/{}/exe", pid)).ok().map(|p| p.to_string_lossy().into_owned())
}

pub fn args(pid: i32) -> Option<Vec<String>> {
    let raw = fs::read(format!("/proc/{}/cmdline", pid)).ok()?;
    Some(raw.split(|&b| b == 0).filter(|s| !s.is_empty()).map(|s| String::from_utf8_lossy(s).into_owned()).collect())
}

pub fn responsible_pid(_pid: i32) -> Option<i32> {
    None
}

pub fn mapped_files(pid: i32) -> Vec<String> {
    let mut out: Vec<String> = fs::read_to_string(format!("/proc/{}/maps", pid))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(5).filter(|p| p.starts_with('/')).map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// An address of /proc/net/{tcp,udp}[6]: `0100007F:1F90`, or 32 hex digits
/// for IPv6, each 32-bit word as the kernel holds it; then the port.
fn proc_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> { Some(u32::from_str_radix(a.get(i * 8..i * 8 + 8)?, 16).ok()?.to_ne_bytes()) };
    let ip = match a.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            canonical(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => return None,
    };
    Some((ip, port))
}

/// The socket that sent this packet: the same local port and address (or
/// bound to any address), connected to the same peer (UDP: or to none).
/// The port alone is not enough: a packet this machine only forwards can
/// come from a port a local socket also uses.
fn socket_inode(key: &FlowKey) -> Option<String> {
    let tables: &[&str] = if key.proto == TCP { &["tcp", "tcp6"] } else { &["udp", "udp6"] };
    let (src, dst) = (canonical(key.src), canonical(key.dst));
    let mut best: Option<(u8, String)> = None;
    for t in tables {
        let Ok(s) = fs::read_to_string(format!("/proc/net/{}", t)) else { continue };
        for l in s.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() <= 9 {
                continue;
            }
            let (Some((la, lp)), Some((ra, rp))) = (proc_addr(f[1]), proc_addr(f[2])) else { continue };
            if lp != key.sport {
                continue;
            }
            let local = if la == src { 2 } else if la.is_unspecified() { 1 } else { continue };
            let remote = if ra == dst && rp == key.dport {
                2
            } else if key.proto != TCP && ra.is_unspecified() && rp == 0 {
                1
            } else {
                continue;
            };
            if best.as_ref().map_or(true, |(b, _)| local + remote > *b) {
                best = Some((local + remote, f[9].to_string()));
            }
            if local + remote == 4 {
                return best.map(|b| b.1);
            }
        }
    }
    best.map(|b| b.1)
}

pub fn socket_owner(key: &FlowKey) -> Option<i32> {
    let target = format!("socket:[{}]", socket_inode(key)?);
    for e in fs::read_dir("/proc").ok()?.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(fds) = fs::read_dir(e.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            if fs::read_link(fd.path()).map_or(false, |l| l.to_string_lossy() == target) {
                return Some(pid);
            }
        }
    }
    None
}

pub fn os_info() -> OsInfo {
    let rel = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let get = |k: &str| {
        rel.lines()
            .find_map(|l| l.strip_prefix(k).map(|v| v.trim_matches('"').to_string()))
    };
    OsInfo {
        os: "linux".into(),
        distro: get("ID="),
        version: get("PRETTY_NAME="),
        build: get("VERSION_ID="),
        kernel: fs::read_to_string("/proc/sys/kernel/osrelease").ok().map(|s| s.trim().to_string()),
        model: None,
        arch: std::env::consts::ARCH.into(),
    }
}

pub const DEFAULT_DEVICE: &str = "any";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_endian = "little")]
    fn proc_addresses() {
        assert_eq!(proc_addr("0100007F:1F90"), Some(("127.0.0.1".parse().unwrap(), 8080)));
        assert_eq!(proc_addr("00000000000000000000000001000000:0050"), Some(("::1".parse().unwrap(), 80)));
        // A dual-stack socket's IPv4 peer.
        assert_eq!(proc_addr("0000000000000000FFFF00000100007F:0050"), Some(("127.0.0.1".parse().unwrap(), 80)));
        assert_eq!(proc_addr("00000000:0000"), Some(("0.0.0.0".parse().unwrap(), 0)));
        assert_eq!(proc_addr("zz"), None);
    }

    /// This test's own sockets are found; a packet from another address
    /// that only shares a local socket's port is not this process's.
    #[test]
    fn owner_of_own_sockets() {
        use std::net::{TcpListener, TcpStream, UdpSocket};
        let me = Some(std::process::id() as i32);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (local, remote) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
        let key = FlowKey { proto: TCP, src: local.ip(), sport: local.port(), dst: remote.ip(), dport: remote.port() };
        assert_eq!(socket_owner(&key), me);
        let other_peer = FlowKey { dst: "198.51.100.1".parse().unwrap(), dport: 443, ..key };
        assert_eq!(socket_owner(&other_peer), None);
        let forwarded = FlowKey { src: "192.0.2.7".parse().unwrap(), sport: l.local_addr().unwrap().port(), ..other_peer };
        assert_eq!(socket_owner(&forwarded), None);

        let u = UdpSocket::bind("0.0.0.0:0").unwrap();
        let key = FlowKey {
            proto: crate::net::UDP,
            src: "127.0.0.1".parse().unwrap(),
            sport: u.local_addr().unwrap().port(),
            dst: "198.51.100.1".parse().unwrap(),
            dport: 443,
        };
        assert_eq!(socket_owner(&key), me);
        u.connect("127.0.0.1:9").unwrap();
        assert_eq!(socket_owner(&FlowKey { dst: "127.0.0.1".parse().unwrap(), dport: 9, ..key }), me);
        assert_eq!(socket_owner(&key), None, "connected elsewhere");
    }
}
