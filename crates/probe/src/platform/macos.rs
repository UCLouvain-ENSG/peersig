//! macOS process queries: libproc, sysctl, and the private but stable
//! `responsibility_get_pid_responsible_for_pid` (what Activity Monitor uses
//! to put an XPC service under the app it works for).

use std::ffi::{c_void, CStr};
use std::mem::{size_of, MaybeUninit};
use std::sync::OnceLock;

use super::{OsInfo, PidBasic};
use crate::net::FlowKey;

pub fn basic(pid: i32) -> Option<PidBasic> {
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as i32;
    let r = unsafe {
        libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr() as *mut c_void, size)
    };
    if r != size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let name = unsafe { CStr::from_ptr(info.pbi_name.as_ptr()) }.to_string_lossy().into_owned();
    let comm = unsafe { CStr::from_ptr(info.pbi_comm.as_ptr()) }.to_string_lossy().into_owned();
    Some(PidBasic {
        ppid: info.pbi_ppid as i32,
        uid: Some(info.pbi_uid),
        start_us: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
        name: if name.is_empty() { comm } else { name },
        exe: None,
    })
}

pub fn exe_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// argv from KERN_PROCARGS2: argc, the exec path, padding, then argv.
pub fn args(pid: i32) -> Option<Vec<String>> {
    let mut argmax: libc::c_int = 0;
    let mut size = size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    if unsafe {
        libc::sysctl(mib.as_mut_ptr(), 2, &mut argmax as *mut _ as *mut c_void, &mut size, std::ptr::null_mut(), 0)
    } != 0
    {
        return None;
    }
    let mut buf = vec![0u8; argmax.max(4096) as usize];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    if unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr() as *mut c_void, &mut size, std::ptr::null_mut(), 0)
    } != 0
    {
        return None;
    }
    buf.truncate(size);
    if buf.len() < 4 {
        return None;
    }
    let argc = i32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;
    let mut pos = 4;
    while pos < buf.len() && buf[pos] != 0 {
        pos += 1; // exec path
    }
    while pos < buf.len() && buf[pos] == 0 {
        pos += 1;
    }
    let mut out = Vec::with_capacity(argc);
    for _ in 0..argc.min(4096) {
        if pos >= buf.len() {
            break;
        }
        let end = buf[pos..].iter().position(|&c| c == 0).map_or(buf.len(), |e| pos + e);
        out.push(String::from_utf8_lossy(&buf[pos..end]).into_owned());
        pos = end + 1;
    }
    Some(out)
}

type RespFn = unsafe extern "C" fn(libc::pid_t) -> libc::pid_t;

fn resp_fn() -> Option<RespFn> {
    static F: OnceLock<Option<RespFn>> = OnceLock::new();
    *F.get_or_init(|| {
        let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"responsibility_get_pid_responsible_for_pid".as_ptr()) };
        if sym.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, RespFn>(sym) })
        }
    })
}

/// Asks Apple's libpcap to keep the PKTAP header (process, interface,
/// direction) on a `pktap` capture. Without this call it strips the header
/// and hands back the bare packets. Apple's tcpdump calls it for `-k`. It is
/// exported by libpcap but not declared in the SDK headers, hence dlsym.
/// Must be called before the capture is activated. Returns false if absent.
pub(crate) fn want_pktap(p: *mut c_void) -> bool {
    type F = unsafe extern "C" fn(*mut c_void, libc::c_int) -> libc::c_int;
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"pcap_set_want_pktap".as_ptr()) };
    if sym.is_null() {
        return false;
    }
    let f = unsafe { std::mem::transmute::<*mut c_void, F>(sym) };
    unsafe { f(p, 1) == 0 }
}

pub fn responsible_pid(pid: i32) -> Option<i32> {
    let f = resp_fn()?;
    let r = unsafe { f(pid) };
    (r > 0).then_some(r)
}

/// xnu `struct proc_regioninfo` (sys/proc_info.h).
#[repr(C)]
#[derive(Clone, Copy)]
struct RegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    obj_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

#[repr(C)]
struct RegionWithPath {
    info: RegionInfo,
    vip: libc::vnode_info_path,
}

// Checked against the macOS 27 SDK with clang.
const _: () = assert!(size_of::<RegionInfo>() == 96);
const _: () = assert!(size_of::<RegionWithPath>() == 1272);
const PROC_PIDREGIONPATHINFO: i32 = 8;

/// Files mapped in the process (libraries outside the shared cache, the
/// executable, frameworks). System libraries live in the dyld shared cache
/// and do not show up here.
pub fn mapped_files(pid: i32) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut addr: u64 = 0;
    let size = size_of::<RegionWithPath>() as i32;
    for _ in 0..100_000 {
        let mut r = MaybeUninit::<RegionWithPath>::zeroed();
        let n = unsafe {
            libc::proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, addr, r.as_mut_ptr() as *mut c_void, size)
        };
        if n != size {
            break;
        }
        let r = unsafe { r.assume_init() };
        let p = unsafe { CStr::from_ptr(r.vip.vip_path.as_ptr() as *const libc::c_char) };
        if !p.to_bytes().is_empty() {
            let s = p.to_string_lossy();
            if out.last().map_or(true, |l| l.as_str() != s) {
                out.push(s.into_owned());
            }
        }
        let next = r.info.address.saturating_add(r.info.size);
        if next <= addr {
            break;
        }
        addr = next;
    }
    out.sort();
    out.dedup();
    out
}

/// Without PKTAP metadata: the process that has this flow's socket open.
/// `lsof` is slow (100 ms or more) but only runs for flows PKTAP did not
/// attribute.
///
/// `lsof -i TCP:<port>` lists every socket with that port number at either
/// end and on any address, so each one is checked against the whole flow.
/// Taking the first process listed credited Defender's connections to
/// Thunderbird, whose loopback connection to a local service had that port
/// as its remote port, and to XQuartz, which had the port on `::1`; and a
/// Firefox connection to a git process that kept a socket with the same
/// port on the address of a network the Mac had left.
pub fn socket_owner(key: &FlowKey) -> Option<i32> {
    let proto = if key.proto == crate::net::TCP { "TCP" } else { "UDP" };
    let spec = format!("{}:{}", proto, key.sport);
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-w", "-F", "pn", "-i", &spec])
        .output()
        .ok()?;
    owner_in_lsof(&String::from_utf8_lossy(&out.stdout), key)
}

/// The process of the socket that best matches the flow in `lsof -F pn`
/// output (`p<pid>`, then an `n<name>` line per socket): both endpoints, or
/// for UDP an unconnected socket on the source port. The local address may
/// be the wildcard. A socket that matches only the port number is never
/// taken.
fn owner_in_lsof(out: &str, key: &FlowKey) -> Option<i32> {
    let mut pid = None;
    let mut best: Option<(u8, i32)> = None;
    for l in out.lines() {
        if let Some(p) = l.strip_prefix('p') {
            pid = p.parse::<i32>().ok();
            continue;
        }
        let (Some(name), Some(p)) = (l.strip_prefix('n'), pid) else { continue };
        let Some(score) = flow_match(name, key) else { continue };
        if best.map_or(true, |(b, _)| score > b) {
            best = Some((score, p));
        }
        if score == 4 {
            break;
        }
    }
    best.map(|(_, p)| p)
}

/// How well an `lsof` socket name (`10.0.0.2:52000->192.0.2.1:443`,
/// `[::1]:6000`, `*:5353`) matches the flow: 2 per endpoint that matches
/// exactly, 1 for a wildcard local address or an unconnected UDP socket;
/// None when an endpoint differs.
fn flow_match(name: &str, key: &FlowKey) -> Option<u8> {
    let (local, remote) = match name.split_once("->") {
        Some((l, r)) => (l, Some(r)),
        None => (name, None),
    };
    let (la, lp) = lsof_endpoint(local)?;
    if lp != key.sport {
        return None;
    }
    let local = match la {
        Some(a) if a == super::canonical(key.src) => 2,
        None => 1,
        Some(a) if a.is_unspecified() => 1,
        Some(_) => return None,
    };
    let remote = match remote {
        Some(r) => match lsof_endpoint(r)? {
            (Some(ra), rp) if ra == super::canonical(key.dst) && rp == key.dport => 2,
            _ => return None,
        },
        None if key.proto != crate::net::TCP => 1,
        None => return None,
    };
    Some(local + remote)
}

/// `192.0.2.1:443`, `[2001:db8::1]:443`, `[fe80::1%en0]:5353` or `*:5353`
/// (None for the wildcard address).
fn lsof_endpoint(s: &str) -> Option<(Option<std::net::IpAddr>, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port = port.parse().ok()?;
    if host == "*" {
        return Some((None, port));
    }
    let host = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let host = host.split('%').next().unwrap_or(host);
    Some((Some(super::canonical(host.parse().ok()?)), port))
}

fn sysctl_string(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut size = 0usize;
    if unsafe { libc::sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) } != 0 {
        return None;
    }
    let mut buf = vec![0u8; size];
    if unsafe {
        libc::sysctlbyname(cname.as_ptr(), buf.as_mut_ptr() as *mut c_void, &mut size, std::ptr::null_mut(), 0)
    } != 0
    {
        return None;
    }
    buf.truncate(size);
    while buf.last() == Some(&0) {
        buf.pop();
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

pub fn os_info() -> OsInfo {
    OsInfo {
        os: "macos".into(),
        distro: None,
        version: sysctl_string("kern.osproductversion"),
        build: sysctl_string("kern.osversion"),
        kernel: sysctl_string("kern.osrelease"),
        model: sysctl_string("hw.model"),
        arch: std::env::consts::ARCH.into(),
    }
}

pub const DEFAULT_DEVICE: &str = "pktap,all";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{TCP, UDP};

    fn key(proto: u8, src: &str, dst: &str) -> FlowKey {
        let (s, d): (std::net::SocketAddr, std::net::SocketAddr) = (src.parse().unwrap(), dst.parse().unwrap());
        FlowKey { proto, src: s.ip(), sport: s.port(), dst: d.ip(), dport: d.port() }
    }

    /// The three misattributions of 0.1.1 (lsof lines as it prints them):
    /// the same port number elsewhere is not the flow's socket.
    #[test]
    fn same_port_elsewhere() {
        // Defender from 192.168.0.102:49155; Thunderbird is connected to a
        // local service listening on 127.0.0.1:49155.
        let k = key(TCP, "192.168.0.102:49155", "4.207.44.64:443");
        let lsof = "p1060\nf22\nn127.0.0.1:49406->127.0.0.1:49155\np2214\nf3\nn127.0.0.1:49155->127.0.0.1:49406\nf7\nn127.0.0.1:49155\n";
        assert_eq!(owner_in_lsof(lsof, &k), None);
        let with_owner = format!("{}p700\nf12\nn192.168.0.102:49155->4.207.44.64:443\n", lsof);
        assert_eq!(owner_in_lsof(&with_owner, &k), Some(700));
        // XQuartz's own loopback connection on [::1].
        let k = key(TCP, "130.104.228.108:49156", "72.145.163.206:443");
        assert_eq!(owner_in_lsof("p804\nf16\nn[::1]:49156->[::1]:6000\n", &k), None);
        // git kept a socket on the address of the previous network.
        let k = key(TCP, "130.104.45.87:63006", "213.244.171.241:443");
        assert_eq!(owner_in_lsof("p82752\nf5\nn130.104.228.108:63006->140.82.121.4:443\n", &k), None);
    }

    #[test]
    fn udp_and_ipv6() {
        let k = key(UDP, "[2001:db8::5]:51234", "[2001:db8::1]:443");
        // An unconnected socket on the wildcard address, then the
        // connected one: the connected one wins.
        let lsof = "p10\nf4\nn*:51234\np11\nf9\nn[2001:db8::5]:51234->[2001:db8::1]:443\n";
        assert_eq!(owner_in_lsof(lsof, &k), Some(11));
        assert_eq!(owner_in_lsof("p10\nf4\nn*:51234\n", &k), Some(10));
        assert_eq!(owner_in_lsof("p10\nf4\nn[2001:db8::5]:51234->[2001:db8::2]:443\n", &k), None);
        // A TCP socket without a peer (listening) is not a connection.
        let k = key(TCP, "192.0.2.5:6000", "192.0.2.1:443");
        assert_eq!(owner_in_lsof("p10\nf4\nn*:6000\n", &k), None);
        // An IPv4 flow on a dual-stack socket; a scoped address.
        let k = key(TCP, "192.0.2.5:52000", "198.51.100.1:443");
        assert_eq!(owner_in_lsof("p12\nf4\nn[::ffff:192.0.2.5]:52000->[::ffff:198.51.100.1]:443\n", &k), Some(12));
        assert_eq!(lsof_endpoint("[fe80::1%en0]:5353"), Some((Some("fe80::1".parse().unwrap()), 5353)));
    }

    /// The real lsof on this process's own connection (no root needed).
    #[test]
    fn own_connection() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (_a, _) = l.accept().unwrap();
        let (src, dst) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
        let k = FlowKey { proto: TCP, src: src.ip(), sport: src.port(), dst: dst.ip(), dport: dst.port() };
        assert_eq!(socket_owner(&k), Some(std::process::id() as i32));
        // The same local port towards another peer: nobody.
        let other = FlowKey { dport: dst.port().wrapping_add(1), ..k };
        assert_eq!(socket_owner(&other), None);
    }
}
