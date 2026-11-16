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
        uid: info.pbi_uid,
        start_us: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
        name: if name.is_empty() { comm } else { name },
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
pub fn want_pktap(p: *mut c_void) -> bool {
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

/// Without PKTAP metadata: who has this local port open. `lsof` is slow
/// (100 ms or more) but only runs for flows PKTAP did not attribute.
pub fn socket_owner(key: &FlowKey) -> Option<i32> {
    let proto = if key.proto == crate::net::TCP { "TCP" } else { "UDP" };
    let spec = format!("{}:{}", proto, key.sport);
    let out = std::process::Command::new("/usr/sbin/lsof")
        .args(["-nP", "-w", "-F", "p", "-i", &spec])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix('p').and_then(|p| p.parse().ok()))
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
        version: sysctl_string("kern.osproductversion"),
        build: sysctl_string("kern.osversion"),
        kernel: sysctl_string("kern.osrelease"),
        model: sysctl_string("hw.model"),
        arch: std::env::consts::ARCH.into(),
    }
}

pub const DEFAULT_DEVICE: &str = "pktap,all";
