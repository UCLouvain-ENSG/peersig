//! Windows process queries.
//!
//! - Socket owner: the TCP and UDP tables with owning pids
//!   (`GetExtendedTcpTable`/`GetExtendedUdpTable`, what `netstat -ano` reads),
//!   looked up once per ClientHello: Windows has no per-packet process.
//! - Process: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` for the image
//!   path, start time and parent; the command line from
//!   `NtQueryInformationProcess(ProcessCommandLineInformation)` (only
//!   Chromium's `--type` and an interpreter's script are kept from it); the
//!   loaded modules from a ToolHelp snapshot.
//! - Services hosted by a process (`svchost.exe`): the service manager.
//! - Who a process works for: a WebView2 process works for the app that
//!   started it, a Chromium or Electron child for its browser process (the
//!   parent chain, checked against pid reuse).
//!
//! As LocalSystem (the PeerSig service) every process can be queried. Run by
//! a user, other accounts' processes (services) give their name and services
//! only.

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, FILETIME, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Process32FirstW, Process32NextW, MODULEENTRY32W,
    PROCESSENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemDirectoryW, OSVERSIONINFOEXW, OSVERSIONINFOW};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_BASIC_INFORMATION, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::{OsInfo, PidBasic};
use crate::net::{FlowKey, TCP};

/// Every adapter, through the system's packet capture (`capture::etw`).
pub const DEFAULT_DEVICE: &str = "all";

pub fn wide(s: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

fn from_wide(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn open(pid: i32) -> Option<Handle> {
    if pid <= 0 {
        return None;
    }
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid as u32) };
    (!h.is_null()).then_some(Handle(h))
}

/// Microseconds since the Unix epoch.
fn filetime_us(ft: &FILETIME) -> u64 {
    let t = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    (t / 10).saturating_sub(11_644_473_600_000_000)
}

fn start_us(h: &Handle) -> Option<u64> {
    let z = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut c, mut e, mut k, mut u) = (z, z, z, z);
    if unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } == 0 {
        return None;
    }
    Some(filetime_us(&c))
}

fn parent_pid(h: &Handle) -> Option<i32> {
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut ret = 0u32;
    let st = unsafe {
        NtQueryInformationProcess(
            h.0,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret,
        )
    };
    (st >= 0).then_some(pbi.InheritedFromUniqueProcessId as i32)
}

fn image_path(h: &Handle) -> Option<String> {
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) } == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

fn file_name(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

struct Entry {
    ppid: i32,
    name: String,
}

/// Name and parent from a process snapshot: needs no access to the process.
fn snapshot_entry(pid: i32) -> Option<Entry> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return None;
    }
    let snap = Handle(snap);
    let mut e: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
    while ok != 0 {
        if e.th32ProcessID == pid as u32 {
            return Some(Entry { ppid: e.th32ParentProcessID as i32, name: from_wide(&e.szExeFile) });
        }
        ok = unsafe { Process32NextW(snap.0, &mut e) };
    }
    None
}

pub fn basic(pid: i32) -> Option<PidBasic> {
    if pid <= 0 {
        return None;
    }
    if let Some(h) = open(pid) {
        if let Some(start_us) = start_us(&h) {
            let exe = image_path(&h);
            let name = exe.as_deref().map(file_name).or_else(|| snapshot_entry(pid).map(|e| e.name)).unwrap_or_default();
            return Some(PidBasic { ppid: parent_pid(&h).unwrap_or(0), uid: None, start_us, name, exe });
        }
    }
    // Another account's process, without the rights to open it: the
    // snapshot still names it. Its start time is unknown (0).
    let e = snapshot_entry(pid)?;
    Some(PidBasic { ppid: e.ppid, uid: None, start_us: 0, name: e.name, exe: None })
}

pub fn exe_path(pid: i32) -> Option<String> {
    image_path(&open(pid)?)
}

/// The command line, split as `CommandLineToArgvW` does.
pub fn args(pid: i32) -> Option<Vec<String>> {
    let h = open(pid)?;
    let mut need = 0u32;
    let mut buf: Vec<u64> = vec![0; 512];
    for _ in 0..3 {
        let len = (buf.len() * 8) as u32;
        let st = unsafe {
            NtQueryInformationProcess(h.0, ProcessCommandLineInformation, buf.as_mut_ptr() as *mut c_void, len, &mut need)
        };
        if st >= 0 {
            // A UNICODE_STRING whose buffer follows it in `buf`.
            let base = buf.as_ptr() as *const u8;
            let bytes = unsafe { std::ptr::read_unaligned(base as *const u16) } as usize;
            let ptr = unsafe { std::ptr::read_unaligned(base.add(8) as *const *const u16) };
            let total = buf.len() * 8;
            let start = (ptr as usize).checked_sub(base as usize)?;
            if ptr.is_null() || start + bytes > total {
                return None;
            }
            let s = unsafe { std::slice::from_raw_parts(ptr, bytes / 2) };
            return Some(split_command_line(&String::from_utf16_lossy(s)));
        }
        if need as usize <= buf.len() * 8 {
            return None;
        }
        buf = vec![0; need as usize / 8 + 2];
    }
    None
}

/// Splits a command line by the rules of `CommandLineToArgvW` and the C
/// runtime: the program name ends at the next space or closing quote;
/// then `2n` backslashes and a quote give `n` backslashes and toggle
/// quoting, `2n+1` backslashes and a quote give `n` and a literal quote, and
/// `""` inside quotes is a literal quote.
pub fn split_command_line(s: &str) -> Vec<String> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut a0 = String::new();
    if c.first() == Some(&'"') {
        i = 1;
        while i < c.len() && c[i] != '"' {
            a0.push(c[i]);
            i += 1;
        }
        i += 1;
    } else {
        while i < c.len() && c[i] != ' ' && c[i] != '\t' {
            a0.push(c[i]);
            i += 1;
        }
    }
    out.push(a0);
    loop {
        while i < c.len() && (c[i] == ' ' || c[i] == '\t') {
            i += 1;
        }
        if i >= c.len() {
            break;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while i < c.len() {
            match c[i] {
                ' ' | '\t' if !quoted => break,
                '\\' => {
                    let mut n = 0;
                    while i < c.len() && c[i] == '\\' {
                        n += 1;
                        i += 1;
                    }
                    if i < c.len() && c[i] == '"' {
                        arg.extend(std::iter::repeat_n('\\', n / 2));
                        if n % 2 == 1 {
                            arg.push('"');
                            i += 1;
                        }
                    } else {
                        arg.extend(std::iter::repeat_n('\\', n));
                    }
                }
                '"' => {
                    if quoted && c.get(i + 1) == Some(&'"') {
                        arg.push('"');
                        i += 2;
                    } else {
                        quoted = !quoted;
                        i += 1;
                    }
                }
                ch => {
                    arg.push(ch);
                    i += 1;
                }
            }
        }
        out.push(arg);
    }
    out
}

fn is_webview2(exe: &str) -> bool {
    file_name(exe).eq_ignore_ascii_case("msedgewebview2.exe")
}

/// The process another one works for: up the parent chain, through WebView2
/// processes (an Edge WebView2 runtime works for the app that hosts it) and
/// through processes of the same executable (a Chromium or Electron child
/// and its browser process). Only the same executable: every system binary
/// shares System32, and svchost does not work for services.exe. A parent
/// that started after its child is not its parent any more (pids are
/// reused).
pub fn responsible_pid(pid: i32) -> Option<i32> {
    let mut cur = pid;
    let mut cur_exe = exe_path(pid)?;
    let mut cur_basic = basic(pid)?;
    for _ in 0..16 {
        let parent = cur_basic.ppid;
        if parent <= 4 || parent == cur {
            break;
        }
        let Some(pb) = basic(parent) else { break };
        if pb.start_us == 0 || pb.start_us > cur_basic.start_us {
            break;
        }
        let Some(pexe) = exe_path(parent) else { break };
        let same_app = cur_exe.eq_ignore_ascii_case(&pexe);
        if !(is_webview2(&cur_exe) || same_app) {
            break;
        }
        cur = parent;
        cur_exe = pexe;
        cur_basic = pb;
    }
    (cur != pid).then_some(cur)
}

/// Modules loaded in the process: the executable and its DLLs.
pub fn mapped_files(pid: i32) -> Vec<String> {
    let mut out = Vec::new();
    if pid <= 4 {
        return out;
    }
    let mut snap = INVALID_HANDLE_VALUE;
    // ERROR_BAD_LENGTH is transient while the process loads modules.
    for _ in 0..3 {
        snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid as u32) };
        if snap != INVALID_HANDLE_VALUE {
            break;
        }
    }
    if snap == INVALID_HANDLE_VALUE {
        return out;
    }
    let snap = Handle(snap);
    let mut m: MODULEENTRY32W = unsafe { std::mem::zeroed() };
    m.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut ok = unsafe { Module32FirstW(snap.0, &mut m) };
    while ok != 0 {
        out.push(from_wide(&m.szExePath));
        ok = unsafe { Module32NextW(snap.0, &mut m) };
    }
    out.sort();
    out.dedup();
    out
}

/// A table from GetExtendedTcpTable/GetExtendedUdpTable: the row count, then
/// the rows. Returned as u64s for alignment.
fn table(get: impl Fn(*mut c_void, &mut u32) -> u32) -> Option<Vec<u64>> {
    let mut size = 16 * 1024u32;
    for _ in 0..5 {
        let mut buf = vec![0u64; size as usize / 8 + 1];
        let mut sz = (buf.len() * 8) as u32;
        match get(buf.as_mut_ptr() as *mut c_void, &mut sz) {
            NO_ERROR => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER => size = sz + 4096,
            _ => return None,
        }
    }
    None
}

fn rows<T: Copy>(buf: &[u64]) -> Vec<T> {
    let base = buf.as_ptr() as *const u8;
    let n = unsafe { std::ptr::read_unaligned(base as *const u32) } as usize;
    let size = std::mem::size_of::<T>();
    // Rows start after the u32 count, aligned to 4 (they hold u32s and bytes).
    if 4 + n.saturating_mul(size) > buf.len() * 8 {
        return Vec::new();
    }
    (0..n).map(|i| unsafe { std::ptr::read_unaligned(base.add(4 + i * size) as *const T) }).collect()
}

fn port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

fn v4(a: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(a.to_ne_bytes()))
}

fn v6(a: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(a))
}

/// Same address, an IPv4 address and its IPv4-mapped IPv6 form included.
fn same_ip(a: &IpAddr, b: &IpAddr) -> bool {
    let norm = |x: &IpAddr| match x {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*x),
        _ => *x,
    };
    norm(a) == norm(b)
}

/// Local and remote endpoints and the owning pid of the TCP connections of
/// one address family.
fn tcp_rows(ipv6: bool) -> Vec<(IpAddr, u16, IpAddr, u16, i32)> {
    let family = if ipv6 { AF_INET6 } else { AF_INET } as u32;
    let Some(b) = table(|p, sz| unsafe { GetExtendedTcpTable(p, sz, 0, family, TCP_TABLE_OWNER_PID_ALL, 0) }) else {
        return Vec::new();
    };
    if ipv6 {
        let row = |r: MIB_TCP6ROW_OWNER_PID| {
            (v6(r.ucLocalAddr), port(r.dwLocalPort), v6(r.ucRemoteAddr), port(r.dwRemotePort), r.dwOwningPid as i32)
        };
        rows(&b).into_iter().map(row).collect()
    } else {
        let row = |r: MIB_TCPROW_OWNER_PID| {
            (v4(r.dwLocalAddr), port(r.dwLocalPort), v4(r.dwRemoteAddr), port(r.dwRemotePort), r.dwOwningPid as i32)
        };
        rows(&b).into_iter().map(row).collect()
    }
}

/// Local endpoint and owning pid of the UDP sockets of one address family.
fn udp_rows(ipv6: bool) -> Vec<(IpAddr, u16, i32)> {
    let family = if ipv6 { AF_INET6 } else { AF_INET } as u32;
    let Some(b) = table(|p, sz| unsafe { GetExtendedUdpTable(p, sz, 0, family, UDP_TABLE_OWNER_PID, 0) }) else {
        return Vec::new();
    };
    if ipv6 {
        rows(&b).into_iter().map(|r: MIB_UDP6ROW_OWNER_PID| (v6(r.ucLocalAddr), port(r.dwLocalPort), r.dwOwningPid as i32)).collect()
    } else {
        rows(&b).into_iter().map(|r: MIB_UDPROW_OWNER_PID| (v4(r.dwLocalAddr), port(r.dwLocalPort), r.dwOwningPid as i32)).collect()
    }
}

/// The owner in one address family's table: a TCP connection with both
/// endpoints, or a UDP socket bound to the source port, on that address or
/// on all of them.
fn owner_in(key: &FlowKey, ipv6: bool) -> Option<i32> {
    let pid = if key.proto == TCP {
        let rows = tcp_rows(ipv6);
        let same_flow = |r: &&(IpAddr, u16, IpAddr, u16, i32)| r.1 == key.sport && r.3 == key.dport && same_ip(&r.2, &key.dst);
        rows.iter().filter(same_flow).find(|r| same_ip(&r.0, &key.src)).or_else(|| rows.iter().find(same_flow)).map(|r| r.4)
    } else {
        let rows = udp_rows(ipv6);
        rows.iter()
            .find(|r| r.1 == key.sport && same_ip(&r.0, &key.src))
            .or_else(|| rows.iter().find(|r| r.1 == key.sport && r.0.is_unspecified()))
            .map(|r| r.2)
    };
    pid.filter(|p| *p > 0)
}

/// The process owning the socket that sent this packet. The table of the
/// packet's address family first; then the other one, where an IPv4 flow
/// of a dual-stack socket is listed.
pub fn socket_owner(key: &FlowKey) -> Option<i32> {
    let ipv6 = key.src.is_ipv6();
    owner_in(key, ipv6).or_else(|| owner_in(key, !ipv6))
}
/// Services by hosting process, cached for a few seconds: one service
/// manager query covers every svchost seen in a burst of ClientHellos.
static SERVICES: Mutex<Option<(Instant, HashMap<u32, Vec<String>>)>> = Mutex::new(None);

fn enum_services() -> HashMap<u32, Vec<String>> {
    let mut out: HashMap<u32, Vec<String>> = HashMap::new();
    let scm = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ENUMERATE_SERVICE) };
    if scm.is_null() {
        return out;
    }
    let mut resume = 0u32;
    let mut buf: Vec<u64> = vec![0; 32 * 1024];
    loop {
        let (mut need, mut n) = (0u32, 0u32);
        let ok = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buf.as_mut_ptr() as *mut u8,
                (buf.len() * 8) as u32,
                &mut need,
                &mut n,
                &mut resume,
                null(),
            )
        };
        let more = ok == 0 && unsafe { GetLastError() } == ERROR_MORE_DATA;
        if ok == 0 && !more {
            break;
        }
        let entries = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
        for i in 0..n as usize {
            let e = unsafe { &*entries.add(i) };
            let pid = e.ServiceStatusProcess.dwProcessId;
            if pid == 0 || e.lpServiceName.is_null() {
                continue;
            }
            let len = (0..256).take_while(|&k| unsafe { *e.lpServiceName.add(k) } != 0).count();
            let name = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(e.lpServiceName, len) });
            out.entry(pid).or_default().push(name);
        }
        if !more {
            break;
        }
        if n == 0 && need as usize > buf.len() * 8 {
            buf = vec![0; need as usize / 8 + 1];
        }
    }
    unsafe { CloseServiceHandle(scm) };
    for v in out.values_mut() {
        v.sort();
    }
    out
}

/// Names of the services running in this process (`wuauserv`, `BITS`,
/// `DoSvc`): never localised, unlike their display names.
pub fn services(pid: i32) -> Vec<String> {
    if pid <= 0 {
        return Vec::new();
    }
    let mut g = SERVICES.lock().unwrap_or_else(|e| e.into_inner());
    let fresh = g.as_ref().is_some_and(|(t, _)| t.elapsed() < Duration::from_secs(5));
    if !fresh {
        *g = Some((Instant::now(), enum_services()));
    }
    g.as_ref().and_then(|(_, m)| m.get(&(pid as u32)).cloned()).unwrap_or_default()
}

fn reg_string(key: &str, value: &str) -> Option<String> {
    let (k, v) = (wide(key), wide(value));
    let mut buf = vec![0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    let r = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE as HKEY, k.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr() as *mut c_void, &mut len)
    };
    (r == NO_ERROR).then(|| from_wide(&buf)).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn reg_dword(key: &str, value: &str) -> Option<u32> {
    let (k, v) = (wide(key), wide(value));
    let mut d = 0u32;
    let mut len = 4u32;
    let r = unsafe {
        RegGetValueW(HKEY_LOCAL_MACHINE as HKEY, k.as_ptr(), v.as_ptr(), RRF_RT_REG_DWORD, null_mut(), &mut d as *mut u32 as *mut c_void, &mut len)
    };
    (r == NO_ERROR).then_some(d)
}

/// The marketing name: Windows 11 still reports itself as 10.0, from build
/// 22000 on.
pub fn os_release(major: u32, build: u32, workstation: bool) -> (&'static str, Option<String>) {
    if workstation {
        let v = if major == 10 && build >= 22000 { "11".to_string() } else { major.to_string() };
        return ("windows", Some(v));
    }
    let server = match build {
        14393 => Some("2016"),
        17763 => Some("2019"),
        20348 => Some("2022"),
        26100 => Some("2025"),
        _ => None,
    };
    ("windows server", server.map(str::to_string))
}

pub fn os_info() -> OsInfo {
    let mut v: OSVERSIONINFOEXW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;
    let ok = unsafe { RtlGetVersion(&mut v as *mut OSVERSIONINFOEXW as *mut OSVERSIONINFOW) } >= 0;
    const CURRENT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    const BIOS: &str = r"HARDWARE\DESCRIPTION\System\BIOS";
    // VER_NT_WORKSTATION
    let (os, version) = if ok { os_release(v.dwMajorVersion, v.dwBuildNumber, v.wProductType == 1) } else { ("windows", None) };
    let model = match (reg_string(BIOS, "SystemManufacturer"), reg_string(BIOS, "SystemProductName")) {
        (Some(m), Some(p)) if !p.starts_with(&m) => Some(format!("{} {}", m, p)),
        (_, Some(p)) => Some(p),
        (m, None) => m,
    };
    OsInfo {
        os: os.into(),
        distro: None,
        version,
        build: ok.then(|| match reg_dword(CURRENT, "UBR") {
            Some(ubr) => format!("{}.{}", v.dwBuildNumber, ubr),
            None => v.dwBuildNumber.to_string(),
        }),
        kernel: ok.then(|| format!("{}.{}.{}", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber)),
        model,
        arch: std::env::consts::ARCH.into(),
    }
}

pub fn system_dir() -> PathBuf {
    let mut buf = vec![0u16; 512];
    let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    if n == 0 || n > buf.len() {
        return PathBuf::from(r"C:\Windows\System32");
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..n]))
}

/// `%SystemRoot%` (the parent of System32), for telling OS files apart.
pub fn system_root() -> String {
    system_dir().parent().map(|p| p.display().to_string()).unwrap_or_else(|| r"C:\Windows".into())
}

/// Whether a path is a file of the operating system (under %SystemRoot%).
pub fn is_system_path(path: &str) -> bool {
    static ROOT: OnceLock<String> = OnceLock::new();
    under(path, ROOT.get_or_init(system_root))
}

/// Case-insensitive "is `path` inside `dir`".
pub fn under(path: &str, dir: &str) -> bool {
    let (p, d) = (path.to_ascii_lowercase().replace('/', "\\"), dir.to_ascii_lowercase().replace('/', "\\"));
    let d = d.trim_end_matches('\\');
    !d.is_empty() && p.len() > d.len() && p.starts_with(d) && p.as_bytes()[d.len()] == b'\\'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            split_command_line(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --type=utility --utility-sub-type=network.mojom.NetworkService --lang=fr"#),
            s(&[r"C:\Program Files\Google\Chrome\Application\chrome.exe", "--type=utility", "--utility-sub-type=network.mojom.NetworkService", "--lang=fr"])
        );
        assert_eq!(split_command_line(r#"C:\Windows\system32\svchost.exe -k netsvcs -p -s wuauserv"#), s(&[r"C:\Windows\system32\svchost.exe", "-k", "netsvcs", "-p", "-s", "wuauserv"]));
        assert_eq!(split_command_line(r#"python.exe "C:\a b\c.py" a\\\"b "x""y" \\server\share\"#), s(&["python.exe", r"C:\a b\c.py", r#"a\"b"#, r#"x"y"#, r"\\server\share\"]));
        assert_eq!(split_command_line(r#""C:\a\b.exe""#), s(&[r"C:\a\b.exe"]));
    }

    #[test]
    fn releases() {
        assert_eq!(os_release(10, 26100, true), ("windows", Some("11".into())));
        assert_eq!(os_release(10, 19045, true), ("windows", Some("10".into())));
        assert_eq!(os_release(10, 20348, false), ("windows server", Some("2022".into())));
    }

    #[test]
    fn paths() {
        assert!(under(r"C:\WINDOWS\System32\svchost.exe", r"C:\Windows"));
        assert!(!under(r"C:\WindowsApps\x.exe", r"C:\Windows"));
        assert!(!under(r"C:\Windows", r"C:\Windows"));
    }

    /// The process that owns a connection made here is this test.
    #[test]
    fn owner_of_own_sockets() {
        use std::net::{TcpListener, TcpStream, UdpSocket};
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let c = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (local, remote) = (c.local_addr().unwrap(), c.peer_addr().unwrap());
        let key = FlowKey { proto: TCP, src: local.ip(), sport: local.port(), dst: remote.ip(), dport: remote.port() };
        assert_eq!(socket_owner(&key), Some(std::process::id() as i32));
        let u = UdpSocket::bind("0.0.0.0:0").unwrap();
        let key = FlowKey {
            proto: crate::net::UDP,
            src: "192.0.2.1".parse().unwrap(),
            sport: u.local_addr().unwrap().port(),
            dst: "198.51.100.1".parse().unwrap(),
            dport: 443,
        };
        assert_eq!(socket_owner(&key), Some(std::process::id() as i32));
    }

    #[test]
    fn this_process() {
        let me = std::process::id() as i32;
        let b = basic(me).unwrap();
        assert!(b.start_us > 1_600_000_000_000_000);
        assert!(b.name.to_ascii_lowercase().ends_with(".exe"));
        // The path comes with the name, from the same query.
        assert_eq!(b.exe.as_deref().map(file_name), Some(b.name.clone()));
        // The image path has junctions resolved: compare the file names.
        let exe = exe_path(me).unwrap();
        let cur = std::env::current_exe().unwrap();
        assert!(file_name(&exe).eq_ignore_ascii_case(&cur.file_name().unwrap().to_string_lossy()), "{}", exe);
        assert!(args(me).unwrap().len() >= 1);
        assert!(mapped_files(me).iter().any(|m| m.to_ascii_lowercase().ends_with("kernel32.dll")));
        assert!(os_info().version.is_some());
    }
}
