//! Windows: the packet capture built into the system, so that PeerSig needs
//! nothing else installed. Every Windows 10 and 11 has the NDIS capture
//! filter (ndiscap.sys, what `netsh trace` and `pktmon` use) bound to its
//! adapters. It logs packets through ETW, as the provider
//! Microsoft-Windows-NDIS-PacketCapture, to the trace sessions that enable
//! it. The probe runs such a session, in real time, with only the send path
//! enabled: like the outbound filter on macOS, received traffic (downloads)
//! stays in the kernel.
//!
//! A session that enables this kernel provider needs an administrator, or
//! LocalSystem (the PeerSig service). Sessions outlive their process, so a
//! session left by a probe that died is stopped at the next start.
//!
//! One capture covers every adapter. Packets from adapters with no IP
//! address are left out: a network card under a Hyper-V switch carries the
//! same packets as the switch's virtual adapter, which has the address.
//! Loopback traffic does not go through NDIS and is not seen.
//!
//! The session also enables Microsoft-Windows-Bits-Client: which program
//! created each BITS job and which URLs its transfers fetch (`crate::bits`),
//! so that a download the BITS service makes for a program is credited to
//! that program. Its fields are read by name (TDH), as the event log shows
//! them.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::null;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, QueryAllTracesW, StartTraceW, TdhGetProperty,
    TdhGetPropertySize, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR,
    WNODE_FLAG_TRACED_GUID,
};

use super::file::Writer;
use super::{Packet, Stats};
use crate::platform::wide;

/// Microsoft-Windows-NDIS-PacketCapture.
const PROVIDER: GUID = GUID::from_u128(0x2ed6006e_4729_4609_b423_3ee7bcd678ef);
/// "Packet fragment": MiniportIfIndex, LowerIfIndex, FragmentSize, Fragment.
const EVENT_FRAGMENT: u16 = 1001;
const KW_ETHERNET: u64 = 0x1;
const KW_WWAN: u64 = 0x200;
const KW_TUNNEL: u64 = 0x8000;
const KW_NATIVE_802_11: u64 = 0x1_0000;
const KW_START: u64 = 0x4000_0000;
const KW_END: u64 = 0x8000_0000;
const KW_SEND: u64 = 0x1_0000_0000;
const TRACE_LEVEL_VERBOSE: u8 = 5;

/// Microsoft-Windows-Bits-Client.
const BITS_PROVIDER: GUID = GUID::from_u128(0xef1cc15b_46c1_414e_bb95_e76b077bd51e);
/// Its operational channel's events: 3 job created (jobId, processPath,
/// processId), 16403 file added (jobId, RemoteName, processId), 59 and
/// 60/61 transfer started and stopped (Id, url), 4 and 5 job completed and
/// cancelled (jobId).
const BITS_JOB_CREATED: u16 = 3;
const BITS_JOB_COMPLETED: u16 = 4;
const BITS_JOB_CANCELLED: u16 = 5;
const BITS_TRANSFER_STARTED: u16 = 59;
const BITS_TRANSFER_STOPPED: u16 = 60;
const BITS_TRANSFER_FAILED: u16 = 61;
const BITS_FILE_ADDED: u16 = 16403;
const TRACE_LEVEL_INFORMATION: u8 = 4;

const SESSION_PREFIX: &str = "PeerSig Capture";
/// Link types: Ethernet (wired, and Wi-Fi adapters that present themselves
/// as Ethernet), 802.11 (Wi-Fi adapters whose NDIS medium is Native 802.11,
/// most of them: their packets are logged as 802.11 data frames, with an
/// LLC/SNAP header, also outside monitor mode), raw IP (mobile broadband,
/// tunnels).
const DLT_EN10MB: i32 = 1;
const DLT_RAW: i32 = 101;
const DLT_IEEE802_11: i32 = 105;

/// An EVENT_TRACE_PROPERTIES with room for the session and file names.
struct Props(Vec<u64>);

impl Props {
    fn new() -> Props {
        let base = size_of::<EVENT_TRACE_PROPERTIES>();
        let total = base + 2 * 1024 * 2;
        let mut v = vec![0u64; total / 8 + 1];
        let p = v.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        unsafe {
            (*p).Wnode.BufferSize = total as u32;
            (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            // Event times as FILETIMEs (system time).
            (*p).Wnode.ClientContext = 2;
            // Buffers flushed every 100 ms (EVENT_TRACE_USE_MS_FLUSH_TIMER):
            // a ClientHello reaches the probe while its connection is still
            // open, for the socket owner lookup. The default, a second, misses
            // short connections.
            (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE | 0x10;
            (*p).BufferSize = 64;
            (*p).MinimumBuffers = 16;
            (*p).MaximumBuffers = 256;
            (*p).FlushTimer = 100;
            (*p).LoggerNameOffset = base as u32;
            (*p).LogFileNameOffset = (base + 1024 * 2) as u32;
        }
        Props(v)
    }
    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.0.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }
    fn get(&self) -> &EVENT_TRACE_PROPERTIES {
        unsafe { &*(self.0.as_ptr() as *const EVENT_TRACE_PROPERTIES) }
    }
}

fn stop_session(name: &str) {
    let mut p = Props::new();
    unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, wide(name).as_ptr(), p.ptr(), EVENT_TRACE_CONTROL_STOP) };
}

/// Stops the sessions of probes that are gone ("PeerSig Capture <pid>").
fn stop_stale_sessions() {
    const N: usize = 64;
    let mut props: Vec<Props> = (0..N).map(|_| Props::new()).collect();
    let mut ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> = props.iter_mut().map(|p| p.ptr()).collect();
    let mut count = 0u32;
    if unsafe { QueryAllTracesW(ptrs.as_mut_ptr(), N as u32, &mut count) } != NO_ERROR {
        return;
    }
    for p in props.iter().take(count as usize) {
        let off = p.get().LoggerNameOffset as usize;
        let bytes = unsafe { std::slice::from_raw_parts((p.0.as_ptr() as *const u8).add(off) as *const u16, 1024) };
        let end = bytes.iter().position(|&c| c == 0).unwrap_or(0);
        let name = String::from_utf16_lossy(&bytes[..end]);
        let Some(pid) = name.strip_prefix(SESSION_PREFIX).and_then(|r| r.trim().parse::<u32>().ok()) else { continue };
        let alive = pid == std::process::id()
            || crate::platform::exe_path(pid as i32).is_some_and(|e| e.to_ascii_lowercase().ends_with("peersig-probe.exe"));
        if !alive {
            stop_session(&name);
        }
    }
}

/// Adapters with an IP address (by interface index), refreshed now and
/// then: an adapter that comes up is picked up within seconds.
struct Adapters {
    with_address: HashSet<u32>,
    at: Instant,
}

impl Adapters {
    fn load() -> Adapters {
        let mut with_address = HashSet::new();
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size = 32 * 1024u32;
        for _ in 0..4 {
            let mut buf = vec![0u64; size as usize / 8 + 1];
            let r = unsafe {
                GetAdaptersAddresses(AF_UNSPEC as u32, flags, null(), buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH, &mut size)
            };
            if r == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if r == NO_ERROR {
                let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
                while !p.is_null() {
                    let a = unsafe { &*p };
                    if !a.FirstUnicastAddress.is_null() {
                        with_address.insert(unsafe { a.Anonymous1.Anonymous.IfIndex });
                        with_address.insert(a.Ipv6IfIndex);
                    }
                    p = a.Next;
                }
            }
            break;
        }
        with_address.remove(&0);
        Adapters { with_address, at: Instant::now() }
    }

    fn usable(&mut self, index: u32) -> bool {
        let stale = self.at.elapsed() > Duration::from_secs(60);
        let unknown = !self.with_address.contains(&index) && self.at.elapsed() > Duration::from_secs(5);
        if stale || unknown {
            *self = Adapters::load();
        }
        self.with_address.contains(&index)
    }
}

/// What the event callback works with (on the ProcessTrace thread).
struct Ctx {
    tx: SyncSender<Packet>,
    snaplen: usize,
    iface: Option<u32>,
    adapters: Adapters,
    /// Packets being put together from their fragments, by the thread that
    /// logs them: a packet's fragments come from one thread, in order, but
    /// two threads' packets can interleave.
    partial: HashMap<u32, Packet>,
    received: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
}

/// FILETIME (100 ns since 1601) to Unix seconds.
fn unix_time(ft: i64) -> f64 {
    (ft - 116_444_736_000_000_000) as f64 / 1e7
}

/// A property of an event, by name, as raw bytes.
fn property(rec: &EVENT_RECORD, name: &str) -> Option<Vec<u8>> {
    let w = wide(name);
    let desc = PROPERTY_DATA_DESCRIPTOR { PropertyName: w.as_ptr() as u64, ArrayIndex: u32::MAX, Reserved: 0 };
    let mut size = 0u32;
    if unsafe { TdhGetPropertySize(rec, 0, null(), 1, &desc, &mut size) } != NO_ERROR || size == 0 || size > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    (unsafe { TdhGetProperty(rec, 0, null(), 1, &desc, size, buf.as_mut_ptr()) } == NO_ERROR).then_some(buf)
}

fn string_property(rec: &EVENT_RECORD, name: &str) -> Option<String> {
    let b = property(rec, name)?;
    let w: Vec<u16> = b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    Some(String::from_utf16_lossy(&w))
}

fn guid_property(rec: &EVENT_RECORD, name: &str) -> Option<u128> {
    property(rec, name)?.get(..16)?.try_into().ok().map(u128::from_le_bytes)
}

fn u32_property(rec: &EVENT_RECORD, name: &str) -> Option<u32> {
    property(rec, name)?.get(..4)?.try_into().ok().map(u32::from_le_bytes)
}

/// A BITS event: what the job tracker needs from it.
fn on_bits_event(rec: &EVENT_RECORD) {
    let t = unix_time(rec.EventHeader.TimeStamp);
    let id = |name: &str| guid_property(rec, name);
    match rec.EventHeader.EventDescriptor.Id {
        BITS_JOB_CREATED => {
            let (Some(job), Some(path)) = (id("jobId"), string_property(rec, "processPath")) else { return };
            let pid = u32_property(rec, "processId").unwrap_or(0);
            crate::bits::JOBS.lock().map(|mut j| j.created(job, &path, pid, t)).ok();
        }
        BITS_FILE_ADDED => {
            let (Some(job), Some(url)) = (id("jobId"), string_property(rec, "RemoteName")) else { return };
            // The process adding the file, while it is there to ask.
            let adder = u32_property(rec, "processId")
                .and_then(|pid| crate::platform::exe_path(pid as i32).map(|path| (path, pid)));
            crate::bits::JOBS.lock().map(|mut j| j.file_added(job, &url, adder, t)).ok();
        }
        BITS_TRANSFER_STARTED | BITS_TRANSFER_STOPPED | BITS_TRANSFER_FAILED => {
            let (Some(job), Some(url)) = (id("Id"), string_property(rec, "url")) else { return };
            let started = rec.EventHeader.EventDescriptor.Id == BITS_TRANSFER_STARTED;
            crate::bits::JOBS
                .lock()
                .map(|mut j| if started { j.transfer_started(job, &url, t) } else { j.transfer_stopped(job, &url, t) })
                .ok();
        }
        BITS_JOB_COMPLETED | BITS_JOB_CANCELLED => {
            let Some(job) = id("jobId") else { return };
            crate::bits::JOBS.lock().map(|mut j| j.ended(job, t)).ok();
        }
        _ => {}
    }
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let rec = unsafe { &*rec };
    let h = &rec.EventHeader;
    if guid_eq(&h.ProviderId, &BITS_PROVIDER) {
        on_bits_event(rec);
        return;
    }
    if h.EventDescriptor.Id != EVENT_FRAGMENT || !guid_eq(&h.ProviderId, &PROVIDER) || rec.UserContext.is_null() {
        return;
    }
    let ctx = unsafe { &mut *(rec.UserContext as *mut Ctx) };
    let kw = h.EventDescriptor.Keyword;
    if kw & KW_SEND == 0 {
        return;
    }
    let dlt = if kw & KW_ETHERNET != 0 {
        DLT_EN10MB
    } else if kw & KW_NATIVE_802_11 != 0 {
        DLT_IEEE802_11
    } else if kw & (KW_WWAN | KW_TUNNEL) != 0 {
        DLT_RAW
    } else {
        // Virtual switch internals.
        return;
    };
    if rec.UserData.is_null() || rec.UserDataLength < 12 {
        return;
    }
    let d = unsafe { std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize) };
    let index = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
    let size = u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as usize;
    let fragment = &d[12..12 + size.min(d.len() - 12)];
    if ctx.iface.is_some_and(|i| i != index) || !ctx.adapters.usable(index) {
        return;
    }
    // A packet is one event with both keywords, or a start, any number of
    // fragments, and an end.
    if kw & KW_START != 0 {
        if ctx.partial.len() > 256 {
            ctx.partial.clear();
        }
        ctx.partial.insert(h.ThreadId, (unix_time(h.TimeStamp), dlt, Vec::with_capacity(fragment.len())));
    }
    // No entry: a fragment whose start was not seen.
    let Some(pkt) = ctx.partial.get_mut(&h.ThreadId) else { return };
    let room = ctx.snaplen.saturating_sub(pkt.2.len());
    pkt.2.extend_from_slice(&fragment[..room.min(fragment.len())]);
    if kw & KW_END != 0 {
        let Some(pkt) = ctx.partial.remove(&h.ThreadId) else { return };
        ctx.received.fetch_add(1, Ordering::Relaxed);
        // The callback must not block ETW: a full queue drops.
        if ctx.tx.try_send(pkt).is_err() {
            ctx.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

struct SendPtr(*mut Ctx, PROCESSTRACE_HANDLE);
unsafe impl Send for SendPtr {}

pub struct Live {
    name: String,
    handle: CONTROLTRACE_HANDLE,
    rx: Receiver<Packet>,
    thread: Option<std::thread::JoinHandle<()>>,
    received: Arc<AtomicU64>,
    dropped: Arc<AtomicU64>,
    filter: String,
}

pub type Saver = Writer;

impl Live {
    /// `device`: `all`, or an interface index (`Get-NetAdapter` shows
    /// them) to capture on one adapter only. There is no BPF here.
    pub fn open(device: &str, snaplen: i32, bpf: &Option<String>, _names: bool) -> Result<Live> {
        let iface = match device {
            "all" | "" => None,
            d => Some(d.parse::<u32>().map_err(|_| anyhow::anyhow!("--interface on Windows: `all` or an interface index, not {:?}", d))?),
        };
        if bpf.as_deref().is_some_and(|f| !f.is_empty()) {
            eprintln!("warning: --bpf is not available on Windows; only sent packets are captured");
        }
        stop_stale_sessions();
        let name = format!("{} {}", SESSION_PREFIX, std::process::id());
        let wname = wide(&name);
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut props = Props::new();
        let mut r = unsafe { StartTraceW(&mut handle, wname.as_ptr(), props.ptr()) };
        if r == ERROR_ALREADY_EXISTS {
            stop_session(&name);
            props = Props::new();
            r = unsafe { StartTraceW(&mut handle, wname.as_ptr(), props.ptr()) };
        }
        if r == ERROR_ACCESS_DENIED {
            bail!("capturing needs an administrator: run it from an administrator terminal (the PeerSig service runs as LocalSystem)");
        }
        if r != NO_ERROR {
            bail!("starting the capture session: {}", std::io::Error::from_raw_os_error(r as i32));
        }
        let r = unsafe { EnableTraceEx2(handle, &PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, KW_SEND, 0, 0, null()) };
        if r != NO_ERROR {
            stop_session(&name);
            bail!("enabling the NDIS packet capture: {}", std::io::Error::from_raw_os_error(r as i32));
        }
        // BITS jobs, for its downloads' programs: capture works without.
        let r = unsafe {
            EnableTraceEx2(handle, &BITS_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, u64::MAX, 0, 0, null())
        };
        if r != NO_ERROR {
            eprintln!("warning: BITS events unavailable ({}): its downloads stay credited to BITS", std::io::Error::from_raw_os_error(r as i32));
        }
        let (tx, rx) = sync_channel::<Packet>(65_536);
        let received = Arc::new(AtomicU64::new(0));
        let dropped = Arc::new(AtomicU64::new(0));
        let ctx = Box::into_raw(Box::new(Ctx {
            tx,
            snaplen: snaplen.max(64) as usize,
            iface,
            adapters: Adapters::load(),
            partial: HashMap::new(),
            received: received.clone(),
            dropped: dropped.clone(),
        }));
        let mut wname_mut = wname.clone();
        let mut lf: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
        lf.LoggerName = wname_mut.as_mut_ptr();
        lf.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        lf.Anonymous2.EventRecordCallback = Some(on_event);
        lf.Context = ctx as *mut c_void;
        let trace = unsafe { OpenTraceW(&mut lf) };
        if trace.Value == u64::MAX {
            let e = std::io::Error::last_os_error();
            stop_session(&name);
            drop(unsafe { Box::from_raw(ctx) });
            bail!("opening the capture session: {}", e);
        }
        let p = SendPtr(ctx, trace);
        let thread = std::thread::Builder::new().name("etw".into()).spawn(move || {
            let p = p;
            // Returns when the session stops.
            unsafe { ProcessTrace(&p.1, 1, null(), null()) };
            unsafe { CloseTrace(p.1) };
            drop(unsafe { Box::from_raw(p.0) });
        })?;
        let filter = match iface {
            Some(i) => format!("etw:ndis send path, interface {}", i),
            None => "etw:ndis send path".into(),
        };
        Ok(Live { name, handle, rx, thread: Some(thread), received, dropped, filter })
    }

    /// Ethernet; each packet has its own link type (Wi-Fi adapters give
    /// 802.11 frames, mobile broadband and tunnel adapters raw IP packets).
    pub fn dlt(&self) -> i32 {
        DLT_EN10MB
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// A file for `--save-pcap` (pcapng).
    pub fn saver(&self, path: &str, snaplen: i32) -> Result<Saver> {
        Writer::create(path, snaplen.max(0) as u32)
    }

    /// The next packet, also written to `save`; None after 100 ms without
    /// one.
    pub fn next(&mut self, save: Option<&mut Saver>) -> Result<Option<Packet>> {
        match self.rx.recv_timeout(Duration::from_millis(100)) {
            Ok(p) => {
                if let Some(w) = save {
                    w.write(p.0, p.1, &p.2)?;
                }
                Ok(Some(p))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => bail!("the capture session {:?} was stopped", self.name),
        }
    }

    /// Packets read, packets dropped here (queue full), and events ETW lost.
    pub fn stats(&mut self) -> Option<Stats> {
        let mut p = Props::new();
        let lost = if unsafe { ControlTraceW(self.handle, null(), p.ptr(), EVENT_TRACE_CONTROL_QUERY) } == NO_ERROR {
            p.get().EventsLost as u64 + p.get().RealTimeBuffersLost as u64
        } else {
            0
        };
        Some(Stats {
            received: self.received.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            if_dropped: lost,
        })
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let mut p = Props::new();
        unsafe { ControlTraceW(self.handle, null(), p.ptr(), EVENT_TRACE_CONTROL_STOP) };
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        // 2026-11-17T00:00:00Z
        let ft = (1_794_873_600i64 * 10_000_000) + 116_444_736_000_000_000;
        assert!((unix_time(ft) - 1_794_873_600.0).abs() < 1e-6);
    }

    #[test]
    fn adapters() {
        // This computer has at least one adapter with an address (or none,
        // offline): loading must not fail.
        let a = Adapters::load();
        assert!(!a.with_address.contains(&0));
    }
}
