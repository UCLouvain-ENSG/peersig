//! The capture: each packet an app sends into the VPN interface goes
//! through the probe's own pipeline (crates/probe), as packets from a
//! capture device do on a computer, and the records go to the same daily
//! logs (`peersig-<date>.jsonl`, kept 14 days) and `status.json`, which
//! the participant's side reads as everywhere else.
//!
//! The pipeline asks the system which app owns each ClientHello's
//! connection, by uid ([`UidOwners`]), instead of looking processes up.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::json;

use peersig_probe::attrib::{App, AppsDb, Owners, Process, Resolver};
use peersig_probe::logdir::LogDir;
use peersig_probe::net::{FlowKey, DLT_RAW};
use peersig_probe::pipeline::{now_ts, start_record, ts_string, Options, Pipeline};

use crate::apps;
use crate::Java;

/// When a packet was read, and the IP packet.
pub type Packet = (f64, Vec<u8>);

/// Daily files older than this are deleted, as by the desktop probe.
pub const KEEP_DAYS: u32 = 14;
/// The device the records name.
const DEVICE: &str = "vpn";

/// An app, as the pipeline credits it.
type Owner = Option<(Arc<Process>, App)>;

/// Uid -> app, through the app's Kotlin side, cached: the package
/// manager is slow, and a ClientHello's app rarely changes.
pub struct UidOwners {
    java: Arc<dyn Java>,
    db: AppsDb,
    apps: HashMap<u32, (Instant, Owner)>,
}

impl UidOwners {
    pub fn new(java: Arc<dyn Java>) -> UidOwners {
        UidOwners { java, db: AppsDb::load(), apps: HashMap::new() }
    }
}

impl Owners for UidOwners {
    fn owner(&mut self, key: &FlowKey) -> Owner {
        let uid = self.java.owner_uid(key.proto, (key.src, key.sport).into(), (key.dst, key.dport).into())?;
        // Ten minutes: an app updated meanwhile shows its new version soon.
        if let Some((t, a)) = self.apps.get(&uid) {
            if t.elapsed() < Duration::from_secs(600) {
                return a.clone();
            }
        }
        let facts = self.java.package_facts(uid);
        let a = apps::app_of(uid, facts.as_ref(), &self.db);
        if self.apps.len() > 4096 {
            self.apps.clear();
        }
        self.apps.insert(uid, (Instant::now(), a.clone()));
        a
    }
}

/// Counters the forwarder and the window read.
#[derive(Default)]
pub struct Counters {
    /// The VPN is up: packets are coming.
    pub running: AtomicBool,
    /// Counts the VPN interfaces started, so that one that ends after
    /// the next started does not mark the capture stopped.
    pub generation: AtomicU64,
    /// Packets the pipeline could not keep up with.
    pub dropped: AtomicU64,
    /// Connections and datagram flows forwarded.
    pub tcp: AtomicU64,
    pub udp: AtomicU64,
    /// Connections that could not be opened to their destination.
    pub failed: AtomicU64,
}

/// The pipeline's thread, for as long as the app's process lives.
pub struct Capture {
    tx: SyncSender<Packet>,
    pub counters: Arc<Counters>,
    /// Why the capture cannot run (written to `status.json`).
    pub error: Arc<std::sync::Mutex<Option<String>>>,
}

impl Capture {
    pub fn start(logs: &Path, owners: Box<dyn Owners>) -> Result<Capture> {
        let dir = LogDir::new(logs, None, KEEP_DAYS)?;
        let (tx, rx) = sync_channel::<Packet>(16_384);
        let counters = Arc::new(Counters::default());
        let error = Arc::new(std::sync::Mutex::new(None));
        let (c, e) = (counters.clone(), error.clone());
        std::thread::Builder::new().name("peersig-capture".into()).spawn(move || {
            if let Err(err) = run(dir, owners, rx, c, e) {
                log::error!("capture: {:#}", err);
            }
        })?;
        Ok(Capture { tx, counters, error })
    }

    pub fn sender(&self) -> SyncSender<Packet> {
        self.tx.clone()
    }
}

fn status(p: &Pipeline, c: &Counters, started: &str, file: &Path, error: Option<String>) -> serde_json::Value {
    let f = &p.tracker.stats;
    let running = c.running.load(Ordering::Relaxed);
    let mut v = json!({
        "tool": format!("peersig-android {}", env!("CARGO_PKG_VERSION")),
        "started": started,
        "updated": now_ts(),
        "device": DEVICE,
        "dlt": DLT_RAW,
        "pktap": false,
        "paused": !running,
        "names": true,
        "packets": f.packets,
        "hellos": {"tcp": f.tcp_hellos, "quic": f.quic_hellos, "dtls": f.dtls_hellos},
        "last_hello": p.last_hello.map(ts_string),
        "file": file.display().to_string(),
        "keep_days": KEEP_DAYS,
        "dropped": c.dropped.load(Ordering::Relaxed),
        "flows": {"tcp": c.tcp.load(Ordering::Relaxed), "udp": c.udp.load(Ordering::Relaxed), "failed": c.failed.load(Ordering::Relaxed)},
    });
    // The window shows a capture that is not running as stopped, with why.
    if !running {
        v["stopped"] = json!(now_ts());
    }
    if let Some(e) = error {
        v["error"] = json!(e);
    }
    v
}

fn run(
    mut dir: LogDir,
    owners: Box<dyn Owners>,
    rx: Receiver<Packet>,
    counters: Arc<Counters>,
    error: Arc<std::sync::Mutex<Option<String>>>,
) -> Result<()> {
    let mut resolver = Resolver::new(true);
    resolver.owners = Some(owners);
    let db = resolver.db.version.clone();
    dir.prune();
    let (w, mut file) = dir.open_today()?;
    let mut p = Pipeline::new(resolver, w, Options { names: true, verbose: false, console: false });
    p.write(&start_record(DEVICE, DLT_RAW, "", true, true, &db));
    p.flush();
    let started = now_ts();
    let mut last_flush = Instant::now();
    let mut last_report = Instant::now();
    let mut last_status = Instant::now() - Duration::from_secs(60);
    let mut was_running = false;
    let now = || chrono::Utc::now().timestamp_micros() as f64 / 1e6;
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok((ts, data)) => p.packet(ts, DLT_RAW, &data),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if last_flush.elapsed() < Duration::from_secs(1) {
            continue;
        }
        last_flush = Instant::now();
        p.flush();
        let running = counters.running.load(Ordering::Relaxed);
        // Stopped: the names seen so far are written now.
        if was_running && !running {
            p.flush_domains();
            let rec = p.stats_record(now(), json!({"dropped": counters.dropped.load(Ordering::Relaxed)}));
            p.write(&rec);
            p.flush();
            last_status = Instant::now() - Duration::from_secs(60);
        }
        if running && !was_running {
            last_status = Instant::now() - Duration::from_secs(60);
        }
        was_running = running;
        if dir.needs_rotation() {
            p.flush_domains();
            let rec = p.stats_record(now(), json!({"dropped": counters.dropped.load(Ordering::Relaxed)}));
            p.write(&rec);
            let (w, path) = dir.open_today()?;
            p.set_output(w);
            file = path;
            p.write(&start_record(DEVICE, DLT_RAW, "", true, true, &db));
            dir.prune();
        }
        if last_status.elapsed() >= Duration::from_secs(5) {
            last_status = Instant::now();
            let e = error.lock().unwrap().clone();
            dir.write_status(&status(&p, &counters, &started, &file, e));
        }
        if last_report.elapsed() >= Duration::from_secs(300) {
            last_report = Instant::now();
            p.flush_domains();
            let rec = p.stats_record(now(), json!({"dropped": counters.dropped.load(Ordering::Relaxed)}));
            p.write(&rec);
        }
    }
    p.flush_domains();
    p.flush();
    Ok(())
}

/// Whether the pipeline needs a packet: everything but TCP segments
/// without data or SYN (the ACKs of downloads), which never carry a
/// ClientHello.
pub fn wanted(pkt: &[u8]) -> bool {
    let (proto, l4) = match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => {
            let ihl = ((pkt[0] & 0x0f) as usize) * 4;
            let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            // A fragment's first packet holds its header; later ones go too.
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0;
            if frag || ihl < 20 || pkt.len() < ihl {
                return true;
            }
            (pkt[9], &pkt[ihl..total.clamp(ihl, pkt.len())])
        }
        // Extension headers: not worth parsing here.
        Some(6) if pkt.len() >= 40 => (pkt[6], &pkt[40..]),
        _ => return true,
    };
    if proto != 6 || l4.len() < 20 {
        return true;
    }
    let off = ((l4[12] >> 4) as usize) * 4;
    let syn = l4[13] & 0x02 != 0;
    syn || l4.len() > off
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apps::PackageFacts;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    struct FakeJava {
        asked: Mutex<Vec<(u8, SocketAddr, SocketAddr)>>,
    }

    impl Java for FakeJava {
        fn owner_uid(&self, proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
            self.asked.lock().unwrap().push((proto, src, dst));
            Some(10_123)
        }
        fn package_facts(&self, _uid: u32) -> Option<PackageFacts> {
            Some(PackageFacts { packages: vec!["com.example.app".into()], label: Some("Example".into()), version: Some("1.2.3".into()), ..Default::default() })
        }
        fn capture_allowed(&self) -> bool {
            true
        }
        fn notify(&self, _body: &str) {}
        fn state(&self, _view: &str, _tray: &str) {}
    }

    /// An IPv4 TCP segment from 10.88.0.1:40000 to 192.0.2.7:443.
    fn segment(flags: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 88, 0, 1, 192, 0, 2, 7];
        let total = (20 + 20 + payload.len()) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn filter() {
        assert!(wanted(&segment(0x02, 1, b"")), "SYN");
        assert!(wanted(&segment(0x18, 2, b"\x16\x03\x01")), "data");
        assert!(!wanted(&segment(0x10, 2, b"")), "bare ACK");
        assert!(wanted(&[0x60; 8]), "short");
    }

    /// A ClientHello sent into the VPN becomes a `hello` record naming the
    /// app the system gave, which the participant's side reads as an item.
    #[test]
    fn hello_from_the_vpn() {
        let ch = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../probe/tests/data/ch_curl.bin")).unwrap();
        let logs = std::env::temp_dir().join(format!("peersig-android-capture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&logs);
        let java = Arc::new(FakeJava { asked: Mutex::new(vec![]) });
        let cap = Capture::start(&logs, Box::new(UidOwners::new(java.clone()))).unwrap();
        cap.counters.running.store(true, Ordering::Relaxed);
        let tx = cap.sender();
        let t = chrono::Utc::now().timestamp() as f64;
        tx.send((t, segment(0x02, 1000, b""))).unwrap();
        tx.send((t, segment(0x18, 1001, &ch))).unwrap();
        // The thread writes within a second or two.
        let mut text = String::new();
        for _ in 0..50 {
            std::thread::sleep(Duration::from_millis(100));
            text = peersig_proto::logs::files(&logs).iter().map(|f| std::fs::read_to_string(f).unwrap()).collect();
            if text.contains(r#""type":"hello""#) && logs.join("status.json").exists() {
                break;
            }
        }
        let hello: serde_json::Value = text.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).find(|v| v["type"] == "hello").expect(&text);
        assert_eq!(hello["attribution"], "uid");
        assert_eq!(hello["app"]["name"], "Example");
        assert_eq!(hello["app"]["id"], "com.example.app");
        assert_eq!(hello["app"]["kind"], "app");
        assert_eq!(hello["proc"], "com.example.app");
        assert!(hello["ja4"].as_str().unwrap().starts_with("t1"), "{}", hello);
        let asked = java.asked.lock().unwrap()[0];
        assert_eq!(asked, (6, "10.88.0.1:40000".parse().unwrap(), "192.0.2.7:443".parse().unwrap()));
        // What the participant's side makes of it: an item for "android".
        let start: serde_json::Value = text.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()).find(|v| v["type"] == "start").unwrap();
        assert_eq!(start["device"], "vpn");
        let status: serde_json::Value = serde_json::from_slice(&std::fs::read(logs.join("status.json")).unwrap()).unwrap();
        assert!(status["hellos"]["tcp"].as_u64().unwrap() >= 1, "{}", status);
        assert!(status.get("stopped").is_none());
        let _ = std::fs::remove_dir_all(&logs);
    }
}
