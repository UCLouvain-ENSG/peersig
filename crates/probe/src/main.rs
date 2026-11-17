//! peersig-probe: ties each TLS, QUIC and DTLS ClientHello's JA4 to the
//! application that sent it, and records the names each process contacts.
//! See README.md.

mod attrib;
mod binary;
mod bundle;
mod capture;
mod dns;
mod domains;
mod fingerprint;
mod flow;
mod logdir;
mod net;
mod pipeline;
mod platform;
mod quic;
#[cfg(windows)]
mod service;
mod summary;
mod tls;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::json;

use attrib::Resolver;
use pipeline::{Options, Pipeline};

#[derive(Parser)]
#[command(version, about = "Ties TLS/QUIC/DTLS JA4 fingerprints to the applications that send them")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct RunOpts {
    /// Capture device. macOS default: the PKTAP pseudo-interface on all
    /// interfaces, which tags every packet with its process. Windows:
    /// `all` (default), or an interface index.
    #[arg(short, long)]
    interface: Option<String>,
    /// Output file (JSON lines). Default: peersig-probe-<date>-<time>.jsonl
    #[arg(short, long)]
    output: Option<String>,
    /// Daemon mode: daily files peersig-<date>.jsonl in this directory,
    /// a status.json heartbeat, and a `paused` file to stop capturing.
    #[arg(long)]
    dir: Option<String>,
    /// With --dir: user owning the files (default: who ran sudo). On
    /// Windows, the account's SID, given read access to the directory.
    #[arg(long)]
    owner: Option<String>,
    /// With --dir: delete daily files older than this.
    #[arg(long, default_value_t = 14)]
    keep_days: u32,
    /// Do not record server names (SNI, DNS, HTTP Host) nor the
    /// per-process name tables.
    #[arg(long)]
    no_names: bool,
    /// Kernel filter; "" for none. Default: outbound packets and DNS
    /// answers on PKTAP, none otherwise. Windows captures sent packets
    /// only, without BPF.
    #[arg(long)]
    bpf: Option<String>,
    #[arg(long, default_value_t = 16384)]
    snaplen: i32,
    /// Also save the captured packets (pcap, PKTAP link type on macOS;
    /// pcapng on Windows).
    #[arg(long)]
    save_pcap: Option<String>,
    /// Print every ClientHello (default: each new JA4/application pair).
    #[arg(short, long)]
    verbose: bool,
    /// Nothing on the terminal.
    #[arg(short, long)]
    quiet: bool,
    /// Seconds between the per-process name tables and stats records.
    #[arg(long, default_value_t = 300)]
    flush_every: u64,
    /// Stop after this many seconds.
    #[arg(long)]
    duration: Option<u64>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Capture live (needs root: sudo peersig-probe run; an administrator
    /// terminal on Windows)
    Run(RunOpts),
    /// Windows service entry point, used by the service the PeerSig app
    /// installs: `run`, under the service manager.
    #[cfg(windows)]
    #[command(hide = true)]
    Service(RunOpts),
    /// Read a capture file (no process lookups; PKTAP files keep the
    /// process names)
    Read {
        file: String,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(long)]
        no_names: bool,
        #[arg(short, long)]
        verbose: bool,
    },
    /// Aggregate logs: applications per JA4, names per application
    Summary {
        files: Vec<String>,
        /// Include server names (SNI per fingerprint, names per app).
        #[arg(long)]
        names: bool,
        /// table, json, or classifier (data/ja4_fingerprints.json format)
        #[arg(long, default_value = "table")]
        format: String,
        /// Fingerprint to group by: ja4, ja4_legacy (what the Iris classifier
        /// stored before 2026-11-16), ja4_o, ja3
        #[arg(long, default_value = "ja4")]
        key: String,
    },
    /// Show what peersig-probe knows about a process (no capture, no root needed
    /// for your own processes)
    Whois { pids: Vec<i32> },
}

impl RunOpts {
    fn into_args(self) -> RunArgs {
        RunArgs {
            interface: self.interface,
            output: self.output,
            dir: self.dir,
            owner: self.owner,
            keep_days: self.keep_days,
            names: !self.no_names,
            bpf: self.bpf,
            snaplen: self.snaplen,
            save_pcap: self.save_pcap,
            opts: Options { names: !self.no_names, verbose: self.verbose, console: !self.quiet },
            flush_every: self.flush_every,
            duration: self.duration,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run(o) => {
            let stop = Arc::new(AtomicBool::new(false));
            {
                let stop = stop.clone();
                ctrlc::set_handler(move || {
                    if stop.swap(true, Ordering::SeqCst) {
                        std::process::exit(130);
                    }
                })?;
            }
            run(o.into_args(), stop)
        }
        #[cfg(windows)]
        Cmd::Service(o) => service::start(o.into_args()),
        Cmd::Read { file, output, no_names, verbose } => read(&file, output, Options { names: !no_names, verbose, console: true }),
        Cmd::Summary { files, names, format, key } => summary::run(&files, &summary::Opts { names, format, key }),
        Cmd::Whois { pids } => whois(&pids),
    }
}

fn session_id() -> String {
    let mut b = [0u8; 8];
    match File::open("/dev/urandom") {
        Ok(mut f) => {
            let _ = std::io::Read::read_exact(&mut f, &mut b);
        }
        Err(_) => {
            // Windows: std seeds its hash keys from the system's random
            // generator.
            use std::hash::{BuildHasher, Hasher};
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
            b = h.finish().to_le_bytes();
        }
    }
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Output file owned by the user who ran sudo, so they can read and send it.
fn create_output(path: &str) -> Result<Box<dyn Write + Send>> {
    let f = File::create(path).with_context(|| format!("creating {}", path))?;
    #[cfg(unix)]
    if let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        if let (Ok(uid), Ok(gid)) = (uid.parse::<u32>(), gid.parse::<u32>()) {
            let c = std::ffi::CString::new(path).unwrap();
            unsafe { libc::chown(c.as_ptr(), uid, gid) };
        }
    }
    Ok(Box::new(BufWriter::with_capacity(1 << 16, f)))
}

fn start_record(device: &str, dlt: i32, filter: &str, live: bool, names: bool, db: &str) -> serde_json::Value {
    json!({
        "type": "start",
        "ts": now_ts(),
        "tool": format!("peersig-probe {}", env!("CARGO_PKG_VERSION")),
        "apps_db": db,
        "session": session_id(),
        // The capturing machine's OS; unknown for a capture file.
        "os": if live { serde_json::to_value(platform::os_info()).unwrap_or_default() } else { serde_json::Value::Null },
        "device": device,
        // Link type: 149 or 258 is PKTAP, with a process on every packet.
        "dlt": dlt,
        "filter": filter,
        "live": live,
        "names": names,
    })
}

fn now_ts() -> String {
    pipeline::ts_string(chrono::Utc::now().timestamp_micros() as f64 / 1e6)
}

pub struct RunArgs {
    interface: Option<String>,
    output: Option<String>,
    dir: Option<String>,
    owner: Option<String>,
    keep_days: u32,
    names: bool,
    bpf: Option<String>,
    snaplen: i32,
    save_pcap: Option<String>,
    opts: Options,
    flush_every: u64,
    duration: Option<u64>,
}

/// Captures until `stop` is set (Ctrl-C, or the Windows service manager).
fn run(a: RunArgs, stop: Arc<AtomicBool>) -> Result<()> {
    let RunArgs { interface, output, dir, owner, keep_days, names, bpf, snaplen, save_pcap, opts, flush_every, duration } = a;
    let device = interface.unwrap_or_else(|| platform::DEFAULT_DEVICE.to_string());
    if device.is_empty() {
        bail!("no default capture device on this OS: pass --interface");
    }
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 && device.starts_with("pktap") {
        bail!("capturing on {} needs root: sudo {}", device, std::env::args().collect::<Vec<_>>().join(" "));
    }
    if dir.is_some() && (output.is_some() || save_pcap.is_some()) {
        bail!("--dir writes daily files: it does not go with --output or --save-pcap");
    }
    let mut logdir = match &dir {
        Some(d) => Some(logdir::LogDir::new(std::path::Path::new(d), logdir::resolve_owner(owner.as_deref())?, keep_days)?),
        None => None,
    };
    // A daemon waits until it can capture, and says why in its status file
    // meanwhile.
    let cap = loop {
        match capture::Live::open(&device, snaplen, &bpf, names) {
            Ok(c) => break c,
            Err(e) => {
                let Some(l) = logdir.as_ref() else { return Err(e) };
                l.write_status(&json!({
                    "tool": format!("peersig-probe {}", env!("CARGO_PKG_VERSION")),
                    "pid": std::process::id(),
                    "updated": now_ts(),
                    "device": device,
                    "paused": l.paused(),
                    "error": format!("{:#}", e),
                }));
                for _ in 0..150 {
                    if stop.load(Ordering::SeqCst) {
                        return Ok(());
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    };
    let (dlt, filter_used) = (cap.dlt(), cap.filter().to_string());
    if !cfg!(windows) && !net::is_pktap(dlt) {
        // Always shown: on macOS this means the attribution is much weaker.
        eprintln!("warning: {} has no per-packet process metadata (link type {}); processes are looked up per ClientHello", device, dlt);
    }
    let (out, mut out_path) = match logdir.as_mut() {
        Some(l) => {
            l.prune();
            let (w, p) = l.open_today()?;
            (w, p.display().to_string())
        }
        None => {
            let p = output.unwrap_or_else(|| format!("peersig-probe-{}.jsonl", chrono::Local::now().format("%Y%m%d-%H%M%S")));
            (create_output(&p)?, p)
        }
    };
    let resolver = Resolver::new(true);
    let db_version = resolver.db.version.clone();
    let console = opts.console;
    let mut p = Pipeline::new(resolver, out, opts);
    p.write(&start_record(&device, dlt, &filter_used, true, names, &db_version));
    p.flush();
    if console {
        eprintln!("peersig-probe: capturing on {} (link type {}), writing {}; Ctrl-C to stop", device, dlt, out_path);
    }

    let paused = Arc::new(AtomicBool::new(logdir.as_ref().is_some_and(|l| l.paused())));
    let cap_stats: Arc<Mutex<Option<capture::Stats>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = sync_channel::<capture::Packet>(65_536);
    let cap_thread = {
        let stop = stop.clone();
        let paused = paused.clone();
        let stats = cap_stats.clone();
        let device = device.clone();
        let bpf = bpf.clone();
        std::thread::Builder::new().name("capture".into()).spawn(move || -> Result<()> {
            let mut cap = Some(cap);
            // Outlives a pause, which closes the device.
            let mut save = match (&save_pcap, cap.as_ref()) {
                (Some(path), Some(c)) => Some(c.saver(path, snaplen)?),
                _ => None,
            };
            let mut last = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                // Paused: the device is closed, not merely ignored.
                if paused.load(Ordering::Relaxed) {
                    cap = None;
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                let c = match cap.as_mut() {
                    Some(c) => c,
                    None => match capture::Live::open(&device, snaplen, &bpf, names) {
                        Ok(c) => cap.insert(c),
                        Err(e) => {
                            eprintln!("reopening {}: {:#}", device, e);
                            std::thread::sleep(Duration::from_secs(5));
                            continue;
                        }
                    },
                };
                if let Some(pkt) = c.next(save.as_mut())? {
                    if tx.send(pkt).is_err() {
                        break;
                    }
                }
                if last.elapsed() > Duration::from_secs(2) {
                    last = Instant::now();
                    if let Some(s) = c.stats() {
                        *stats.lock().unwrap() = Some(s);
                    }
                }
            }
            if let Some(s) = cap.as_mut().and_then(|c| c.stats()) {
                *stats.lock().unwrap() = Some(s);
            }
            if let Some(s) = save.as_mut() {
                let _ = s.flush();
            }
            Ok(())
        })?
    };

    let started = Instant::now();
    let started_ts = now_ts();
    let mut warned = false;
    let mut last_flush = Instant::now();
    let mut last_report = Instant::now();
    let mut last_status = Instant::now() - Duration::from_secs(60);
    let capture_stats = |s: &Arc<Mutex<Option<capture::Stats>>>| {
        let g = s.lock().unwrap();
        match &*g {
            Some(st) => json!({"received": st.received, "dropped": st.dropped, "if_dropped": st.if_dropped}),
            None => json!(null),
        }
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok((ts, dlt, data)) => p.packet(ts, dlt, &data),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if duration.map_or(false, |d| started.elapsed() >= Duration::from_secs(d)) {
            stop.store(true, Ordering::SeqCst);
        }
        if last_flush.elapsed() >= Duration::from_secs(1) {
            last_flush = Instant::now();
            p.flush();
            if let Some(l) = logdir.as_mut() {
                let now_paused = l.paused();
                if now_paused != paused.swap(now_paused, Ordering::SeqCst) {
                    last_status = Instant::now() - Duration::from_secs(60);
                    if console {
                        eprintln!("peersig-probe: {}", if now_paused { "paused" } else { "resumed" });
                    }
                }
                if l.needs_rotation() {
                    p.flush_domains();
                    let now = chrono::Utc::now().timestamp_micros() as f64 / 1e6;
                    let rec = p.stats_record(now, capture_stats(&cap_stats));
                    p.write(&rec);
                    let (w, path) = l.open_today()?;
                    p.set_output(w);
                    out_path = path.display().to_string();
                    p.write(&start_record(&device, dlt, &filter_used, true, names, &db_version));
                    l.prune();
                }
                if last_status.elapsed() >= Duration::from_secs(5) {
                    last_status = Instant::now();
                    let f = &p.tracker.stats;
                    l.write_status(&json!({
                        "tool": format!("peersig-probe {}", env!("CARGO_PKG_VERSION")),
                        "pid": std::process::id(),
                        "started": started_ts,
                        "updated": now_ts(),
                        "device": device,
                        "dlt": dlt,
                        "pktap": net::is_pktap(dlt),
                        "paused": paused.load(Ordering::SeqCst),
                        "names": names,
                        "packets": f.packets,
                        "hellos": {"tcp": f.tcp_hellos, "quic": f.quic_hellos, "dtls": f.dtls_hellos},
                        "last_hello": p.last_hello.map(pipeline::ts_string),
                        "file": out_path,
                        "keep_days": keep_days,
                    }));
                }
            }
        }
        if !warned && started.elapsed() > Duration::from_secs(15) && p.tracker.stats.packets == 0 && !paused.load(Ordering::Relaxed) {
            warned = true;
            if console {
                eprintln!(
                    "warning: no packet in 15 s{}",
                    if cfg!(windows) || filter_used.is_empty() { "" } else { "; if the network is in use, retry with --bpf \"\" (no kernel filter)" }
                );
            }
        }
        if last_report.elapsed() >= Duration::from_secs(flush_every) {
            last_report = Instant::now();
            p.flush_domains();
            let now = chrono::Utc::now().timestamp_micros() as f64 / 1e6;
            let rec = p.stats_record(now, capture_stats(&cap_stats));
            p.write(&rec);
            if console {
                let f = &p.tracker.stats;
                eprintln!(
                    "-- {} packets, ClientHellos tcp {} quic {} dtls {}, {} names",
                    f.packets, f.tcp_hellos, f.quic_hellos, f.dtls_hellos, p.counters.connections_named
                );
            }
        }
        if stop.load(Ordering::Relaxed) {
            // The capture thread stops within its 100 ms read timeout; keep
            // what it already queued.
            while let Ok((ts, dlt, data)) = rx.recv_timeout(Duration::from_millis(300)) {
                p.packet(ts, dlt, &data);
            }
            break;
        }
    }
    drop(rx);
    let failure = match cap_thread.join() {
        Ok(Err(e)) => Some(format!("capture error: {:#}", e)),
        Err(_) => Some("capture thread panicked".to_string()),
        _ => None,
    };
    if let Some(f) = &failure {
        eprintln!("{}", f);
    }
    p.flush_domains();
    let now = chrono::Utc::now().timestamp_micros() as f64 / 1e6;
    let rec = p.stats_record(now, capture_stats(&cap_stats));
    p.write(&rec);
    p.flush();
    if let Some(l) = &logdir {
        l.write_status(&json!({"tool": format!("peersig-probe {}", env!("CARGO_PKG_VERSION")), "stopped": pipeline::ts_string(now)}));
    }
    if console {
        let f = &p.tracker.stats;
        eprintln!(
            "peersig-probe: {} packets, ClientHellos tcp {} quic {} dtls {}; written to {}",
            f.packets, f.tcp_hellos, f.quic_hellos, f.dtls_hellos, out_path
        );
    }
    // A failed capture is an error exit, so that a service manager
    // restarts the probe.
    match failure {
        Some(f) => bail!(f),
        None => Ok(()),
    }
}

fn read(file: &str, output: Option<String>, opts: Options) -> Result<()> {
    let mut cap = capture::Offline::open(file).with_context(|| file.to_string())?;
    let dlt = cap.dlt();
    let out: Box<dyn Write + Send> = match &output {
        Some(p) => create_output(p)?,
        None => Box::new(BufWriter::new(std::io::stdout())),
    };
    let names = opts.names;
    let mut p = Pipeline::new(Resolver::new(false), out, Options { console: output.is_some(), ..opts });
    let db = p.resolver.db.version.clone();
    p.write(&start_record(file, dlt, "", false, names, &db));
    let mut last_ts = 0.0;
    while let Some((ts, dlt, data)) = cap.next()? {
        last_ts = ts;
        p.packet(ts, dlt, &data);
    }
    p.flush_domains();
    let rec = p.stats_record(last_ts, json!(null));
    p.write(&rec);
    p.flush();
    Ok(())
}

fn whois(pids: &[i32]) -> Result<()> {
    let mut r = Resolver::new(true);
    for &pid in pids {
        let meta = net::PktapMeta { pid, comm: String::new(), ..Default::default() };
        let key = net::FlowKey {
            proto: net::TCP,
            src: "0.0.0.0".parse().unwrap(),
            sport: 0,
            dst: "0.0.0.0".parse().unwrap(),
            dport: 0,
        };
        let a = r.attribute(Some(&meta), &key);
        let v = json!({
            "pid": pid,
            "app": a.app,
            "proc": a.proc.as_deref(),
            "resp": a.resp.as_deref().map(|p| &p.id),
        });
        println!("{}", serde_json::to_string_pretty(&v)?);
    }
    Ok(())
}
