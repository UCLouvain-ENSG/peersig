//! peersig-probe: ties each TLS, QUIC and DTLS ClientHello's JA4 to the
//! application that sent it, and records the names each process contacts.
//! See README.md.

mod attrib;
mod binary;
mod bundle;
mod dns;
mod domains;
mod fingerprint;
mod flow;
mod logdir;
mod net;
mod pipeline;
mod platform;
mod quic;
mod summary;
mod tls;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use attrib::Resolver;
use pipeline::{Options, Pipeline};

#[derive(Parser)]
#[command(version, about = "Ties TLS/QUIC/DTLS JA4 fingerprints to the applications that send them")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Capture live (needs root: sudo peersig-probe run)
    Run {
        /// Capture device. macOS default: the PKTAP pseudo-interface on all
        /// interfaces, which tags every packet with its process.
        #[arg(short, long)]
        interface: Option<String>,
        /// Output file (JSON lines). Default: peersig-probe-<date>-<time>.jsonl
        #[arg(short, long)]
        output: Option<String>,
        /// Daemon mode: daily files peersig-<date>.jsonl in this directory,
        /// a status.json heartbeat, and a `paused` file to stop capturing.
        #[arg(long)]
        dir: Option<String>,
        /// With --dir: user owning the files (default: who ran sudo).
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
        /// answers on PKTAP, none otherwise.
        #[arg(long)]
        bpf: Option<String>,
        #[arg(long, default_value_t = 16384)]
        snaplen: i32,
        /// Also save the captured packets (pcap, PKTAP link type on macOS).
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
    },
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { interface, output, dir, owner, keep_days, no_names, bpf, snaplen, save_pcap, verbose, quiet, flush_every, duration } => {
            run(RunArgs {
                interface,
                output,
                dir,
                owner,
                keep_days,
                names: !no_names,
                bpf,
                snaplen,
                save_pcap,
                opts: Options { names: !no_names, verbose, console: !quiet },
                flush_every,
                duration,
            })
        }
        Cmd::Read { file, output, no_names, verbose } => read(&file, output, Options { names: !no_names, verbose, console: true }),
        Cmd::Summary { files, names, format, key } => summary::run(&files, &summary::Opts { names, format, key }),
        Cmd::Whois { pids } => whois(&pids),
    }
}

fn session_id() -> String {
    let mut b = [0u8; 8];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut b);
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
        "ts": pipeline::ts_string(chrono::Utc::now().timestamp_micros() as f64 / 1e6),
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

fn ts_of(h: &pcap::PacketHeader) -> f64 {
    h.ts.tv_sec as f64 + h.ts.tv_usec as f64 / 1e6
}

/// Opens the capture device; returns it with its link type and the kernel
/// filter actually in use.
fn open_capture(device: &str, snaplen: i32, bpf: &Option<String>, names: bool) -> Result<(pcap::Capture<pcap::Active>, i32, String)> {
    let inactive = pcap::Capture::from_device(device)?.snaplen(snaplen).buffer_size(16 << 20).promisc(false).timeout(100);
    #[cfg(target_os = "macos")]
    if device.starts_with("pktap") && !platform::want_pktap(inactive.as_ptr().cast()) {
        eprintln!("warning: this libpcap has no pcap_set_want_pktap: no per-packet process metadata");
    }
    let mut cap = inactive.open().with_context(|| format!("opening {}", device))?;
    let dlt = cap.get_datalink().0;
    let filter = match bpf {
        Some(f) => f.clone(),
        None if net::is_pktap(dlt) => net::pktap_filter(names),
        None => String::new(),
    };
    let mut used = filter.clone();
    if !filter.is_empty() {
        if let Err(e) = cap.filter(&filter, true) {
            eprintln!("warning: kernel filter rejected ({}); filtering in user space only", e);
            used = String::new();
        }
    }
    Ok((cap, dlt, used))
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

fn run(a: RunArgs) -> Result<()> {
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
    let (cap, dlt, filter_used) = open_capture(&device, snaplen, &bpf, names)?;
    if !net::is_pktap(dlt) {
        // Always shown: on macOS this means the attribution is much weaker.
        eprintln!("warning: {} has no per-packet process metadata (link type {}); processes are looked up per ClientHello", device, dlt);
    }
    let mut logdir = match &dir {
        Some(d) => Some(logdir::LogDir::new(std::path::Path::new(d), logdir::resolve_owner(owner.as_deref())?, keep_days)?),
        None => None,
    };
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

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || {
            if stop.swap(true, Ordering::SeqCst) {
                std::process::exit(130);
            }
        })?;
    }
    let paused = Arc::new(AtomicBool::new(logdir.as_ref().is_some_and(|l| l.paused())));
    let pcap_stats: Arc<Mutex<Option<pcap::Stat>>> = Arc::new(Mutex::new(None));
    let (tx, rx) = sync_channel::<(f64, Vec<u8>)>(65_536);
    let cap_thread = {
        let stop = stop.clone();
        let paused = paused.clone();
        let stats = pcap_stats.clone();
        let device = device.clone();
        std::thread::Builder::new().name("capture".into()).spawn(move || -> Result<()> {
            let mut cap = Some(cap);
            let mut save = match (&save_pcap, cap.as_mut()) {
                (Some(path), Some(c)) => Some(c.savefile(path)?),
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
                    None => match open_capture(&device, snaplen, &bpf, names) {
                        Ok((c, _, _)) => cap.insert(c),
                        Err(e) => {
                            eprintln!("reopening {}: {}", device, e);
                            std::thread::sleep(Duration::from_secs(5));
                            continue;
                        }
                    },
                };
                match c.next_packet() {
                    Ok(pkt) => {
                        if let Some(s) = save.as_mut() {
                            s.write(&pkt);
                        }
                        if tx.send((ts_of(pkt.header), pkt.data.to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => return Err(e.into()),
                }
                if last.elapsed() > Duration::from_secs(2) {
                    last = Instant::now();
                    if let Ok(s) = c.stats() {
                        *stats.lock().unwrap() = Some(s);
                    }
                }
            }
            if let Some(Ok(s)) = cap.as_mut().map(|c| c.stats()) {
                *stats.lock().unwrap() = Some(s);
            }
            if let Some(s) = save.as_mut() {
                let _ = s.flush();
            }
            Ok(())
        })?
    };

    let started = Instant::now();
    let started_ts = pipeline::ts_string(chrono::Utc::now().timestamp_micros() as f64 / 1e6);
    let mut warned = false;
    let mut last_flush = Instant::now();
    let mut last_report = Instant::now();
    let mut last_status = Instant::now() - Duration::from_secs(60);
    let capture_stats = |s: &Arc<Mutex<Option<pcap::Stat>>>| {
        let g = s.lock().unwrap();
        match &*g {
            Some(st) => json!({"received": st.received, "dropped": st.dropped, "if_dropped": st.if_dropped}),
            None => json!(null),
        }
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok((ts, data)) => p.packet(ts, dlt, &data),
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
                    let rec = p.stats_record(now, capture_stats(&pcap_stats));
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
                        "updated": pipeline::ts_string(chrono::Utc::now().timestamp_micros() as f64 / 1e6),
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
                    if filter_used.is_empty() { "" } else { "; if the network is in use, retry with --bpf \"\" (no kernel filter)" }
                );
            }
        }
        if last_report.elapsed() >= Duration::from_secs(flush_every) {
            last_report = Instant::now();
            p.flush_domains();
            let now = chrono::Utc::now().timestamp_micros() as f64 / 1e6;
            let rec = p.stats_record(now, capture_stats(&pcap_stats));
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
            while let Ok((ts, data)) = rx.recv_timeout(Duration::from_millis(300)) {
                p.packet(ts, dlt, &data);
            }
            break;
        }
    }
    drop(rx);
    match cap_thread.join() {
        Ok(Err(e)) => eprintln!("capture error: {}", e),
        Err(_) => eprintln!("capture thread panicked"),
        _ => {}
    }
    p.flush_domains();
    let now = chrono::Utc::now().timestamp_micros() as f64 / 1e6;
    let rec = p.stats_record(now, capture_stats(&pcap_stats));
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
    Ok(())
}

fn read(file: &str, output: Option<String>, opts: Options) -> Result<()> {
    let mut cap = pcap::Capture::from_file(file).with_context(|| file.to_string())?;
    let dlt = cap.get_datalink().0;
    let out: Box<dyn Write + Send> = match &output {
        Some(p) => create_output(p)?,
        None => Box::new(BufWriter::new(std::io::stdout())),
    };
    let names = opts.names;
    let mut p = Pipeline::new(Resolver::new(false), out, Options { console: output.is_some(), ..opts });
    let db = p.resolver.db.version.clone();
    p.write(&start_record(file, dlt, "", false, names, &db));
    let mut last_ts = 0.0;
    loop {
        match cap.next_packet() {
            Ok(pkt) => {
                last_ts = ts_of(pkt.header);
                p.packet(last_ts, dlt, pkt.data);
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => return Err(e.into()),
        }
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
