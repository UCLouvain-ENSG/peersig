//! Packet -> records. Shared by live capture and capture files.

use std::collections::{HashMap, HashSet};
use std::io::Write;

use serde_json::{json, Value};

use crate::attrib::{Attribution, Resolver, Written};
use crate::dns;
use crate::domains::{self, DnsCache, DomainTable};
use crate::fingerprint;
use crate::flow::{Hello, Tracker};
use crate::net::{self, FlowKey, TCP, UDP};
use crate::quic;

pub struct Options {
    /// Record server names (SNI, DNS, HTTP Host) and the per-process tables.
    pub names: bool,
    /// Print every ClientHello, not only new (JA4, app) pairs.
    pub verbose: bool,
    /// Print to stderr at all.
    pub console: bool,
}

#[derive(Default, serde::Serialize)]
pub struct Counters {
    pub connections: u64,
    pub connections_named: u64,
    pub dns_queries: u64,
    pub http_requests: u64,
    pub undecoded: u64,
}

pub struct Pipeline {
    pub tracker: Tracker,
    pub resolver: Resolver,
    dns: DnsCache,
    domains: DomainTable,
    udp_seen: HashMap<FlowKey, f64>,
    written: Written,
    pairs: HashSet<(String, String)>,
    pub counters: Counters,
    out: Box<dyn Write + Send>,
    opts: Options,
    hellos: Vec<Hello>,
    /// Time of the last ClientHello, for the status file.
    pub last_hello: Option<f64>,
}

pub fn ts_string(ts: f64) -> String {
    let secs = ts.floor() as i64;
    let nanos = ((ts - secs as f64) * 1e9).round().clamp(0.0, 999_999_999.0) as u32;
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        .unwrap_or_default()
}

/// Now, as records write it.
pub fn now_ts() -> String {
    ts_string(chrono::Utc::now().timestamp_micros() as f64 / 1e6)
}

fn session_id() -> String {
    let mut b = [0u8; 8];
    match std::fs::File::open("/dev/urandom") {
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

/// The first record of every log file. `os` says what items carry
/// (`peersig_proto::item::os_label`).
pub fn start_record(device: &str, dlt: i32, filter: &str, live: bool, names: bool, db: &str) -> Value {
    json!({
        "type": "start",
        "ts": now_ts(),
        "tool": format!("peersig-probe {}", env!("CARGO_PKG_VERSION")),
        "apps_db": db,
        "session": session_id(),
        // The capturing machine's OS; unknown for a capture file.
        "os": if live { serde_json::to_value(crate::platform::os_info()).unwrap_or_default() } else { Value::Null },
        "device": device,
        // Link type: 149 or 258 is PKTAP, with a process on every packet.
        "dlt": dlt,
        "filter": filter,
        "live": live,
        "names": names,
    })
}

fn endpoint(ip: &std::net::IpAddr, port: u16) -> String {
    match ip {
        std::net::IpAddr::V6(v6) => format!("[{}]:{}", v6, port),
        _ => format!("{}:{}", ip, port),
    }
}

fn port_label(k: &FlowKey) -> String {
    format!("{}/{}", if k.proto == TCP { "tcp" } else { "udp" }, k.dport)
}

impl Pipeline {
    pub fn new(resolver: Resolver, out: Box<dyn Write + Send>, opts: Options) -> Self {
        Pipeline {
            tracker: Tracker::new(),
            resolver,
            dns: DnsCache::new(),
            domains: DomainTable::default(),
            udp_seen: HashMap::new(),
            written: Written::default(),
            pairs: HashSet::new(),
            counters: Counters::default(),
            out,
            opts,
            hellos: Vec::new(),
            last_hello: None,
        }
    }

    pub fn write(&mut self, v: &Value) {
        let _ = serde_json::to_writer(&mut self.out, v);
        let _ = self.out.write_all(b"\n");
    }

    pub fn flush(&mut self) {
        let _ = self.out.flush();
    }

    /// Switches to a new log file (daily rotation). The per-process name
    /// tables and process records start over, so each file stands alone.
    pub fn set_output(&mut self, out: Box<dyn Write + Send>) {
        let _ = self.out.flush();
        self.out = out;
        self.domains.reset();
        self.written = Written::default();
    }

    pub fn packet(&mut self, ts: f64, dlt: i32, data: &[u8]) {
        self.tracker.stats.packets += 1;
        let Some((meta, l4)) = net::decode(dlt, data) else {
            self.counters.undecoded += 1;
            return;
        };
        let k = l4.key;
        // DNS answers, whatever their direction: they name later connections.
        if k.proto == UDP && k.sport == 53 {
            if self.opts.names {
                if let Some(m) = dns::parse(l4.payload).filter(|m| m.response && m.rcode == 0) {
                    self.dns.learn(&m, ts);
                }
            }
            return;
        }
        let inbound = meta.as_ref().map_or(false, |m| m.flags & net::PTH_FLAG_DIR_IN != 0);
        if self.opts.names && !inbound {
            self.names(ts, meta.as_ref(), &l4);
        }
        let mut hellos = std::mem::take(&mut self.hellos);
        self.tracker.packet(ts, meta, &l4, &mut hellos);
        for h in hellos.drain(..) {
            self.hello(h);
        }
        self.hellos = hellos;
    }

    /// Connections, DNS queries and HTTP requests, for the per-process names.
    /// Only with PKTAP metadata: looking up a socket's owner for every
    /// connection would cost too much (ClientHellos still get one).
    fn names(&mut self, ts: f64, meta: Option<&net::PktapMeta>, l4: &net::L4) {
        let Some(meta) = meta else { return };
        let k = &l4.key;
        let new_conn = match k.proto {
            TCP => l4.tcp_flags & 0x12 == 0x02,
            UDP => {
                let new = match self.udp_seen.get(k) {
                    Some(t) => ts - t > 120.0,
                    None => true,
                };
                self.udp_seen.insert(*k, ts);
                if self.udp_seen.len() > 100_000 {
                    self.udp_seen.retain(|_, t| ts - *t < 120.0);
                }
                new
            }
            _ => false,
        };
        if new_conn && k.dport != 53 {
            self.counters.connections += 1;
            if let Some(name) = self.dns.name(&k.dst, ts).map(str::to_string) {
                self.counters.connections_named += 1;
                let att = self.resolver.attribute(Some(meta), k);
                self.note_processes(&att);
                self.domains.add(&ts_string(ts), &att, &name, "dns", port_label(k), None);
            }
        }
        if k.proto == UDP && k.dport == 53 {
            let resolver_proc = self.resolver.db.resolvers.iter().any(|r| *r == meta.comm);
            if !resolver_proc || meta.delegated() {
                if let Some(m) = dns::parse(l4.payload).filter(|m| !m.response) {
                    self.counters.dns_queries += 1;
                    let att = self.resolver.attribute(Some(meta), k);
                    self.note_processes(&att);
                    for (q, t) in &m.questions {
                        if matches!(t, 1 | 28 | 65 | 64 | 5) {
                            self.domains.add(&ts_string(ts), &att, q, "dns-query", format!("dns/{}", dns::qtype_name(*t)), None);
                        }
                    }
                }
            }
        }
        if k.proto == TCP && !l4.payload.is_empty() {
            if let Some(host) = domains::http_host(l4.payload) {
                self.counters.http_requests += 1;
                let att = self.resolver.attribute(Some(meta), k);
                self.note_processes(&att);
                self.domains.add(&ts_string(ts), &att, &host, "http", port_label(k), None);
            }
        }
    }

    /// Writes the full record of each process the first time it appears.
    fn note_processes(&mut self, att: &Attribution) {
        let new: Vec<Value> = att
            .processes()
            .filter(|p| self.written.first_time(&p.id))
            .map(|p| {
                let mut v = serde_json::to_value(&**p).unwrap_or(Value::Null);
                if let Value::Object(o) = &mut v {
                    o.insert("type".into(), "process".into());
                }
                v
            })
            .collect();
        for v in new {
            self.write(&v);
        }
    }

    fn hello(&mut self, h: Hello) {
        let att = self.resolver.attribute(h.meta.as_ref(), &h.key);
        let att = self.resolver.bits_delegate(att, h.ch.sni.as_deref(), h.ts);
        self.note_processes(&att);
        let fp = fingerprint::compute(&h.ch, h.transport);
        let ts = ts_string(h.ts);
        self.last_hello = Some(h.ts);
        let alpn: Vec<String> = h.ch.alpn.iter().map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        let sni = if self.opts.names { h.ch.sni.clone() } else { None };
        let mut rec = json!({
            "type": "hello",
            "ts": ts,
            "transport": h.transport.name(),
            "src": endpoint(&h.key.src, h.key.sport),
            "dst": endpoint(&h.key.dst, h.key.dport),
            "sni": sni,
            "alpn": alpn,
            "version": format!("{:04x}", fingerprint::offered_version(&h.ch)),
            "ech": h.ch.has_ext(crate::tls::EXT_ECH),
            "ja4": fp.ja4,
            "ja4_r": fp.ja4_r,
            "ja4_o": fp.ja4_o,
            "ja4_ro": fp.ja4_ro,
            "ja3": fp.ja3,
            "ja3_r": fp.ja3_r,
            "packets": h.packets,
            "attribution": att.source,
            "app": att.app,
        });
        let o = rec.as_object_mut().unwrap();
        if let Some(m) = &h.meta {
            o.insert("iface".into(), m.ifname.clone().into());
            o.insert("svc".into(), m.svc_name().into());
        }
        if let Some(v) = h.quic_version {
            o.insert("quic_version".into(), quic::version_name(v).into());
        }
        if let Some(ua) = &h.ch.quic_user_agent {
            o.insert("quic_user_agent".into(), ua.clone().into());
        }
        if let Some(p) = &att.proc {
            o.insert("proc_id".into(), p.id.clone().into());
            o.insert("proc".into(), p.display().into());
            if let Some(hp) = &p.helper {
                o.insert("helper".into(), hp.clone().into());
            }
            if !p.stacks.is_empty() {
                o.insert("stacks".into(), p.stacks.clone().into());
            }
        }
        if let Some(p) = &att.eproc {
            o.insert("eproc_id".into(), p.id.clone().into());
            o.insert("eproc".into(), p.display().into());
        }
        if let Some(p) = &att.resp {
            o.insert("resp_id".into(), p.id.clone().into());
            o.insert("resp".into(), p.display().into());
        }
        self.write(&rec);
        if let (true, Some(s)) = (self.opts.names, &h.ch.sni) {
            self.domains.add(&ts, &att, s, "sni", port_label(&h.key), Some(&fp.ja4));
        }
        if self.opts.console {
            let label = att.app.label();
            if self.opts.verbose || self.pairs.insert((fp.ja4.clone(), label.clone())) {
                let mut line = format!("{}  {:<4}  {}  {}", &ts[11..19], h.transport.name(), fp.ja4, label);
                if let Some(p) = &att.proc {
                    if p.display() != att.app.name {
                        line.push_str(&format!("  [{}]", p.display()));
                    }
                }
                if let Some(s) = &h.ch.sni {
                    if self.opts.names {
                        line.push_str(&format!("  -> {}", s));
                    }
                }
                eprintln!("{}", line);
            }
        }
    }

    /// Writes the per-process name entries changed since the last call.
    pub fn flush_domains(&mut self) {
        for e in self.domains.take_dirty() {
            let v = serde_json::to_value(&e).unwrap_or(Value::Null);
            self.write(&v);
        }
    }

    pub fn stats_record(&self, ts: f64, extra: Value) -> Value {
        json!({
            "type": "stats",
            "ts": ts_string(ts),
            "flows": self.tracker.stats,
            "names": self.counters,
            "dns_responses": self.dns.responses,
            "domain_entries": self.domains.len(),
            "process_lookups": self.resolver.lookups,
            "not_local": self.resolver.not_local,
            "pending": self.tracker.pending_len(),
            "capture": extra,
        })
    }
}
