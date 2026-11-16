//! Finds ClientHellos in the client's packets: TCP segments put back in
//! sequence order, QUIC CRYPTO frames by stream offset, DTLS handshake
//! fragments by fragment offset. Only flows that started a ClientHello hold
//! state, and only until it is complete or `TIMEOUT` passes.

use std::collections::{BTreeMap, HashMap};

use crate::fingerprint::Transport;
use crate::net::{FlowKey, PktapMeta, L4, TCP, UDP};
use crate::quic;
use crate::tls::{self, ClientHello, StreamHello};

const TIMEOUT: f64 = 30.0;
/// Larger than any ClientHello seen in practice (~2 KB with ML-KEM, a few KB
/// with big PSK tickets); TLS caps a handshake record at 16 KB.
const MAX_HELLO: usize = 64 * 1024;
/// QUIC and DTLS ClientHellos already reported, kept to ignore their
/// retransmissions.
const DONE_TTL: f64 = 120.0;

pub struct Hello {
    pub ts: f64,
    pub key: FlowKey,
    pub transport: Transport,
    pub ch: ClientHello,
    /// PKTAP metadata of the first packet of the ClientHello.
    pub meta: Option<PktapMeta>,
    pub quic_version: Option<u32>,
    pub packets: usize,
}

#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub packets: u64,
    pub decoded: u64,
    pub inbound_skipped: u64,
    pub tcp_hellos: u64,
    pub quic_hellos: u64,
    pub dtls_hellos: u64,
    pub tcp_incomplete: u64,
    pub quic_undecryptable: u64,
    pub quic_unsupported_version: u64,
    pub malformed: u64,
}

struct Pending {
    first_ts: f64,
    meta: Option<PktapMeta>,
    /// Stream offset -> bytes (TCP: relative to the first segment's seq).
    segs: BTreeMap<u64, Vec<u8>>,
    packets: usize,
    // TCP
    base_seq: u32,
    hello_started: bool,
    // QUIC
    quic_version: u32,
    keys: Option<quic::Keys>,
    dcid: Vec<u8>,
}

impl Pending {
    fn new(ts: f64, meta: Option<PktapMeta>) -> Self {
        Pending {
            first_ts: ts,
            meta,
            segs: BTreeMap::new(),
            packets: 0,
            base_seq: 0,
            hello_started: false,
            quic_version: 0,
            keys: None,
            dcid: Vec::new(),
        }
    }

    fn add(&mut self, off: u64, data: &[u8]) {
        if data.is_empty() || off as usize >= MAX_HELLO {
            return;
        }
        let e = self.segs.entry(off).or_default();
        if data.len() > e.len() {
            *e = data.to_vec();
        }
    }

    /// Bytes contiguous from offset 0.
    fn prefix(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for (&off, data) in &self.segs {
            let off = off as usize;
            if off > out.len() {
                break;
            }
            let skip = out.len() - off;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
            if out.len() >= MAX_HELLO {
                break;
            }
        }
        out
    }
}

pub struct Tracker {
    pending: HashMap<FlowKey, Pending>,
    /// Reported ClientHellos, to skip retransmissions: (flow, empty) for
    /// QUIC, (flow, JA4) for DTLS -> time reported.
    done: HashMap<(FlowKey, Vec<u8>), f64>,
    last_sweep: f64,
    pub stats: Stats,
    /// Accept packets the PKTAP header marks as received (default: skip).
    pub keep_inbound: bool,
}

impl Tracker {
    pub fn new() -> Self {
        Tracker {
            pending: HashMap::new(),
            done: HashMap::new(),
            last_sweep: 0.0,
            stats: Stats::default(),
            keep_inbound: false,
        }
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn packet(&mut self, ts: f64, meta: Option<PktapMeta>, l4: &L4, out: &mut Vec<Hello>) {
        self.stats.decoded += 1;
        if let Some(m) = &meta {
            if m.flags & crate::net::PTH_FLAG_DIR_IN != 0 && !self.keep_inbound {
                self.stats.inbound_skipped += 1;
                return;
            }
        }
        if ts - self.last_sweep > 5.0 {
            self.sweep(ts);
        }
        match l4.key.proto {
            TCP => self.tcp(ts, meta, l4, out),
            UDP => {
                if l4.payload.first().map_or(false, |b| b & 0x80 != 0) {
                    self.quic(ts, meta, l4, out);
                } else if l4.payload.len() > 25
                    && l4.payload[0] == 0x16
                    && (l4.payload[1] == 0xfe || l4.payload[1..3] == [0x01, 0x00])
                {
                    self.dtls(ts, meta, l4, out);
                }
            }
            _ => {}
        }
    }

    fn sweep(&mut self, now: f64) {
        self.last_sweep = now;
        // A ClientHello that never completed (lost segment, snaplen).
        let mut expired = 0;
        self.pending.retain(|k, p| {
            let keep = now - p.first_ts < TIMEOUT;
            if !keep && k.proto == TCP && p.hello_started {
                expired += 1;
            }
            keep
        });
        self.stats.tcp_incomplete += expired;
        self.done.retain(|_, t| now - *t < DONE_TTL);
    }

    fn tcp(&mut self, ts: f64, meta: Option<PktapMeta>, l4: &L4, out: &mut Vec<Hello>) {
        let key = l4.key;
        let p = l4.payload;
        // The client's SYN fixes offset 0, so a ClientHello whose second
        // segment arrives first is still put together.
        if l4.tcp_flags & 0x12 == 0x02 {
            let mut st = Pending::new(ts, meta);
            st.base_seq = l4.tcp_seq.wrapping_add(1);
            self.pending.insert(key, st);
            return;
        }
        if p.is_empty() {
            return;
        }
        if !self.pending.contains_key(&key) {
            if !tls::looks_like_tls_hello(p) {
                return;
            }
            let mut st = Pending::new(ts, meta.clone());
            st.base_seq = l4.tcp_seq;
            self.pending.insert(key, st);
        }
        let st = self.pending.get_mut(&key).unwrap();
        if l4.tcp_seq.wrapping_sub(st.base_seq) as usize >= MAX_HELLO {
            // Before offset 0 (SYN missed) or far after it: restart on a
            // ClientHello start, ignore anything else.
            if !tls::looks_like_tls_hello(p) {
                return;
            }
            *st = Pending::new(ts, meta.clone());
            st.base_seq = l4.tcp_seq;
        }
        if st.packets == 0 {
            // Metadata of the first data packet (the SYN may predate a
            // socket handed to another process).
            if meta.is_some() {
                st.meta = meta;
            }
        }
        let off = l4.tcp_seq.wrapping_sub(st.base_seq) as u64;
        st.add(off, p);
        st.packets += 1;
        let prefix = st.prefix();
        if prefix.len() < 6 {
            return; // nothing (or too little) from offset 0 yet
        }
        if !tls::looks_like_tls_hello(&prefix) {
            self.pending.remove(&key); // not TLS
            return;
        }
        st.hello_started = true;
        match tls::client_hello_from_stream(&prefix) {
            StreamHello::NeedMore => {}
            StreamHello::Done(ch) => {
                let st = self.pending.remove(&key).unwrap();
                self.stats.tcp_hellos += 1;
                out.push(Hello {
                    ts: st.first_ts,
                    key,
                    transport: Transport::Tcp,
                    ch,
                    meta: st.meta,
                    quic_version: None,
                    packets: st.packets,
                });
            }
            StreamHello::NotTls | StreamHello::Malformed => {
                self.stats.malformed += 1;
                self.pending.remove(&key);
            }
        }
    }

    fn quic(&mut self, ts: f64, meta: Option<PktapMeta>, l4: &L4, out: &mut Vec<Hello>) {
        let pkts = match quic::split(l4.payload) {
            quic::Datagram::NotLong => return,
            quic::Datagram::Unsupported(v) => {
                // gQUIC ("Q0.."), later drafts, version-negotiation GREASE;
                // not RTP or other UDP that merely has the high bit set.
                if v >> 24 == 0x51 || v >> 8 == 0xff_0000 || v & 0x0f0f_0f0f == 0x0a0a_0a0a {
                    self.stats.quic_unsupported_version += 1;
                }
                return;
            }
            quic::Datagram::Packets(p) => p,
        };
        let key = l4.key;
        // One report per connection: later client Initials (ACKs, the
        // ClientHello again after a Retry) are skipped.
        if self.done.contains_key(&(key, Vec::new())) {
            return;
        }
        for lh in pkts.iter().filter(|lh| lh.initial) {
            // Keys of the ClientHello in progress first (the client keeps
            // them after switching to the server's connection id), then the
            // packet's own DCID (first packet, or a new one after a Retry).
            let mut plain = None;
            if let Some(st) = self.pending.get(&key) {
                if st.quic_version == lh.version {
                    if let Some(k) = &st.keys {
                        plain = quic::decrypt(lh, k);
                    }
                }
            }
            if plain.is_none() {
                let Some(k) = quic::client_keys(lh.dcid, lh.version) else { continue };
                let Some(pl) = quic::decrypt(lh, &k) else {
                    self.stats.quic_undecryptable += 1;
                    continue;
                };
                let mut st = Pending::new(ts, meta.clone());
                st.quic_version = lh.version;
                st.keys = Some(k);
                st.dcid = lh.dcid.to_vec();
                self.pending.insert(key, st);
                plain = Some(pl);
            }
            let plain = plain.unwrap();
            let st = self.pending.get_mut(&key).unwrap();
            st.packets += 1;
            for (off, data) in quic::crypto_frames(&plain) {
                st.add(off, &data);
            }
            let stream = st.prefix();
            if stream.len() < 4 {
                continue;
            }
            if stream[0] != 1 {
                // Not a ClientHello (a server's Initial when inbound is kept).
                self.stats.malformed += 1;
                self.pending.remove(&key);
                return;
            }
            let need = 4 + (((stream[1] as usize) << 16) | ((stream[2] as usize) << 8) | stream[3] as usize);
            if stream.len() < need {
                continue;
            }
            let st = self.pending.remove(&key).unwrap();
            self.done.insert((key, Vec::new()), ts);
            match tls::parse_client_hello(&stream[4..need], false) {
                Some(ch) => {
                    self.stats.quic_hellos += 1;
                    out.push(Hello {
                        ts: st.first_ts,
                        key,
                        transport: Transport::Quic,
                        ch,
                        meta: st.meta,
                        quic_version: Some(st.quic_version),
                        packets: st.packets,
                    });
                }
                None => self.stats.malformed += 1,
            }
            return;
        }
    }

    fn dtls(&mut self, ts: f64, meta: Option<PktapMeta>, l4: &L4, out: &mut Vec<Hello>) {
        let key = l4.key;
        let mut r = tls::Reader::new(l4.payload);
        // DTLSPlaintext: type, version, epoch, sequence (48 bits), length
        while r.remaining() >= 13 {
            let (Some(ct), Some(ver)) = (r.u8(), r.u16()) else { return };
            let Some(epoch) = r.u16() else { return };
            if r.bytes(6).is_none() {
                return;
            }
            let Some(len) = r.u16() else { return };
            let Some(frag) = r.bytes(len as usize) else { return };
            if ct != 22 || epoch != 0 || ver >> 8 != 0xfe && ver != 0x0100 {
                continue;
            }
            // Handshake: type, length, message_seq, fragment_offset, fragment_length
            let mut h = tls::Reader::new(frag);
            let (Some(ht), Some(total), Some(_seq), Some(foff), Some(flen)) = (h.u8(), h.u24(), h.u16(), h.u24(), h.u24())
            else {
                return;
            };
            if ht != 1 {
                continue;
            }
            let Some(body) = h.bytes(flen as usize) else { return };
            let st = self.pending.entry(key).or_insert_with(|| Pending::new(ts, meta.clone()));
            st.packets += 1;
            st.add(foff as u64, body);
            let stream = st.prefix();
            if stream.len() < total as usize {
                continue;
            }
            let st = self.pending.remove(&key).unwrap();
            let Some(ch) = tls::parse_client_hello(&stream[..total as usize], true) else {
                self.stats.malformed += 1;
                return;
            };
            // HelloVerifyRequest makes the client send it again with a cookie.
            let fp = crate::fingerprint::compute(&ch, Transport::Dtls).ja4;
            let dkey = (key, fp.into_bytes());
            if self.done.contains_key(&dkey) {
                return;
            }
            self.done.insert(dkey, ts);
            self.stats.dtls_hellos += 1;
            out.push(Hello {
                ts: st.first_ts,
                key,
                transport: Transport::Dtls,
                ch,
                meta: st.meta,
                quic_version: None,
                packets: st.packets,
            });
            return;
        }
    }
}
