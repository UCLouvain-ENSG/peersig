//! Names each process contacts.
//!
//! Sources (`via`):
//! - `sni`: the ClientHello's server name;
//! - `dns`: a connection opened to an address a DNS answer gave for that
//!   name (the name asked, not the CDN alias it resolves through). On macOS
//!   mDNSResponder sends the queries, so the answers, matched to the
//!   connection that follows, are what tie a name to an app;
//! - `dns-query`: a query the process sent itself (Chromium's and Go's own
//!   resolvers, dig);
//! - `http`: the Host header of a plain HTTP request (or a CONNECT target).
//!
//! Encrypted DNS (DoH, DoT, iCloud Private Relay) leaves no answers to read:
//! those names only come from SNI.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use serde::Serialize;

use crate::attrib::Attribution;
use crate::dns;

pub struct DnsCache {
    map: HashMap<IpAddr, (String, f64)>,
    pub responses: u64,
}

/// Answers older than this are not used to name a connection.
const DNS_MAX_AGE: f64 = 6.0 * 3600.0;

impl DnsCache {
    pub fn new() -> Self {
        DnsCache { map: HashMap::new(), responses: 0 }
    }

    pub fn learn(&mut self, m: &dns::Message, ts: f64) {
        self.responses += 1;
        let Some((qname, _)) = m.questions.first() else { return };
        // Every address in the answer is credited to the name asked: the
        // CNAME chain only leads there.
        for (_, ip) in &m.addrs {
            self.map.insert(*ip, (qname.clone(), ts));
        }
        if self.map.len() > 200_000 {
            self.map.retain(|_, (_, t)| ts - *t < 3600.0);
        }
    }

    pub fn name(&self, ip: &IpAddr, now: f64) -> Option<&str> {
        self.map.get(ip).filter(|(_, t)| now - *t < DNS_MAX_AGE).map(|(n, _)| n.as_str())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub proc_id: String,
    pub proc: String,
    pub app: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_version: Option<String>,
    pub app_kind: String,
    pub domain: String,
    pub via: BTreeSet<&'static str>,
    /// Connections (or requests, or queries) seen; cumulative.
    pub count: u64,
    pub first: String,
    pub last: String,
    pub ports: BTreeSet<String>,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub ja4: BTreeSet<String>,
}

const MAX_SET: usize = 16;

#[derive(Default)]
pub struct DomainTable {
    entries: HashMap<(String, String), Entry>,
    dirty: HashSet<(String, String)>,
}

impl DomainTable {
    pub fn add(&mut self, ts: &str, att: &Attribution, domain: &str, via: &'static str, port: String, ja4: Option<&str>) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return;
        }
        let key = (att.credited_id(), domain.clone());
        let e = self.entries.entry(key.clone()).or_insert_with(|| {
            let credited = att.eproc.as_ref().or(att.proc.as_ref());
            Entry {
                kind: "domain",
                proc_id: key.0.clone(),
                proc: credited.map(|p| p.display()).unwrap_or_else(|| "unknown".into()),
                app: att.app.name.clone(),
                app_id: att.app.id.clone(),
                app_version: att.app.version.clone(),
                app_kind: att.app.kind.clone(),
                domain,
                via: BTreeSet::new(),
                count: 0,
                first: ts.to_string(),
                last: ts.to_string(),
                ports: BTreeSet::new(),
                ja4: BTreeSet::new(),
            }
        });
        e.via.insert(via);
        e.count += 1;
        e.last = ts.to_string();
        if e.ports.len() < MAX_SET {
            e.ports.insert(port);
        }
        if let Some(j) = ja4 {
            if e.ja4.len() < MAX_SET {
                e.ja4.insert(j.to_string());
            }
        }
        self.dirty.insert(key);
    }

    /// Entries changed since the last call (with cumulative counts).
    pub fn take_dirty(&mut self) -> Vec<Entry> {
        let mut out: Vec<Entry> = self.dirty.drain().filter_map(|k| self.entries.get(&k).cloned()).collect();
        out.sort_by(|a, b| (&a.proc_id, &a.domain).cmp(&(&b.proc_id, &b.domain)));
        out
    }

    /// Forgets everything: a new log file starts from zero.
    pub fn reset(&mut self) {
        self.entries.clear();
        self.dirty.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Host of a plain HTTP request starting in this segment.
pub fn http_host(p: &[u8]) -> Option<String> {
    const METHODS: &[&[u8]] =
        &[b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT "];
    let m = METHODS.iter().find(|m| p.starts_with(m))?;
    let head = &p[..p.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    let host = if *m == b"CONNECT " {
        text.lines().next()?.split_whitespace().nth(1)?.to_string()
    } else {
        text.lines()
            .skip(1)
            .take_while(|l| !l.is_empty())
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case("host").then(|| v.trim().to_string())
            })?
    };
    // Strip the port; keep IPv6 literals whole.
    let host = if host.starts_with('[') {
        host.split(']').next().map(|h| format!("{}]", h)).unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or("").to_string()
    };
    (!host.is_empty() && host.len() < 256).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(http_host(b"GET /x HTTP/1.1\r\nUser-Agent: a\r\nhost: Example.com:8080\r\n\r\n").as_deref(), Some("Example.com"));
        assert_eq!(http_host(b"CONNECT api.github.com:443 HTTP/1.1\r\n\r\n").as_deref(), Some("api.github.com"));
        assert_eq!(http_host(b"\x16\x03\x01"), None);
    }
}
