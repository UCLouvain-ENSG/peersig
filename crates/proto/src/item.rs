//! The only things a ballot can carry, and how the app derives them from the
//! probe's local logs.
//!
//! A `hello` item is "an application of this name and version, on this OS,
//! sent a ClientHello with this JA4". A `domain` item (only when the
//! participant opts in, never for browsers) is "this application sent a
//! ClientHello with this JA4 to this server name (SNI)": what a network
//! observer sees together. A `presence` item says "one participant
//! reported this epoch".
//!
//! Never part of an item: addresses, ports, times, process ids, paths,
//! command lines, host or user names. Items carry presence, not counts.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::epoch::EpochSpec;

pub const MAX_FIELD: usize = 128;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct AppRef {
    pub name: String,
    /// Bundle id (macOS) or package name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Code-signing team (macOS): the vendor, e.g. UBF8T346G9 for Microsoft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// browser, app, system or cli.
    pub kind: String,
    /// chromium <v>, electron <v>, gecko <v>, webkit <build>...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Hello,
    Domain,
    Presence,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::Hello => "hello",
            Class::Domain => "domain",
            Class::Presence => "presence",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields, from = "Received")]
pub enum Item {
    Hello {
        /// "macos 27", "windows 11": the system and its major version only;
        /// on Linux the distribution's ("linux ubuntu 24", `os_label`).
        os: String,
        /// tcp, quic or dtls.
        transport: String,
        ja4: String,
        app: AppRef,
    },
    Domain {
        os: String,
        app: AppRef,
        /// The server name (SNI): lower case, random-looking labels
        /// replaced by `*`.
        domain: String,
        /// The JA4 of the ClientHello that carried it.
        ja4: String,
    },
    Presence {
        shares_domains: bool,
    },
}

/// An item as it arrives, from any app version: as `Item`, except that a
/// `hello` from PeerSig 0.1.9 or older also carries a second, non-standard
/// JA4, which is dropped. Their ballots count under the same key as
/// everyone else's, and counters stored before keep a key `Item` reads.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Received {
    Hello {
        os: String,
        transport: String,
        ja4: String,
        #[serde(default, rename = "ja4_legacy")]
        _dropped: Option<String>,
        app: AppRef,
    },
    Domain {
        os: String,
        app: AppRef,
        domain: String,
        ja4: String,
    },
    Presence {
        shares_domains: bool,
    },
}

impl From<Received> for Item {
    fn from(r: Received) -> Item {
        match r {
            Received::Hello { os, transport, ja4, app, .. } => Item::Hello { os, transport, ja4, app },
            Received::Domain { os, app, domain, ja4 } => Item::Domain { os, app, domain, ja4 },
            Received::Presence { shares_domains } => Item::Presence { shares_domains },
        }
    }
}

impl Item {
    pub fn class(&self) -> Class {
        match self {
            Item::Hello { .. } => Class::Hello,
            Item::Domain { .. } => Class::Domain,
            Item::Presence { .. } => Class::Presence,
        }
    }

    /// Canonical form: the server re-serializes what it parsed, so two
    /// equal items always have the same key.
    pub fn key(&self) -> String {
        serde_json::to_string(self).expect("items serialize")
    }

    pub fn from_key(key: &str) -> Option<Item> {
        serde_json::from_str(key).ok()
    }

    /// One line for people.
    pub fn label(&self) -> String {
        match self {
            Item::Hello { os, transport, ja4, app, .. } => {
                format!("{} {} via {} on {}: {}", app_label(app), app.kind, transport, os, ja4)
            }
            Item::Domain { os, app, domain, ja4 } => format!("{} on {} sent {} to {}", app_label(app), os, ja4, domain),
            Item::Presence { shares_domains } => {
                format!("one participant reported{}", if *shares_domains { ", sharing domains" } else { "" })
            }
        }
    }

    /// Checks shapes and sizes, so the server stores only well-formed items.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Item::Hello { os, transport, ja4, app } => {
                check_os(os)?;
                if !matches!(transport.as_str(), "tcp" | "quic" | "dtls") {
                    return Err(format!("transport {:?}", transport));
                }
                if !is_ja4(ja4) {
                    return Err(format!("ja4 {:?}", ja4));
                }
                check_app(app)
            }
            Item::Domain { os, app, domain, ja4 } => {
                check_os(os)?;
                check_app(app)?;
                if !is_ja4(ja4) {
                    return Err(format!("ja4 {:?}", ja4));
                }
                if app.kind == "browser" {
                    return Err("domains are never collected for browsers".into());
                }
                if normalize_domain(domain).as_deref() != Some(domain.as_str()) {
                    return Err(format!("domain {:?}", domain));
                }
                Ok(())
            }
            Item::Presence { .. } => Ok(()),
        }
    }
}

fn app_label(app: &AppRef) -> String {
    match &app.version {
        Some(v) => format!("{} {}", app.name, v),
        None => app.name.clone(),
    }
}

fn check_text(what: &str, s: &str) -> Result<(), String> {
    if s.is_empty() || s.chars().count() > MAX_FIELD || s.chars().any(char::is_control) {
        return Err(format!("{} {:?}", what, s));
    }
    Ok(())
}

fn check_os(os: &str) -> Result<(), String> {
    check_text("os", os)?;
    if os.len() > 32 || !os.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == ' ' || c == '.') {
        return Err(format!("os {:?}", os));
    }
    Ok(())
}

fn check_app(app: &AppRef) -> Result<(), String> {
    check_text("app name", &app.name)?;
    for (what, v) in [("app id", &app.id), ("version", &app.version), ("team id", &app.team_id), ("engine", &app.engine)] {
        if let Some(v) = v {
            check_text(what, v)?;
        }
    }
    if !matches!(app.kind.as_str(), "browser" | "app" | "system" | "cli") {
        return Err(format!("app kind {:?}", app.kind));
    }
    Ok(())
}

/// `t13d1516h2_8daaf6152771_e5627efa2ab1`: FoxIO's JA4 shape.
pub fn is_ja4(s: &str) -> bool {
    let p: Vec<&str> = s.split('_').collect();
    let hex12 = |x: &str| x.len() == 12 && x.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if p.len() != 3 || p[0].len() != 10 || !hex12(p[1]) || !hex12(p[2]) {
        return false;
    }
    let a = p[0].as_bytes();
    matches!(a[0], b't' | b'q' | b'd')
        && a[1..3].iter().all(u8::is_ascii_alphanumeric)
        && matches!(a[3], b'd' | b'i')
        && a[4..8].iter().all(u8::is_ascii_digit)
        && a[8..10].iter().all(u8::is_ascii_alphanumeric)
}

/// Lower-cases a name, drops the ones that are local or addresses, and
/// replaces random-looking labels (CDN shards, session hashes) by `*`. The
/// last two labels are kept. A label with a `*` in it (`p*-fmip`, from
/// `crate::merge`) stays as it is. None when the name must not be reported.
pub fn normalize_domain(name: &str) -> Option<String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if n.len() > 253 || !n.contains('.') || n.starts_with('.') {
        return None;
    }
    if !n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.' || b == b'*') {
        return None;
    }
    const PRIVATE: &[&str] = &["local", "lan", "home", "internal", "localdomain", "arpa", "corp", "intranet", "test", "invalid", "localhost"];
    let labels: Vec<&str> = n.split('.').collect();
    if labels.iter().any(|l| l.is_empty() || l.len() > 63) {
        return None;
    }
    let tld = labels[labels.len() - 1];
    if PRIVATE.contains(&tld) || tld.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let keep_from = labels.len().saturating_sub(2);
    let out: Vec<String> = labels
        .iter()
        .enumerate()
        .map(|(i, l)| if i < keep_from && looks_random(l) { "*".to_string() } else { l.to_string() })
        .collect();
    if out[keep_from..].iter().any(|l| l.contains('*')) {
        return None;
    }
    Some(out.join("."))
}

fn looks_random(label: &str) -> bool {
    if label == "*" {
        return true;
    }
    // A label merged around its random part (`p*-fmip`, crate::merge) is
    // kept unless what is left looks random too.
    if label.contains('*') {
        let rest: String = label.chars().filter(|c| *c != '*').collect();
        return rest.is_empty() || looks_random(&rest);
    }
    let digits = label.bytes().filter(u8::is_ascii_digit).count();
    let hex = label.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    digits >= 4 || (label.len() >= 8 && hex && digits > 0) || label.len() >= 20
}

/// "macos 27" from the probe's `start` record `os` object.
pub fn os_label(os: &Value) -> Option<String> {
    let family = os.get("os")?.as_str()?.to_ascii_lowercase();
    let s = if family == "linux" {
        linux_label(os)
    } else {
        let major = os.get("version").and_then(|v| v.as_str()).and_then(|v| v.split('.').next()).unwrap_or("");
        if major.is_empty() { family } else { format!("{} {}", family, major) }
    };
    check_os(&s).ok().map(|_| s)
}

/// Linux has no version of its own: "linux ubuntu 24", the distribution
/// and its major release, from what the probe records of os-release:
/// `distro` (`ID`) and `build` (`VERSION_ID`). Probes before 0.1.8 did not
/// record `ID`; the first word of `version` (`PRETTY_NAME`, "Ubuntu
/// 24.04.3 LTS") stands in for it. A release that is a date (rolling
/// distributions) is left out.
fn linux_label(os: &Value) -> String {
    let field = |k: &str| os.get(k).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty());
    let name = match field("distro") {
        Some(id) => id.to_string(),
        None => field("version").and_then(|p| p.split_whitespace().next()).unwrap_or("").to_string(),
    };
    let name: String = name.to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' }).collect();
    let name: String = name.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(20).collect();
    let name = name.trim_end();
    if name.is_empty() || name == "linux" {
        return "linux".into();
    }
    let release = field("build")
        .and_then(|b| b.split('.').next())
        .filter(|m| !m.is_empty() && m.len() <= 4 && m.bytes().all(|b| b.is_ascii_digit()));
    match release {
        Some(r) => format!("linux {} {}", name, r),
        None => format!("linux {}", name),
    }
}

/// An item seen locally. `count`, `first`, `last`, `procs` and `merged`
/// are shown to the participant and never sent.
#[derive(Serialize, Clone, Debug)]
pub struct Observed {
    pub key: String,
    pub item: Item,
    pub count: u64,
    pub first: i64,
    pub last: i64,
    pub procs: BTreeSet<String>,
    /// Labels of the items merged into this one (`crate::merge`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub merged: Vec<String>,
}

/// What was left out, so the app can say so.
#[derive(Serialize, Default, Clone, Debug)]
pub struct Skipped {
    /// ClientHellos with no known application.
    pub unattributed: u64,
    /// Names contacted by browsers: browsing history, never collected.
    pub browser_domains: u64,
    /// Local names, addresses, malformed names.
    pub private_domains: u64,
    /// Domains not collected because sharing them is off.
    pub domains_off: u64,
    /// Names seen only through DNS or plain HTTP, never in a ClientHello:
    /// not sent.
    pub not_sni: u64,
}

impl Skipped {
    fn add(&mut self, o: &Skipped) {
        self.unattributed += o.unattributed;
        self.browser_domains += o.browser_domains;
        self.private_domains += o.private_domains;
        self.domains_off += o.domains_off;
        self.not_sni += o.not_sni;
    }
}

/// Turns probe log records (`start`, `hello`, `domain`) into the items of
/// one epoch.
pub struct Collector {
    spec: EpochSpec,
    epoch: u32,
    share_domains: bool,
    os: Option<String>,
    items: HashMap<Item, Observed>,
    /// ClientHellos of the epoch, with an application or not.
    pub hellos: u64,
    pub skipped: Skipped,
}

pub(crate) fn ts(v: &Value, field: &str) -> Option<i64> {
    let s = v.get(field)?.as_str()?;
    chrono::DateTime::parse_from_rfc3339(s).ok().map(|t| t.timestamp())
}

/// Invisible formatting characters some bundles put in their names
/// (WhatsApp's starts with U+200E).
fn invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}')
}

/// A field that is a string or a list of strings.
fn strings(v: &Value, k: &str) -> Vec<String> {
    match v.get(k) {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

fn opt(v: &Value, k: &str) -> Option<String> {
    let s: String = v.get(k)?.as_str()?.chars().filter(|c| !invisible(*c)).collect();
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

impl Collector {
    pub fn new(spec: EpochSpec, epoch: u32, share_domains: bool) -> Self {
        Collector { spec, epoch, share_domains, os: None, items: HashMap::new(), hellos: 0, skipped: Skipped::default() }
    }

    /// The system the next records come from, as a `start` record before
    /// them would set it (`logs::Index` reads `start` records itself).
    pub(crate) fn set_os(&mut self, os: &Option<String>) {
        if self.os != *os {
            self.os = os.clone();
        }
    }

    /// Adds what another collector of the same epoch found (another file's
    /// records).
    pub fn absorb(&mut self, other: &Collector) {
        for (item, o) in &other.items {
            match self.items.get_mut(item) {
                Some(e) => {
                    e.count += o.count;
                    e.first = e.first.min(o.first);
                    e.last = e.last.max(o.last);
                    for p in &o.procs {
                        if e.procs.len() >= 8 {
                            break;
                        }
                        e.procs.insert(p.clone());
                    }
                }
                None => {
                    self.items.insert(item.clone(), o.clone());
                }
            }
        }
        self.hellos += other.hellos;
        self.skipped.add(&other.skipped);
    }

    fn in_epoch(&self, t: Option<i64>) -> Option<i64> {
        t.filter(|t| self.spec.at(*t) == Some(self.epoch))
    }

    fn add(&mut self, item: Item, t: i64, proc_name: Option<String>, n: u64) {
        // Checked and keyed once per item, not once per record.
        if !self.items.contains_key(&item) {
            if item.validate().is_err() {
                return;
            }
            let key = item.key();
            let o = Observed { key, item: item.clone(), count: 0, first: t, last: t, procs: BTreeSet::new(), merged: Vec::new() };
            self.items.insert(item.clone(), o);
        }
        let Some(e) = self.items.get_mut(&item) else { return };
        e.count += n;
        e.first = e.first.min(t);
        e.last = e.last.max(t);
        if let Some(p) = proc_name {
            if e.procs.len() < 8 {
                e.procs.insert(p);
            }
        }
    }

    pub fn record(&mut self, v: &Value) {
        match v.get("type").and_then(|t| t.as_str()) {
            Some("start") => {
                if let Some(os) = v.get("os").and_then(os_label) {
                    self.os = Some(os);
                }
            }
            Some("hello") => {
                let Some(t) = self.in_epoch(ts(v, "ts")) else { return };
                self.hellos += 1;
                let Some(os) = self.os.clone() else { return };
                let app = v.get("app").cloned().unwrap_or(Value::Null);
                let kind = opt(&app, "kind").unwrap_or_default();
                let (Some(name), Some(ja4), Some(transport)) = (opt(&app, "name"), opt(v, "ja4"), opt(v, "transport")) else {
                    return;
                };
                if kind == "unknown" || kind.is_empty() {
                    self.skipped.unattributed += 1;
                    return;
                }
                let item = Item::Hello {
                    os,
                    transport,
                    ja4,
                    app: AppRef {
                        name,
                        id: opt(&app, "id"),
                        version: opt(&app, "version"),
                        team_id: opt(&app, "team_id"),
                        kind,
                        engine: opt(&app, "engine"),
                    },
                };
                self.add(item, t, opt(v, "proc"), 1);
            }
            Some("domain") => {
                let Some(t) = self.in_epoch(ts(v, "last")) else { return };
                let Some(os) = self.os.clone() else { return };
                let kind = opt(v, "app_kind").unwrap_or_default();
                if kind == "unknown" || kind.is_empty() {
                    return;
                }
                if kind == "browser" {
                    self.skipped.browser_domains += 1;
                    return;
                }
                if !self.share_domains {
                    self.skipped.domains_off += 1;
                    return;
                }
                // Only names a ClientHello carried (SNI), each with its JA4.
                let ja4s: Vec<String> = if strings(v, "via").iter().any(|s| s == "sni") {
                    strings(v, "ja4").into_iter().filter(|j| is_ja4(j)).collect()
                } else {
                    vec![]
                };
                if ja4s.is_empty() {
                    self.skipped.not_sni += 1;
                    return;
                }
                let Some(domain) = opt(v, "domain").as_deref().and_then(normalize_domain) else {
                    self.skipped.private_domains += 1;
                    return;
                };
                let Some(name) = opt(v, "app") else { return };
                let n = v.get("count").and_then(|c| c.as_u64()).unwrap_or(1).max(1);
                for ja4 in ja4s {
                    let item = Item::Domain {
                        os: os.clone(),
                        app: AppRef { name: name.clone(), id: opt(v, "app_id"), version: None, team_id: None, kind: kind.clone(), engine: None },
                        domain: domain.clone(),
                        ja4,
                    };
                    self.add(item, t, opt(v, "proc"), n);
                }
            }
            _ => {}
        }
    }

    /// The items, in the order of their keys.
    pub fn finish(self) -> (Vec<Observed>, Skipped) {
        let mut v: Vec<Observed> = self.items.into_values().collect();
        v.sort_by(|a, b| a.key.cmp(&b.key));
        (v, self.skipped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn app() -> AppRef {
        AppRef { name: "Google Chrome".into(), id: Some("com.google.Chrome".into()), version: Some("157.0.8103.51".into()), team_id: None, kind: "browser".into(), engine: Some("chromium 157.0.8103.51".into()) }
    }

    #[test]
    fn key_is_canonical_and_round_trips() {
        let i = Item::Hello { os: "macos 27".into(), transport: "tcp".into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(), app: app() };
        assert!(i.validate().is_ok());
        let k = i.key();
        assert!(k.starts_with(r#"{"type":"hello","os":"macos 27""#), "{}", k);
        // Field order in the input does not matter.
        let shuffled = r#"{"app":{"kind":"browser","name":"Google Chrome","engine":"chromium 157.0.8103.51","version":"157.0.8103.51","id":"com.google.Chrome"},"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","transport":"tcp","os":"macos 27","type":"hello"}"#;
        assert_eq!(Item::from_key(shuffled).unwrap().key(), k);
        // Unknown fields are refused: an item cannot smuggle extra data.
        let extra = k.replacen("{\"type\":\"hello\",", "{\"type\":\"hello\",\"ip\":\"10.0.0.1\",", 1);
        assert!(Item::from_key(&extra).is_none());
        // The second JA4 of apps up to 0.1.9 is read and dropped: their
        // ballots count under the same key.
        let older = k.replacen("\"ja4\":", "\"ja4_legacy\":\"t13d1516h2_8daaf6152771_02713d6af862\",\"ja4\":", 1);
        assert_ne!(older, k);
        assert_eq!(Item::from_key(&older).unwrap().key(), k);
    }

    #[test]
    fn validation() {
        let mut i = Item::Hello { os: "macos 27".into(), transport: "tcp".into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(), app: app() };
        assert!(i.validate().is_ok());
        if let Item::Hello { ja4, .. } = &mut i {
            *ja4 = "t13d1516h2_8daaf6152771".into();
        }
        assert!(i.validate().is_err());
        let d = Item::Domain { os: "macos 27".into(), app: app(), domain: "www.google.com".into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into() };
        assert!(d.validate().is_err(), "no domains for browsers");
        assert!(is_ja4("q13d0311h3_55b375c5d22e_5a1f323ef56d"));
        assert!(is_ja4("dd2d270800_a2460661a67a_36cef8aed422"));
        assert!(!is_ja4("x13d0311h3_55b375c5d22e_5a1f323ef56d"));
    }

    #[test]
    fn domains() {
        assert_eq!(normalize_domain("Teams.Microsoft.com.").as_deref(), Some("teams.microsoft.com"));
        assert_eq!(normalize_domain("a1234.dscb.akamai.net").as_deref(), Some("*.dscb.akamai.net"));
        assert_eq!(normalize_domain("r3---sn-4g5e6nsz.googlevideo.com").as_deref(), Some("*.googlevideo.com"));
        assert_eq!(normalize_domain("eu-v20.events.data.microsoft.com").as_deref(), Some("eu-v20.events.data.microsoft.com"));
        assert_eq!(normalize_domain("3f2a9c81d0e4.cloudfront.net").as_deref(), Some("*.cloudfront.net"));
        assert_eq!(normalize_domain("p*-fmip.icloud.com").as_deref(), Some("p*-fmip.icloud.com"));
        assert_eq!(normalize_domain("a1b2c3d4e5*.example.com").as_deref(), Some("*.example.com"));
        assert_eq!(normalize_domain("p*-fmip.icloud.*"), None);
        for private in ["printer.local", "nas.lan", "1.0.0.10.in-addr.arpa", "10.0.0.1", "localhost", "router", "x.y.internal"] {
            assert_eq!(normalize_domain(private), None, "{}", private);
        }
    }

    #[test]
    fn collect_from_records() {
        let spec = EpochSpec { origin: 0, length: EpochSpec::WEEK };
        let t = "2026-11-16T17:19:56.110282Z";
        let e = spec.at(chrono::DateTime::parse_from_rfc3339(t).unwrap().timestamp()).unwrap();
        let mut c = Collector::new(spec, e, false);
        c.record(&json!({"type":"start","os":{"os":"macos","version":"27.0.1","build":"26A434"}}));
        let hello = |kind: &str| json!({"type":"hello","ts":t,"transport":"tcp","ja4":"t13d3012h1_1d37bd780c83_882d495ac381",
            "src":"192.0.2.10:49175","dst":"198.51.100.7:443","sni":"eu-v20.events.data.microsoft.com","proc":"telemetryd_v2",
            "app":{"name":"Microsoft Defender","id":"com.microsoft.wdav","version":"101.25","team_id":"UBF8T346G9","kind":kind,"path":"/Applications/Microsoft Defender.app"}});
        c.record(&hello("app"));
        c.record(&hello("app"));
        c.record(&hello("unknown"));
        c.record(&json!({"type":"domain","last":t,"app":"Microsoft Defender","app_kind":"app","domain":"eu-v20.events.data.microsoft.com","count":3}));
        c.record(&json!({"type":"domain","last":t,"app":"Google Chrome","app_kind":"browser","domain":"news.example.org","count":1}));
        c.record(&json!({"type":"hello","ts":t,"transport":"tcp","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1",
            "app":{"name":"\u{200e}WhatsApp","kind":"app"}}));
        let (items, skipped) = c.finish();
        assert!(items.iter().any(|o| o.key.contains(r#""name":"WhatsApp""#)));
        let items: Vec<_> = items.into_iter().filter(|o| !o.key.contains("WhatsApp")).collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].count, 2);
        let k = &items[0].key;
        for leaked in ["192.0.2", "198.51", "49175", "eu-v20", "/Applications", "2026"] {
            assert!(!k.contains(leaked), "{} in {}", leaked, k);
        }
        assert_eq!((skipped.unattributed, skipped.browser_domains, skipped.domains_off), (1, 1, 1));
    }

    /// Linux labels, from os-release as the probe records it (0.1.8 adds
    /// `distro`; before, only the pretty name and `VERSION_ID`).
    #[test]
    fn linux_labels() {
        let cases = [
            (json!({"os":"linux","distro":"ubuntu","version":"Ubuntu 24.04.3 LTS","build":"24.04"}), "linux ubuntu 24"),
            (json!({"os":"linux","version":"Ubuntu 24.04.3 LTS","build":"24.04","kernel":"7.0.0-38-generic"}), "linux ubuntu 24"),
            (json!({"os":"linux","distro":"debian","version":"Debian GNU/Linux 12 (bookworm)","build":"12"}), "linux debian 12"),
            (json!({"os":"linux","version":"Debian GNU/Linux 12 (bookworm)","build":"12"}), "linux debian 12"),
            (json!({"os":"linux","distro":"fedora","version":"Fedora Linux 41 (Server Edition)","build":"41"}), "linux fedora 41"),
            (json!({"os":"linux","distro":"rhel","version":"Red Hat Enterprise Linux 9.4 (Plow)","build":"9.4"}), "linux rhel 9"),
            (json!({"os":"linux","distro":"arch","version":"Arch Linux"}), "linux arch"),
            (json!({"os":"linux","distro":"opensuse-tumbleweed","version":"openSUSE Tumbleweed","build":"20261117"}), "linux opensuse tumbleweed"),
            (json!({"os":"linux","distro":"linuxmint","version":"Linux Mint 22.1","build":"22.1"}), "linux linuxmint 22"),
            (json!({"os":"linux","version":"Linux Mint 22.1","build":"22.1"}), "linux"),
            (json!({"os":"linux"}), "linux"),
            (json!({"os":"macos","version":"27.0.1","build":"26A434"}), "macos 27"),
            (json!({"os":"windows","version":"11","build":"26100.2314"}), "windows 11"),
        ];
        for (os, want) in cases {
            assert_eq!(os_label(&os).as_deref(), Some(want), "{}", os);
        }
    }

    /// Every ClientHello was dropped on Linux before 0.1.8: the pretty
    /// name made a label the check refused, so there was no OS.
    #[test]
    fn collect_on_linux() {
        let spec = EpochSpec { origin: 0, length: EpochSpec::DAY };
        let t = "2026-11-18T13:26:49.969161Z";
        let e = spec.at(chrono::DateTime::parse_from_rfc3339(t).unwrap().timestamp()).unwrap();
        let mut c = Collector::new(spec, e, false);
        c.record(&json!({"type":"start","os":{"arch":"x86_64","build":"24.04","kernel":"7.0.0-38-generic","model":null,"os":"linux","version":"Ubuntu 24.04.3 LTS"}}));
        c.record(&json!({"type":"hello","ts":t,"transport":"tcp","ja4":"t13d1517h2_8daaf6152771_e6dcd7ae0a9e","proc":"clickhouse",
            "attribution":"socket-table","app":{"kind":"system","name":"clickhouse","path":"/usr/bin/clickhouse","via":"self"}}));
        let (items, _) = c.finish();
        assert_eq!(items.len(), 1);
        assert!(items[0].key.contains(r#""os":"linux ubuntu 24""#), "{}", items[0].key);
    }

    /// Shared names: those a ClientHello carried, once per JA4; names seen
    /// only through DNS or HTTP stay on the computer.
    #[test]
    fn server_names_with_their_ja4() {
        let spec = EpochSpec { origin: 0, length: EpochSpec::WEEK };
        let t = "2026-11-16T17:19:56.110282Z";
        let e = spec.at(chrono::DateTime::parse_from_rfc3339(t).unwrap().timestamp()).unwrap();
        let mut c = Collector::new(spec, e, true);
        c.record(&json!({"type":"start","os":{"os":"macos","version":"27.0.1"}}));
        let (tcp, quic) = ("t13d1516h2_8daaf6152771_806a8c22fdea", "q13d0311h3_55b375c5d22e_653d80c3fe9d");
        c.record(&json!({"type":"domain","last":t,"app":"Microsoft Teams","app_kind":"app","domain":"teams.microsoft.com",
            "via":["dns","sni"],"ja4":[tcp, quic],"ports":["tcp/443","udp/443"],"count":4}));
        c.record(&json!({"type":"domain","last":t,"app":"Microsoft Teams","app_kind":"app","domain":"telemetry.example.com",
            "via":["dns-query"],"count":1}));
        c.record(&json!({"type":"domain","last":t,"app":"Microsoft Teams","app_kind":"app","domain":"printer.local",
            "via":["sni"],"ja4":[tcp],"count":1}));
        let (items, skipped) = c.finish();
        let got: BTreeSet<(String, String)> = items
            .iter()
            .map(|o| match &o.item {
                Item::Domain { domain, ja4, .. } => (domain.clone(), ja4.clone()),
                other => panic!("{:?}", other),
            })
            .collect();
        let want: BTreeSet<(String, String)> =
            [tcp, quic].iter().map(|j| ("teams.microsoft.com".to_string(), j.to_string())).collect();
        assert_eq!(got, want);
        assert!(items.iter().all(|o| o.item.validate().is_ok()));
        assert_eq!((skipped.not_sni, skipped.private_domains), (1, 1));
    }
}
