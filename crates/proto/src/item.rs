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

use std::collections::{BTreeMap, BTreeSet};

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
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Item {
    Hello {
        /// "macos 27": family and major version only.
        os: String,
        /// tcp, quic or dtls.
        transport: String,
        ja4: String,
        /// The JA4 the Iris classifier stored before 2026-11-16, to label
        /// traffic archived before then.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ja4_legacy: Option<String>,
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
            Item::Hello { os, transport, ja4, ja4_legacy, app } => {
                check_os(os)?;
                if !matches!(transport.as_str(), "tcp" | "quic" | "dtls") {
                    return Err(format!("transport {:?}", transport));
                }
                if !is_ja4(ja4) {
                    return Err(format!("ja4 {:?}", ja4));
                }
                if let Some(l) = ja4_legacy {
                    if !is_ja4(l) {
                        return Err(format!("ja4_legacy {:?}", l));
                    }
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
    let major = os.get("version").and_then(|v| v.as_str()).and_then(|v| v.split('.').next()).unwrap_or("");
    let s = if major.is_empty() { family } else { format!("{} {}", family, major) };
    check_os(&s).ok().map(|_| s)
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

/// Turns probe log records (`start`, `hello`, `domain`) into the items of
/// one epoch.
pub struct Collector {
    spec: EpochSpec,
    epoch: u32,
    share_domains: bool,
    os: Option<String>,
    items: BTreeMap<String, Observed>,
    pub skipped: Skipped,
}

fn ts(v: &Value, field: &str) -> Option<i64> {
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
        Collector { spec, epoch, share_domains, os: None, items: BTreeMap::new(), skipped: Skipped::default() }
    }

    fn in_epoch(&self, t: Option<i64>) -> Option<i64> {
        t.filter(|t| self.spec.at(*t) == Some(self.epoch))
    }

    fn add(&mut self, item: Item, t: i64, proc_name: Option<String>, n: u64) {
        if item.validate().is_err() {
            return;
        }
        let key = item.key();
        let e = self.items.entry(key.clone()).or_insert_with(|| Observed {
            key,
            item,
            count: 0,
            first: t,
            last: t,
            procs: BTreeSet::new(),
            merged: Vec::new(),
        });
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
                    ja4_legacy: opt(v, "ja4_legacy"),
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

    pub fn finish(self) -> (Vec<Observed>, Skipped) {
        (self.items.into_values().collect(), self.skipped)
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
        let i = Item::Hello { os: "macos 27".into(), transport: "tcp".into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(), ja4_legacy: None, app: app() };
        assert!(i.validate().is_ok());
        let k = i.key();
        assert!(k.starts_with(r#"{"type":"hello","os":"macos 27""#), "{}", k);
        // Field order in the input does not matter.
        let shuffled = r#"{"app":{"kind":"browser","name":"Google Chrome","engine":"chromium 157.0.8103.51","version":"157.0.8103.51","id":"com.google.Chrome"},"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","transport":"tcp","os":"macos 27","type":"hello"}"#;
        assert_eq!(Item::from_key(shuffled).unwrap().key(), k);
        // Unknown fields are refused: an item cannot smuggle extra data.
        let extra = k.replacen("{\"type\":\"hello\",", "{\"type\":\"hello\",\"ip\":\"10.0.0.1\",", 1);
        assert!(Item::from_key(&extra).is_none());
    }

    #[test]
    fn validation() {
        let mut i = Item::Hello { os: "macos 27".into(), transport: "tcp".into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(), ja4_legacy: None, app: app() };
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
