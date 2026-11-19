//! `peersig-probe summary`: from one or more logs, which applications send each
//! JA4, and which names each application contacts. This is what a
//! participant sends back, so names are left out unless asked for.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;

#[derive(Default, Serialize)]
struct AppUse {
    count: u64,
    transports: BTreeSet<String>,
    procs: BTreeSet<String>,
    first: String,
    last: String,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    sni: BTreeSet<String>,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

#[derive(Default, Serialize)]
struct DomainUse {
    count: u64,
    via: BTreeSet<String>,
    procs: BTreeSet<String>,
}

pub struct Opts {
    pub names: bool,
    pub format: String,
    pub key: String,
}

fn s(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_string)
}

fn app_label(app: &Value) -> String {
    let name = s(app, "name").unwrap_or_else(|| "unknown".into());
    match s(app, "version") {
        Some(v) => format!("{} {}", name, v),
        None => name,
    }
}

pub fn run(files: &[String], o: &Opts) -> Result<()> {
    // fingerprint -> app label -> use
    let mut by_fp: BTreeMap<String, BTreeMap<String, AppUse>> = BTreeMap::new();
    // last cumulative domain record per (proc_id, domain)
    let mut domain_last: HashMap<(String, String), Value> = HashMap::new();
    let mut os: BTreeSet<String> = BTreeSet::new();
    for f in files {
        let r = BufReader::new(std::fs::File::open(f).with_context(|| f.clone())?);
        for line in r.lines() {
            let line = line?;
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            match v.get("type").and_then(|t| t.as_str()) {
                Some("start") => {
                    if let Some(osv) = v.get("os").filter(|o| o.is_object()) {
                        os.insert(format!(
                            "{} {} ({})",
                            s(osv, "os").unwrap_or_default(),
                            s(osv, "version").unwrap_or_default(),
                            s(osv, "build").unwrap_or_default()
                        ));
                    }
                }
                Some("hello") => {
                    let Some(fp) = s(&v, &o.key) else { continue };
                    let app = v.get("app").cloned().unwrap_or(Value::Null);
                    let u = by_fp.entry(fp).or_default().entry(app_label(&app)).or_default();
                    let ts = s(&v, "ts").unwrap_or_default();
                    if u.count == 0 {
                        u.first = ts.clone();
                        u.kind = s(&app, "kind").unwrap_or_default();
                        u.engine = s(&app, "engine");
                        u.id = s(&app, "id");
                    }
                    u.count += 1;
                    u.last = ts;
                    if let Some(t) = s(&v, "transport") {
                        u.transports.insert(t);
                    }
                    if let Some(p) = s(&v, "proc") {
                        let p = match s(&v, "helper") {
                            Some(h) => format!("{} [{}]", p, h),
                            None => p,
                        };
                        u.procs.insert(p);
                    }
                    if o.names {
                        if let Some(n) = s(&v, "sni") {
                            if u.sni.len() < 20 {
                                u.sni.insert(n);
                            }
                        }
                    }
                }
                Some("domain") => {
                    let (Some(p), Some(d)) = (s(&v, "proc_id"), s(&v, "domain")) else { continue };
                    domain_last.insert((p, d), v);
                }
                _ => {}
            }
        }
    }

    let mut by_app: BTreeMap<String, BTreeMap<String, DomainUse>> = BTreeMap::new();
    if o.names {
        for v in domain_last.values() {
            let label = match s(v, "app_version") {
                Some(ver) => format!("{} {}", s(v, "app").unwrap_or_default(), ver),
                None => s(v, "app").unwrap_or_default(),
            };
            let d = by_app.entry(label).or_default().entry(s(v, "domain").unwrap_or_default()).or_default();
            d.count += v.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
            for x in v.get("via").and_then(|x| x.as_array()).into_iter().flatten() {
                if let Some(x) = x.as_str() {
                    d.via.insert(x.to_string());
                }
            }
            if let Some(p) = s(v, "proc") {
                d.procs.insert(p);
            }
        }
    }

    match o.format.as_str() {
        "json" => {
            let out = serde_json::json!({ "os": os, "fingerprints": by_fp, "domains": by_app });
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        "classifier" => {
            // The format of data/ja4_fingerprints.json, for rules/fingerprints.toml.
            let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
            let os_s = os.iter().cloned().collect::<Vec<_>>().join(", ");
            let rows: Vec<Value> = by_fp
                .iter()
                .filter_map(|(fp, apps)| {
                    // Unattributed ClientHellos say nothing about the client.
                    let mut v: Vec<(&String, &AppUse)> = apps.iter().filter(|(label, _)| label.as_str() != "unknown").collect();
                    if v.is_empty() {
                        return None;
                    }
                    v.sort_by(|a, b| b.1.count.cmp(&a.1.count));
                    let mut names: Vec<String> = v.iter().take(4).map(|(n, _)| (*n).clone()).collect();
                    if v.len() > 4 {
                        names.push(format!("+{} more", v.len() - 4));
                    }
                    let origin = if os_s.is_empty() { "peersig-probe endpoint".to_string() } else { format!("peersig-probe endpoint, {}", os_s) };
                    Some(serde_json::json!({
                        "ja4_hash": fp,
                        "desc": format!("{} ({})", names.join("; "), origin),
                        "source": "peersig-probe",
                        "fetched": today,
                    }))
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
        _ => {
            if !os.is_empty() {
                println!("# {}", os.iter().cloned().collect::<Vec<_>>().join(", "));
            }
            println!("# {} -> applications (count, transports, processes)", o.key);
            for (fp, apps) in &by_fp {
                println!("{}", fp);
                let mut v: Vec<_> = apps.iter().collect();
                v.sort_by(|a, b| b.1.count.cmp(&a.1.count));
                for (label, u) in v {
                    let engine = u.engine.as_deref().map(|e| format!(" <{}>", e)).unwrap_or_default();
                    println!(
                        "    {:>6}  {} [{}]{}  {}  via {}",
                        u.count,
                        label,
                        u.kind,
                        engine,
                        u.transports.iter().cloned().collect::<Vec<_>>().join(","),
                        u.procs.iter().cloned().collect::<Vec<_>>().join(", ")
                    );
                    if !u.sni.is_empty() {
                        println!("            sni: {}", u.sni.iter().cloned().collect::<Vec<_>>().join(" "));
                    }
                }
            }
            if o.names {
                println!();
                println!("# application -> contacted names (count, via)");
                for (app, ds) in &by_app {
                    println!("{}", app);
                    let mut v: Vec<_> = ds.iter().collect();
                    v.sort_by(|a, b| b.1.count.cmp(&a.1.count).then(a.0.cmp(b.0)));
                    for (d, u) in v {
                        println!("    {:>6}  {}  ({})", u.count, d, u.via.iter().cloned().collect::<Vec<_>>().join(","));
                    }
                }
            }
        }
    }
    Ok(())
}
