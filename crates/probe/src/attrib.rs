//! Who sent a packet, and which application that is.
//!
//! Three processes can matter:
//! - `proc`, the socket owner: its TLS stack wrote the ClientHello, so the
//!   JA4 belongs to it (Chrome's network helper, com.apple.WebKit.Networking,
//!   nsurlsessiond);
//! - `eproc`, the effective process of a delegated socket (PKTAP): the one
//!   nsurlsessiond or another daemon works for;
//! - `resp`, the responsible process (macOS): the app an XPC service such as
//!   WebKit's networking process works for.
//!
//! `app` is the application credited with the traffic: the delegating
//! process if any, then its responsible app when it is an XPC service or a
//! helper inside that app, then the outermost `.app` around it.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::binary::{self, Signing};
use crate::bundle::{self, Bundle, Bundles, Engine, Package};
use crate::net::{FlowKey, PktapMeta};
use crate::platform;

#[derive(Debug, Deserialize)]
struct AppsFile {
    version: String,
    resolvers: Vec<String>,
    browser: Vec<BrowserRule>,
    stack: Vec<StackRule>,
}

#[derive(Debug, Deserialize)]
struct BrowserRule {
    bundle_id: String,
    family: String,
    #[serde(default)]
    exe: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StackRule {
    #[serde(rename = "match")]
    pattern: String,
    stack: String,
}

pub struct AppsDb {
    pub version: String,
    pub resolvers: Vec<String>,
    browsers: Vec<BrowserRule>,
    stacks: Vec<StackRule>,
}

impl AppsDb {
    pub fn load() -> AppsDb {
        let f: AppsFile = toml::from_str(include_str!("../data/apps.toml")).expect("data/apps.toml");
        AppsDb { version: f.version, resolvers: f.resolvers, browsers: f.browser, stacks: f.stack }
    }

    pub fn browser(&self, bundle_id: Option<&str>, exe_name: &str) -> Option<String> {
        if let Some(id) = bundle_id {
            for b in &self.browsers {
                if id == b.bundle_id || id.strip_prefix(&b.bundle_id).map_or(false, |r| r.starts_with('.')) {
                    return Some(b.family.clone());
                }
            }
        }
        let exe = exe_name.to_ascii_lowercase();
        self.browsers.iter().find(|b| b.exe.iter().any(|e| *e == exe)).map(|b| b.family.clone())
    }

    fn stacks_of<'a>(&self, libs: impl Iterator<Item = &'a str>) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for l in libs {
            for s in &self.stacks {
                if l.contains(&s.pattern) && !out.contains(&s.stack) {
                    out.push(s.stack.clone());
                }
            }
        }
        out
    }

    fn is_stack_lib(&self, l: &str) -> bool {
        self.stacks.iter().any(|s| l.contains(&s.pattern))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExeInfo {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<Signing>,
    /// Innermost first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<Bundle>,
    /// Info.plist embedded in the executable (daemons without a bundle).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<Bundle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<Engine>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_main: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<Package>,
    /// TLS stacks and runtimes from the linked libraries.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub linked_stacks: Vec<String>,
}

impl ExeInfo {
    /// Outermost application bundle.
    pub fn app_bundle(&self) -> Option<&Bundle> {
        self.bundles.iter().rev().find(|b| b.kind == "app")
    }
    fn innermost_kind(&self) -> Option<&str> {
        self.bundles.first().map(|b| b.kind.as_str())
    }
    pub fn file_name(&self) -> String {
        Path::new(&self.path).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Process {
    /// `pid@start` (start in microseconds since the epoch); `pid@?` when the
    /// process was gone, `name:<comm>` when reading a capture file.
    pub id: String,
    pub pid: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    pub name: String,
    pub alive: bool,
    /// Chromium `--type` (and `--utility-sub-type`) of a helper process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helper: Option<String>,
    /// Script or module run by an interpreter (file name only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responsible: Option<i32>,
    /// TLS and runtime libraries mapped in the process (outside the shared cache).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tls_libs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stacks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<Arc<ExeInfo>>,
}

impl Process {
    fn stub(id: String, pid: i32, name: &str) -> Process {
        Process {
            id,
            pid,
            ppid: None,
            uid: None,
            start: None,
            name: name.to_string(),
            alive: false,
            helper: None,
            script: None,
            responsible: None,
            tls_libs: Vec::new(),
            stacks: Vec::new(),
            exe: None,
        }
    }
    pub fn display(&self) -> String {
        self.exe.as_ref().map(|e| e.file_name()).unwrap_or_else(|| self.name.clone())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct App {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// browser, app, system, cli, unknown
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser: Option<String>,
    /// Engine of the process that wrote the ClientHello.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// How the app was chosen: self, delegated, responsible.
    pub via: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl App {
    pub fn label(&self) -> String {
        let mut s = self.name.clone();
        if let Some(v) = &self.version {
            s.push(' ');
            s.push_str(v);
        }
        if let Some(d) = &self.detail {
            s.push_str(&format!(" ({})", d));
        }
        s
    }
}

pub struct Attribution {
    /// pktap, pktap-offline, socket-table, none
    pub source: &'static str,
    pub proc: Option<Arc<Process>>,
    pub eproc: Option<Arc<Process>>,
    pub resp: Option<Arc<Process>>,
    pub app: App,
}

impl Attribution {
    pub fn processes(&self) -> impl Iterator<Item = &Arc<Process>> {
        self.proc.iter().chain(self.eproc.iter()).chain(self.resp.iter())
    }
    /// Key of the credited process for per-process tables.
    pub fn credited_id(&self) -> String {
        self.eproc.as_ref().or(self.proc.as_ref()).map(|p| p.id.clone()).unwrap_or_else(|| "unknown".into())
    }
}

const INTERPRETERS: &[&str] =
    &["python", "python3", "node", "ruby", "perl", "php", "java", "bun", "deno", "osascript", "bash", "zsh", "sh", "pwsh"];

const SYSTEM_PREFIXES: &[&str] = &["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/sbin/", "/bin/", "/Library/Apple/"];

pub struct Resolver {
    pub db: AppsDb,
    bundles: Bundles,
    exes: HashMap<String, Arc<ExeInfo>>,
    procs: HashMap<i32, Arc<Process>>,
    socket_cache: HashMap<FlowKey, Option<i32>>,
    /// Query live processes (false when reading a capture file).
    pub live: bool,
    pub lookups: u64,
}

impl Resolver {
    pub fn new(live: bool) -> Resolver {
        Resolver {
            db: AppsDb::load(),
            bundles: Bundles::default(),
            exes: HashMap::new(),
            procs: HashMap::new(),
            socket_cache: HashMap::new(),
            live,
            lookups: 0,
        }
    }

    pub fn exe(&mut self, path: &str) -> Arc<ExeInfo> {
        if let Some(e) = self.exes.get(path) {
            return e.clone();
        }
        let p = Path::new(path);
        let bin = binary::inspect(p).unwrap_or_default();
        let bundles = self.bundles.chain(p);
        let engine = self.bundles.engine(p, &bundles);
        let embedded = bin.info_plist.as_ref().map(|d| Bundle::from_dict("embedded", path, d));
        let linked_stacks = self.db.stacks_of(bin.libs.iter().map(String::as_str));
        let e = Arc::new(ExeInfo {
            path: path.to_string(),
            uuid: bin.uuid,
            signing: bin.signing,
            bundles,
            embedded,
            engine,
            go: bin.go_version,
            go_main: bin.go_main,
            package: bundle::package_of(path),
            linked_stacks,
        });
        self.exes.insert(path.to_string(), e.clone());
        e
    }

    /// A live process, cached by pid and start time (pids are reused).
    pub fn process(&mut self, pid: i32) -> Option<Arc<Process>> {
        if pid <= 0 || !self.live {
            return None;
        }
        let basic = platform::basic(pid)?;
        let id = format!("{}@{}", pid, basic.start_us);
        if let Some(p) = self.procs.get(&pid) {
            if p.id == id {
                return Some(p.clone());
            }
        }
        self.lookups += 1;
        let path = platform::exe_path(pid);
        let exe = path.as_deref().map(|p| self.exe(p));
        let args = platform::args(pid).unwrap_or_default();
        let helper = chromium_helper(&args);
        let script = exe.as_ref().and_then(|e| interpreter_script(&e.file_name(), &args));
        let mapped = platform::mapped_files(pid);
        let tls_libs: Vec<String> =
            mapped.iter().filter(|m| is_code_file(m) && self.db.is_stack_lib(m)).cloned().collect();
        let mut stacks = self.db.stacks_of(tls_libs.iter().map(String::as_str));
        if let Some(e) = &exe {
            // Engines that link their TLS stack statically.
            let implied = match e.engine.as_ref().map(|en| en.name.as_str()) {
                Some("chromium") | Some("electron") | Some("cef") => Some("boringssl"),
                Some("gecko") => Some("nss"),
                Some("webkit") => Some("apple-network"),
                _ => None,
            };
            if let Some(i) = implied {
                if !stacks.iter().any(|s| s == i) {
                    stacks.push(i.into());
                }
            }
            for s in &e.linked_stacks {
                if !stacks.contains(s) {
                    stacks.push(s.clone());
                }
            }
            if e.go.is_some() && !stacks.iter().any(|s| s == "go") {
                stacks.push("go".into());
            }
        }
        let start = chrono::DateTime::from_timestamp_micros(basic.start_us as i64).map(|t| t.to_rfc3339());
        let p = Arc::new(Process {
            id,
            pid,
            ppid: Some(basic.ppid),
            uid: Some(basic.uid),
            start,
            name: basic.name,
            alive: true,
            helper,
            script,
            responsible: platform::responsible_pid(pid).filter(|r| *r != pid),
            tls_libs,
            stacks,
            exe,
        });
        self.procs.insert(pid, p.clone());
        if self.procs.len() > 20_000 {
            self.procs.clear();
        }
        Some(p)
    }

    fn proc_or_stub(&mut self, pid: i32, comm: &str) -> Option<Arc<Process>> {
        if pid <= 0 && comm.is_empty() {
            return None;
        }
        if !self.live {
            return Some(Arc::new(Process::stub(format!("name:{}", comm), pid, comm)));
        }
        self.process(pid).or_else(|| Some(Arc::new(Process::stub(format!("{}@?", pid), pid, comm))))
    }

    pub fn attribute(&mut self, meta: Option<&PktapMeta>, key: &FlowKey) -> Attribution {
        let (source, proc, eproc) = match meta {
            Some(m) if m.pid > 0 || !m.comm.is_empty() => {
                let proc = self.proc_or_stub(m.pid, &m.comm);
                let eproc = if m.delegated() && (m.epid > 0 || !m.ecomm.is_empty()) {
                    self.proc_or_stub(m.epid, &m.ecomm)
                } else {
                    None
                };
                (if self.live { "pktap" } else { "pktap-offline" }, proc, eproc)
            }
            _ if self.live => {
                let pid = match self.socket_cache.get(key) {
                    Some(p) => *p,
                    None => {
                        let p = platform::socket_owner(key);
                        if self.socket_cache.len() > 50_000 {
                            self.socket_cache.clear();
                        }
                        self.socket_cache.insert(*key, p);
                        p
                    }
                };
                match pid.and_then(|p| self.process(p)) {
                    Some(p) => ("socket-table", Some(p), None),
                    None => ("none", None, None),
                }
            }
            _ => ("none", None, None),
        };
        let origin = eproc.clone().or_else(|| proc.clone());
        let mut resp = None;
        let mut credited = origin.clone();
        let mut via = if eproc.is_some() { "delegated".to_string() } else { "self".to_string() };
        if let Some(o) = &origin {
            if let Some(r) = o.responsible.and_then(|r| self.process(r)) {
                if works_for(o, &r) {
                    credited = Some(r.clone());
                    via.push_str("+responsible");
                }
                resp = Some(r);
            }
        }
        let engine_src = proc.as_ref().and_then(|p| p.exe.as_ref()).and_then(|e| e.engine.clone());
        let app = self.app_of(credited.as_deref(), engine_src, via);
        Attribution { source, proc, eproc, resp, app }
    }

    fn app_of(&self, p: Option<&Process>, engine: Option<Engine>, via: String) -> App {
        let Some(p) = p else {
            return App {
                name: "unknown".into(),
                id: None,
                version: None,
                team_id: None,
                kind: "unknown".into(),
                browser: None,
                engine: engine.map(|e| e.label()),
                detail: None,
                via,
                path: None,
            };
        };
        let exe = p.exe.as_deref();
        let app_b = exe.and_then(|e| e.app_bundle());
        let embedded = exe.and_then(|e| e.embedded.as_ref());
        let signing = exe.and_then(|e| e.signing.as_ref());
        let name = app_b
            .map(|b| b.display_name())
            .or_else(|| exe.map(|e| e.file_name()))
            .unwrap_or_else(|| p.name.clone());
        let id = app_b
            .and_then(|b| b.id.clone())
            .or_else(|| embedded.and_then(|b| b.id.clone()))
            .or_else(|| signing.and_then(|s| s.identifier.clone()));
        let version = app_b
            .and_then(|b| b.best_version())
            .or_else(|| embedded.and_then(|b| b.best_version()))
            .or_else(|| exe.and_then(|e| e.package.as_ref()).and_then(|pk| pk.version.clone()))
            .or_else(|| exe.and_then(|e| e.go.clone()));
        let path = app_b.map(|b| b.path.clone()).or_else(|| exe.map(|e| e.path.clone()));
        let browser = self.db.browser(id.as_deref(), &name);
        let system = signing.map_or(false, |s| s.platform)
            || path.as_deref().map_or(false, |p| SYSTEM_PREFIXES.iter().any(|s| p.starts_with(s)));
        let kind = if browser.is_some() {
            "browser"
        } else if system {
            "system"
        } else if app_b.is_some() {
            "app"
        } else if exe.is_some() {
            "cli"
        } else {
            "unknown"
        };
        let engine = engine.or_else(|| exe.and_then(|e| e.engine.clone())).map(|e| e.label());
        App {
            name,
            id,
            version,
            team_id: signing.and_then(|s| s.team_id.clone()),
            kind: kind.into(),
            browser,
            engine,
            detail: p.script.clone(),
            via,
            path,
        }
    }
}

/// An XPC service, app extension, WebKit process or helper inside the
/// responsible app works for it; a command run from Terminal does not work
/// for Terminal.
fn works_for(p: &Process, resp: &Process) -> bool {
    let Some(e) = p.exe.as_deref() else { return false };
    if matches!(e.innermost_kind(), Some("xpc") | Some("appex")) || e.file_name().starts_with("com.apple.WebKit.") {
        return true;
    }
    match resp.exe.as_deref().and_then(|r| r.app_bundle()) {
        Some(b) => e.path.starts_with(&format!("{}/", b.path)),
        None => false,
    }
}

/// Libraries and executables among the mapped files (not resources such
/// as CFNetwork's Localizable.loctable).
fn is_code_file(p: &str) -> bool {
    if p.contains("/Resources/") || p.contains(".lproj/") {
        return false;
    }
    let name = p.rsplit('/').next().unwrap_or(p);
    match name.rsplit_once('.') {
        None => true,
        Some((_, ext)) => matches!(ext, "dylib" | "so" | "bundle" | "node") || name.contains(".so."),
    }
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter().find_map(|a| a.strip_prefix(flag).and_then(|r| r.strip_prefix('=')))
}

fn chromium_helper(args: &[String]) -> Option<String> {
    let t = arg_value(args, "--type")?;
    Some(match arg_value(args, "--utility-sub-type") {
        Some(s) => format!("{}:{}", t, s),
        None => t.to_string(),
    })
}

fn base_name(s: &str) -> String {
    Path::new(s).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_else(|| s.to_string())
}

fn interpreter_script(exe_name: &str, args: &[String]) -> Option<String> {
    let stem = exe_name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if !INTERPRETERS.contains(&exe_name) && !INTERPRETERS.contains(&stem) {
        return None;
    }
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-m" | "-jar" => return it.next().map(|m| base_name(m)),
            "-cp" | "-classpath" | "--class-path" => {
                it.next();
            }
            "-c" | "-e" => return Some(format!("{} <inline>", a)),
            _ if a.starts_with('-') => continue,
            _ => return Some(base_name(a)),
        }
    }
    None
}

/// Process records already written, so each is written once.
#[derive(Default)]
pub struct Written(HashSet<String>);

impl Written {
    pub fn first_time(&mut self, id: &str) -> bool {
        if self.0.len() > 100_000 {
            self.0.clear();
        }
        self.0.insert(id.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(interpreter_script("python3.12", &a(&["python3", "-u", "/x/llm_label.py", "--think"])).as_deref(), Some("llm_label.py"));
        assert_eq!(interpreter_script("python3", &a(&["python3", "-m", "pip", "install"])).as_deref(), Some("pip"));
        assert_eq!(interpreter_script("java", &a(&["java", "-Xmx1g", "-jar", "/a/b/app.jar"])).as_deref(), Some("app.jar"));
        assert_eq!(interpreter_script("curl", &a(&["curl", "x"])), None);
        assert_eq!(
            chromium_helper(&a(&["Helper", "--type=utility", "--utility-sub-type=network.mojom.NetworkService"])).as_deref(),
            Some("utility:network.mojom.NetworkService")
        );
    }

    #[test]
    fn browsers() {
        let db = AppsDb::load();
        assert_eq!(db.browser(Some("com.google.Chrome.canary"), "x").as_deref(), Some("chrome"));
        assert_eq!(db.browser(Some("com.google.Chromecast"), "x"), None);
        assert_eq!(db.browser(None, "msedge.exe").as_deref(), Some("edge"));
    }
}
