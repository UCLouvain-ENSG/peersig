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
//!
//! On Windows, `resp` is the app a WebView2 process works for, or the
//! browser process of a Chromium or Electron child; the app is named by its
//! executable's version resource, and a svchost process by the services it
//! runs. A download the BITS service makes for a program has that program
//! as `eproc` (`crate::bits`). The publisher takes the signing team's place
//! (`team_id`): a Store app's package publisher, else the signer of the
//! executable as Windows verifies it (`platform::publisher`).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::binary::{self, Signing, VersionInfo};
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
        let mut f: AppsFile = toml::from_str(include_str!("../data/apps.toml")).expect("data/apps.toml");
        for s in &mut f.stack {
            s.pattern = lib_key(&s.pattern).into_owned();
        }
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
            let l = lib_key(l);
            for s in &self.stacks {
                if l.contains(&s.pattern) && !out.contains(&s.stack) {
                    out.push(s.stack.clone());
                }
            }
        }
        out
    }

    fn is_stack_lib(&self, l: &str) -> bool {
        let l = lib_key(l);
        self.stacks.iter().any(|s| l.contains(&s.pattern))
    }
}

/// A library path or stack pattern, as they are compared: lower case on
/// Windows, where paths and DLL names come in any case
/// (`C:\WINDOWS\System32\SCHANNEL.dll`, `WINHTTP.dll` in an import table).
fn lib_key(lib: &str) -> Cow<'_, str> {
    if cfg!(windows) {
        Cow::Owned(lib.to_ascii_lowercase())
    } else {
        Cow::Borrowed(lib)
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
    /// Windows: the executable's version resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,
    /// Windows: gui or console.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subsystem: Option<String>,
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

/// `chrome.exe` -> `chrome`: Windows file names as app names.
fn without_exe(name: &str) -> String {
    match name.len().checked_sub(4) {
        Some(i) if name.is_char_boundary(i) && name[i..].eq_ignore_ascii_case(".exe") => name[..i].to_string(),
        _ => name.to_string(),
    }
}

/// Product name from a Windows version resource; none for the generic
/// "Microsoft Windows Operating System" of every OS binary.
fn product_name(v: &VersionInfo) -> Option<String> {
    if v.is_os_component() {
        return None;
    }
    v.product.clone().or_else(|| v.description.clone()).filter(|s| !s.trim().is_empty())
}

/// A svchost process runs one service (since Windows 10 1703 with enough
/// memory), sometimes a few. With many, which one sent a ClientHello
/// cannot be told.
fn is_service_host(p: &Process) -> bool {
    let exe = p.exe.as_ref().map(|e| e.file_name()).unwrap_or_else(|| p.name.clone());
    exe.eq_ignore_ascii_case("svchost.exe") && !p.services.is_empty() && p.services.len() <= 3
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
    /// Windows services running in the process (svchost).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
    /// TLS and runtime libraries mapped in the process (outside the shared cache).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tls_libs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stacks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<Arc<ExeInfo>>,
}

impl Process {
    /// An Android app, known by its uid (`uid:10123`): Android does not
    /// let an app look at other apps' processes.
    pub fn of_uid(uid: u32, name: &str) -> Process {
        let mut p = Process::stub(format!("uid:{}", uid), 0, name);
        p.uid = Some(uid);
        p.alive = true;
        p
    }

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
            services: Vec::new(),
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
    /// pktap, pktap-offline, socket-table, uid (Android), none
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

/// Who owns a connection, when the system says so itself: on Android, the
/// app (by uid) that `ConnectivityManager.getConnectionOwnerUid` names,
/// asked by the PeerSig app (crates/android). It replaces the process
/// lookups, which Android does not allow.
pub trait Owners: Send {
    /// The app behind the connection `key` (as the ClientHello's packet
    /// gives it), or None when the system does not know.
    fn owner(&mut self, key: &FlowKey) -> Option<(Arc<Process>, App)>;
}

const INTERPRETERS: &[&str] =
    &["python", "python3", "node", "ruby", "perl", "php", "java", "bun", "deno", "osascript", "bash", "zsh", "sh", "pwsh"];

/// How long a socket owner looked up stands for its flow: longer than a
/// ClientHello takes after the SYN (the tracker's 30 s).
const SOCKET_TTL: Duration = Duration::from_secs(60);

const SYSTEM_PREFIXES: &[&str] = &["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/sbin/", "/bin/", "/Library/Apple/"];

pub struct Resolver {
    pub db: AppsDb,
    bundles: Bundles,
    exes: HashMap<String, Arc<ExeInfo>>,
    procs: HashMap<i32, Arc<Process>>,
    /// Socket owners looked up, for `SOCKET_TTL`: the connection's SYN and
    /// ClientHello share one lookup, a later connection on the same
    /// addresses and ports gets its own.
    socket_cache: HashMap<FlowKey, (Instant, Option<i32>)>,
    /// This machine's addresses, and when they were listed.
    own: Option<(Instant, HashSet<IpAddr>)>,
    /// Query live processes (false when reading a capture file).
    pub live: bool,
    pub lookups: u64,
    /// ClientHellos from an address that is not this machine's: forwarded
    /// or bridged, so no local process sent them.
    pub not_local: u64,
    /// Android: the system names each connection's app.
    pub owners: Option<Box<dyn Owners>>,
}

impl Resolver {
    pub fn new(live: bool) -> Resolver {
        Resolver {
            db: AppsDb::load(),
            bundles: Bundles::default(),
            exes: HashMap::new(),
            procs: HashMap::new(),
            socket_cache: HashMap::new(),
            own: None,
            live,
            lookups: 0,
            not_local: 0,
            owners: None,
        }
    }

    pub fn exe(&mut self, path: &str) -> Arc<ExeInfo> {
        if let Some(e) = self.exes.get(path) {
            return e.clone();
        }
        let p = Path::new(path);
        let bin = binary::inspect(p).unwrap_or_default();
        let bundles = self.bundles.chain(p);
        let mut engine = self.bundles.engine(p, &bundles);
        if cfg!(windows) && engine.is_none() {
            let v = bin.version.as_ref().and_then(|v| v.version());
            engine = bundle::windows_engine(p, v.as_deref());
        }
        let embedded = bin.info_plist.as_ref().map(|d| Bundle::from_dict("embedded", path, d));
        let linked_stacks = self.db.stacks_of(bin.libs.iter().map(String::as_str));
        let mut package = bundle::package_of(path);
        if let Some(pk) = package.as_mut().filter(|pk| pk.manager == "msix") {
            pk.display_name = bundle::msix_display_name(path);
        }
        // Windows: the publisher stands where macOS has the signing team,
        // from the package of a Store app, else from the file's signature.
        #[cfg(windows)]
        let signing = bin.signing.or_else(|| {
            let msix = package.as_ref().is_some_and(|pk| pk.manager == "msix");
            let publisher = if msix { bundle::msix_publisher(path) } else { None }.or_else(|| platform::publisher(path));
            publisher.map(|p| Signing { team_id: Some(p), ..Default::default() })
        });
        #[cfg(not(windows))]
        let signing = bin.signing;
        let e = Arc::new(ExeInfo {
            path: path.to_string(),
            uuid: bin.uuid,
            signing,
            bundles,
            embedded,
            engine,
            go: bin.go_version,
            go_main: bin.go_main,
            package,
            linked_stacks,
            version_info: bin.version,
            subsystem: bin.subsystem,
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
        // A svchost started as `-k <group> -s <service>` runs that service.
        let mut services = platform::services(pid);
        if services.is_empty() && exe.as_ref().is_some_and(|e| e.file_name().eq_ignore_ascii_case("svchost.exe")) {
            services = args.windows(2).filter(|w| w[0] == "-s").map(|w| w[1].clone()).collect();
        }
        let start = (basic.start_us > 0)
            .then(|| chrono::DateTime::from_timestamp_micros(basic.start_us as i64).map(|t| t.to_rfc3339()))
            .flatten();
        let p = Arc::new(Process {
            id,
            pid,
            ppid: Some(basic.ppid),
            uid: basic.uid,
            start,
            name: basic.name,
            alive: true,
            helper,
            script,
            responsible: platform::responsible_pid(pid).filter(|r| *r != pid),
            services,
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

    /// Whether `ip` is one of this machine's addresses: only then can a
    /// local socket have sent the packet. Without this check, a forwarded
    /// ClientHello whose port matched a local socket's was credited to that
    /// socket's process. The list is read again for an address not in it,
    /// at most every 5 seconds: addresses come and go (DHCP, temporary IPv6).
    fn is_own(&mut self, ip: IpAddr) -> bool {
        let ip = platform::canonical(ip);
        if ip.is_loopback() || self.own.as_ref().is_some_and(|(_, s)| s.contains(&ip)) {
            return true;
        }
        if self.own.as_ref().map_or(true, |(t, _)| t.elapsed() >= Duration::from_secs(5)) {
            match platform::local_addrs() {
                Some(s) => self.own = Some((Instant::now(), s)),
                None => return true,
            }
        }
        self.own.as_ref().map_or(true, |(_, s)| s.contains(&ip))
    }

    pub fn attribute(&mut self, meta: Option<&PktapMeta>, key: &FlowKey) -> Attribution {
        if let (None, Some(owners)) = (meta, self.owners.as_mut()) {
            self.lookups += 1;
            return match owners.owner(key) {
                Some((p, app)) => Attribution { source: "uid", proc: Some(p), eproc: None, resp: None, app },
                None => Attribution { source: "none", proc: None, eproc: None, resp: None, app: self.app_of(None, None, "self".into()) },
            };
        }
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
            _ if self.live && !self.is_own(key.src) => {
                self.not_local += 1;
                ("none", None, None)
            }
            _ if self.live => {
                let pid = match self.socket_cache.get(key) {
                    Some((t, p)) if t.elapsed() < SOCKET_TTL => *p,
                    _ => {
                        let p = platform::socket_owner(key);
                        if self.socket_cache.len() > 50_000 {
                            self.socket_cache.retain(|_, (t, _)| t.elapsed() < SOCKET_TTL);
                        }
                        self.socket_cache.insert(*key, (Instant::now(), p));
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
        let via = if eproc.is_some() { "delegated" } else { "self" };
        self.credit(source, proc, eproc, via)
    }

    /// Windows: a ClientHello from the BITS service, to a host that one of
    /// its jobs is downloading from, is credited to the program that
    /// created the job (`crate::bits`), as a delegated socket is: the BITS
    /// service stays `proc`, that program becomes `eproc`.
    pub fn bits_delegate(&mut self, att: Attribution, sni: Option<&str>, ts: f64) -> Attribution {
        let from_bits = att.eproc.is_none()
            && att.proc.as_ref().is_some_and(|p| p.services.iter().any(|s| s.eq_ignore_ascii_case("BITS")));
        let (true, Some(host)) = (from_bits, sni) else { return att };
        let Some((path, pid)) = crate::bits::JOBS.lock().ok().and_then(|mut j| j.creator(host, ts)) else { return att };
        let pid = pid as i32;
        // The creator itself while it runs (that pid, that executable), else
        // its executable alone.
        let creator = self.process(pid).filter(|p| p.exe.as_ref().is_some_and(|e| e.path.eq_ignore_ascii_case(&path)));
        let creator = creator.unwrap_or_else(|| {
            let mut stub = Process::stub(format!("{}@?", pid), pid, &base_name(&path));
            stub.exe = Some(self.exe(&path));
            Arc::new(stub)
        });
        self.credit(att.source, att.proc, Some(creator), "bits")
    }

    /// The process credited with the traffic (the delegating one, then the
    /// app it works for), and its app.
    fn credit(&mut self, source: &'static str, proc: Option<Arc<Process>>, eproc: Option<Arc<Process>>, via: &str) -> Attribution {
        let origin = eproc.clone().or_else(|| proc.clone());
        let mut resp = None;
        let mut credited = origin.clone();
        let mut via = via.to_string();
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
        let vinfo = exe.and_then(|e| e.version_info.as_ref());
        let package = exe.and_then(|e| e.package.as_ref());
        // Windows service hosts are named after their services (BITS,
        // wuauserv, DoSvc): the service names, which are never translated.
        let service = is_service_host(p).then(|| p.services.join("+"));
        // An MSIX app's package says its name and version better than its
        // executable (WhatsApp's is "WhatsApp.Root 1.0.0").
        let msix = package.filter(|pk| pk.manager == "msix");
        let name = service
            .clone()
            .or_else(|| app_b.map(|b| b.display_name()))
            .or_else(|| msix.and_then(|pk| pk.display_name.clone()))
            .or_else(|| vinfo.and_then(product_name))
            .or_else(|| exe.map(|e| without_exe(&e.file_name())))
            .unwrap_or_else(|| without_exe(&p.name));
        let id = app_b
            .and_then(|b| b.id.clone())
            .or_else(|| embedded.and_then(|b| b.id.clone()))
            .or_else(|| signing.and_then(|s| s.identifier.clone()))
            .or_else(|| package.and_then(|pk| pk.family.clone()));
        let version = app_b
            .and_then(|b| b.best_version())
            .or_else(|| embedded.and_then(|b| b.best_version()))
            .or_else(|| msix.and_then(|pk| pk.version.clone()))
            .or_else(|| vinfo.and_then(|v| v.version()))
            .or_else(|| package.and_then(|pk| pk.version.clone()))
            .or_else(|| exe.and_then(|e| e.go.clone()));
        let path = app_b.map(|b| b.path.clone()).or_else(|| exe.map(|e| e.path.clone()));
        // By bundle id or name, then (Windows, Linux) by executable name.
        let browser = self
            .db
            .browser(id.as_deref(), &name)
            .or_else(|| self.db.browser(None, &exe.map(|e| e.file_name()).unwrap_or_else(|| p.name.clone())))
            .or_else(|| unlisted_chromium_browser(exe));
        let system = signing.map_or(false, |s| s.platform)
            || path.as_deref().map_or(false, |p| SYSTEM_PREFIXES.iter().any(|s| p.starts_with(s)) || is_windows_system(p))
            || service.is_some()
            // Windows components outside %SystemRoot% (Defender's platform
            // in ProgramData). The product name is not signed: a label only.
            || vinfo.is_some_and(|v| v.is_os_component());
        // Windows has no bundles: a GUI executable is an app.
        let gui = exe.and_then(|e| e.subsystem.as_deref()) == Some("gui");
        let kind = if browser.is_some() {
            "browser"
        } else if system {
            "system"
        } else if app_b.is_some() || gui {
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

/// Windows: an executable installed the way Chromium browsers are (a
/// version directory with chrome.dll or msedge.dll), but not in
/// apps.toml: a browser all the same (Whale, Yandex, Thorium...), so that
/// the names it contacts are never collected. Electron and CEF apps, and
/// the WebView2 runtime, are installed otherwise.
fn unlisted_chromium_browser(exe: Option<&ExeInfo>) -> Option<String> {
    let e = exe?;
    let en = e.engine.as_ref()?;
    let browser_layout = en.name == "chromium" && en.via.ends_with(".dll");
    (browser_layout && !e.file_name().eq_ignore_ascii_case("msedgewebview2.exe")).then(|| "chromium".to_string())
}

/// Windows: a file under %SystemRoot%.
fn is_windows_system(path: &str) -> bool {
    #[cfg(windows)]
    {
        platform::is_system_path(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        false
    }
}

/// An XPC service, app extension, WebKit process or helper inside the
/// responsible app works for it; a command run from Terminal does not work
/// for Terminal. On Windows, a WebView2 process works for its host, and a
/// process of the same executable as its responsible process (a Chromium
/// or Electron child) for that process.
fn works_for(p: &Process, resp: &Process) -> bool {
    let Some(e) = p.exe.as_deref() else { return false };
    if matches!(e.innermost_kind(), Some("xpc") | Some("appex")) || e.file_name().starts_with("com.apple.WebKit.") {
        return true;
    }
    if cfg!(windows) {
        if e.file_name().eq_ignore_ascii_case("msedgewebview2.exe") {
            return true;
        }
        if let Some(r) = resp.exe.as_deref() {
            if e.path.eq_ignore_ascii_case(&r.path) {
                return true;
            }
        }
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
        Some((_, ext)) => {
            matches!(ext, "dylib" | "so" | "bundle" | "node") || name.contains(".so.") || ext.eq_ignore_ascii_case("dll")
        }
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

    fn exe(path: &str, product: Option<&str>, version: &str, gui: bool) -> Arc<ExeInfo> {
        let mut package = bundle::package_of(path);
        if let Some(pk) = package.as_mut().filter(|pk| pk.manager == "msix") {
            pk.display_name = Some("Microsoft Teams".into());
        }
        Arc::new(ExeInfo {
            path: path.into(),
            uuid: None,
            signing: None,
            bundles: vec![],
            embedded: None,
            engine: None,
            go: None,
            go_main: None,
            package,
            linked_stacks: vec![],
            version_info: Some(VersionInfo {
                product: product.map(str::to_string),
                product_version: Some(version.into()),
                ..Default::default()
            }),
            subsystem: Some(if gui { "gui" } else { "console" }.into()),
        })
    }

    fn process(e: Arc<ExeInfo>, services: &[&str]) -> Process {
        let mut p = Process::stub("1@1".into(), 1, &e.file_name());
        p.exe = Some(e);
        p.services = services.iter().map(|s| s.to_string()).collect();
        p
    }

    /// Windows naming: version resources, service hosts, MSIX packages,
    /// browsers by executable name, GUI or console. Windows only: system
    /// files are recognized only there (`is_windows_system`), and other
    /// systems do not split `C:\...` paths.
    #[test]
    #[cfg(windows)]
    fn windows_apps() {
        let r = Resolver::new(false);
        let app = |p: &Process| r.app_of(Some(p), None, "self".into());
        let os = Some("Microsoft® Windows® Operating System");
        let a = app(&process(exe(r"C:\Windows\System32\svchost.exe", os, "10.0.26100.1", false), &["wuauserv"]));
        assert_eq!((a.name.as_str(), a.kind.as_str(), a.version.as_deref()), ("wuauserv", "system", Some("10.0.26100.1")));
        // Too many services in one host to tell which one: the host itself.
        let many = ["a", "b", "c", "d"];
        assert_eq!(app(&process(exe(r"C:\Windows\System32\svchost.exe", os, "10.0.26100.1", false), &many)).name, "svchost");
        let a = app(&process(exe(r"C:\Program Files\Google\Chrome\Application\chrome.exe", Some("Google Chrome"), "131.0.6778.86", true), &[]));
        assert_eq!((a.name.as_str(), a.kind.as_str(), a.browser.as_deref()), ("Google Chrome", "browser", Some("chrome")));
        let teams = r"C:\Program Files\WindowsApps\MSTeams_25290.205.4069.4894_x64__8wekyb3d8bbwe\ms-teams.exe";
        let a = app(&process(exe(teams, Some("Microsoft Teams"), "1.0.0", true), &[]));
        assert_eq!(
            (a.name.as_str(), a.id.as_deref(), a.version.as_deref(), a.kind.as_str()),
            ("Microsoft Teams", Some("MSTeams_8wekyb3d8bbwe"), Some("25290.205.4069.4894"), "app")
        );
        let a = app(&process(exe(r"C:\Program Files\Python313\python.exe", Some("Python"), "3.13.1", false), &[]));
        assert_eq!((a.name.as_str(), a.kind.as_str()), ("Python", "cli"));
        let a = app(&process(exe(r"C:\tools\tool.exe", None, "", false), &[]));
        assert_eq!((a.name.as_str(), a.version, a.kind.as_str()), ("tool", None, "cli"));
        // A Chromium browser missing from apps.toml is still a browser; the
        // WebView2 runtime is not.
        let with_engine = |path: &str| {
            let mut e = (*exe(path, Some("Some Browser"), "131.1.2.3", true)).clone();
            e.engine = Some(bundle::Engine { name: "chromium".into(), version: Some("131.1.2.3".into()), via: "chrome.dll".into() });
            Arc::new(e)
        };
        let a = app(&process(with_engine(r"C:\Program Files\Some\Application\somebrowser.exe"), &[]));
        assert_eq!((a.kind.as_str(), a.browser.as_deref()), ("browser", Some("chromium")));
        let a = app(&process(with_engine(r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\131.1.2.3\msedgewebview2.exe"), &[]));
        assert_eq!(a.kind, "app");
    }

    #[test]
    fn browsers() {
        let db = AppsDb::load();
        assert_eq!(db.browser(Some("com.google.Chrome.canary"), "x").as_deref(), Some("chrome"));
        assert_eq!(db.browser(Some("com.google.Chromecast"), "x"), None);
        assert_eq!(db.browser(None, "msedge.exe").as_deref(), Some("edge"));
    }
}
