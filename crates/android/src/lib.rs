//! PeerSig on Android: the native half of the Android app (android/).
//!
//! Android lets an app see other apps' traffic only through a VPN, and
//! never lets it look at their processes. So, on a phone:
//!
//! - the capture is the app's own VPN, which forwards everything unchanged
//!   ([`forward`]) and passes a copy of each packet the apps send to the
//!   probe's pipeline ([`capture`]); the system names the app behind each
//!   ClientHello by its uid ([`apps`]). The records and daily logs are the
//!   desktop probe's, in the app's private storage;
//! - the participant's side is the desktop app's (`peersig_client`):
//!   settings, review, ballots through the relay. The window is the
//!   desktop app's too (crates/app/ui), in a WebView.
//!
//! The Kotlin side (android/app) holds the VPN service, the notification
//! and the window, and answers [`Java`]'s questions; `jni.rs` connects the
//! two.

pub mod apps;
pub mod capture;
#[cfg(unix)]
pub mod forward;
#[cfg(target_os = "android")]
mod jni;

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::{json, Value};

use peersig_client::core::{Core, View};
use peersig_client::{commands, worker, Host, Shared, Wake};

use crate::apps::PackageFacts;
use crate::capture::{Capture, UidOwners};

/// What the Kotlin side answers (`Host` in the app).
pub trait Java: Send + Sync + 'static {
    /// The uid of the app that owns the connection (protocol 6 or 17),
    /// from `ConnectivityManager.getConnectionOwnerUid`.
    fn owner_uid(&self, proto: u8, src: SocketAddr, dst: SocketAddr) -> Option<u32>;
    /// What the package manager says of a uid.
    fn package_facts(&self, uid: u32) -> Option<PackageFacts>;
    /// The participant allowed PeerSig's VPN (`VpnService.prepare`).
    fn capture_allowed(&self) -> bool;
    fn notify(&self, body: &str);
    /// The new state, as JSON: the window's (`View`), and what the
    /// notification says (`peersig_client::tray::Tray`).
    fn state(&self, view: &str, tray: &str);
}

/// Sends a new state to the Kotlin side.
fn show(java: &dyn Java, view: &View) {
    let tray = peersig_client::tray::tray(view);
    if let (Ok(v), Ok(t)) = (serde_json::to_string(view), serde_json::to_string(&tray)) {
        java.state(&v, &t);
    }
}

/// The Android app's side of `peersig_client`.
struct AndroidHost {
    java: Arc<dyn Java>,
    logs: PathBuf,
}

impl Host for AndroidHost {
    fn os(&self) -> &'static str {
        "android"
    }
    fn default_logs_dir(&self) -> PathBuf {
        self.logs.clone()
    }
    fn capture_installed(&self) -> bool {
        self.java.capture_allowed()
    }
    fn notify(&self, body: &str) {
        self.java.notify(body);
    }
    fn show(&self, view: &View) {
        show(&*self.java, view);
    }
}

/// Everything native, once per process.
pub struct Android {
    pub core: Shared,
    pub wake: Wake,
    java: Arc<dyn Java>,
    /// The participant's side: the worker and the window's commands.
    app: tokio::runtime::Runtime,
    /// The VPN's forwarding, apart, so that preparing a report (blinding
    /// hundreds of tokens) never holds up the phone's traffic.
    #[cfg(unix)]
    net: tokio::runtime::Runtime,
    logs: PathBuf,
    capture: Mutex<Option<Capture>>,
    #[cfg(unix)]
    forwarder: Mutex<Option<forward::Forwarder>>,
    #[cfg(unix)]
    pub dns: Arc<forward::Dns>,
}

fn arg_str(a: &Value, k: &str) -> String {
    a.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn arg_bool(a: &Value, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn arg_u32(a: &Value, k: &str) -> u32 {
    a.get(k).and_then(Value::as_u64).unwrap_or(0).min(u32::MAX as u64) as u32
}

impl Android {
    /// Loads the state from `files` (the app's private storage), and starts
    /// the worker: from now on, reports are sent while the process lives.
    pub fn new(files: &Path, java: Arc<dyn Java>) -> Result<Android> {
        let logs = files.join("logs");
        std::fs::create_dir_all(&logs)?;
        let host = Arc::new(AndroidHost { java: java.clone(), logs: logs.clone() });
        let core: Shared = Arc::new(tokio::sync::Mutex::new(Core::load(files, host)));
        let wake: Wake = Arc::new(tokio::sync::Notify::new());
        let app = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("peersig-app").enable_all().build()?;
        app.spawn(worker::run(core.clone(), wake.clone()));
        Ok(Android {
            core,
            wake,
            java,
            app,
            #[cfg(unix)]
            net: tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("peersig-vpn").enable_all().build()?,
            logs,
            capture: Mutex::new(None),
            #[cfg(unix)]
            forwarder: Mutex::new(None),
            #[cfg(unix)]
            dns: Arc::new(forward::Dns::new()),
        })
    }

    /// The window's commands that every app shares (`peersig_client`).
    /// The capture's (pause, start) are the Kotlin side's.
    pub fn command(&self, cmd: &str, a: &Value) -> Result<Value, String> {
        let (core, wake) = (&self.core, &self.wake);
        let rt = &self.app;
        let v = match cmd {
            "get_state" => serde_json::to_value(rt.block_on(commands::state(core))).map_err(|e| e.to_string())?,
            "get_items" => rt.block_on(commands::items(core, arg_bool(a, "current"))),
            "set_excluded" => {
                let keys: Vec<String> = a.get("keys").cloned().and_then(|k| serde_json::from_value(k).ok()).unwrap_or_default();
                let view = rt.block_on(commands::set_excluded(core, keys, arg_bool(a, "excluded")))?;
                self.show(&view);
                Value::Null
            }
            "enroll" => {
                let r = rt.block_on(commands::enroll(core, wake, arg_str(a, "server"), arg_str(a, "relay"), arg_str(a, "code"), arg_bool(a, "shareDomains")));
                r.map(|_| Value::Null)?
            }
            "save_settings" => {
                let form: commands::SettingsForm = a.get("form").cloned().and_then(|f| serde_json::from_value(f).ok()).ok_or("bad settings")?;
                rt.block_on(commands::save_settings(core, wake, form)).map(|_| Value::Null)?
            }
            "send_now" => rt.block_on(commands::send_now(core, wake)).map(|_| Value::Null)?,
            "leave" => rt.block_on(commands::leave(core, arg_bool(a, "deleteLogs"))).map(|_| Value::Null)?,
            // The capture changed (paused, started): a new state now.
            "refresh" => {
                wake.notify_one();
                Value::Null
            }
            _ => return Err(format!("unknown command {}", cmd)),
        };
        Ok(v)
    }

    /// The JSON the Kotlin side gets back from a command.
    pub fn command_json(&self, cmd: &str, args: &str) -> String {
        let a: Value = serde_json::from_str(args).unwrap_or(Value::Null);
        match self.command(cmd, &a) {
            Ok(v) => json!({ "ok": v }).to_string(),
            Err(e) => json!({ "err": e }).to_string(),
        }
    }

    fn show(&self, view: &View) {
        show(&*self.java, view);
    }

    /// The network's DNS servers, for the VPN's own.
    #[cfg(unix)]
    pub fn set_dns(&self, servers: Vec<IpAddr>) {
        self.dns.set(servers);
    }

    /// Starts forwarding and capturing on the VPN interface `fd` (this
    /// takes it, and closes it when stopped). Replaces any previous one.
    #[cfg(unix)]
    pub fn start_capture(&self, fd: i32) -> Result<(), String> {
        let mut cap = self.capture.lock().unwrap();
        if cap.is_none() {
            let owners = Box::new(UidOwners::new(self.java.clone()));
            *cap = Some(Capture::start(&self.logs, owners).map_err(|e| format!("{:#}", e))?);
        }
        let c = cap.as_ref().unwrap();
        *c.error.lock().unwrap() = None;
        let f = forward::Forwarder::start(self.net.handle(), fd, c.sender(), c.counters.clone(), self.dns.clone()).map_err(|e| e.to_string())?;
        log::info!("vpn interface up");
        // The previous interface closes when its forwarder is dropped.
        *self.forwarder.lock().unwrap() = Some(f);
        self.wake.notify_one();
        Ok(())
    }

    /// Stops the VPN: closes the interface. `why`, when the capture could
    /// not run, is what the window shows.
    #[cfg(unix)]
    pub fn stop_capture(&self, why: Option<String>) {
        if let Some(f) = self.forwarder.lock().unwrap().take() {
            f.stop();
            log::info!("vpn interface down{}", why.as_deref().map(|w| format!(": {}", w)).unwrap_or_default());
        }
        if let Some(c) = self.capture.lock().unwrap().as_ref() {
            c.counters.running.store(false, std::sync::atomic::Ordering::SeqCst);
            *c.error.lock().unwrap() = why;
        }
        self.wake.notify_one();
    }
}
