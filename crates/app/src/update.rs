//! Updates of the desktop app. Once a day the app asks GitHub for the
//! latest published release's `latest.json` (a draft release is never
//! offered), and checks the update's signature against the public key
//! built into the app (`plugins.updater.pubkey` in tauri.conf.json): only
//! the study's release workflow can sign one (docs/deploy.md). An update
//! found is shown (notification, tray, window), and installed only when
//! the participant asks.
//!
//! The check is a plain download of a public file: it carries nothing
//! about the participant, but GitHub sees the computer's address, as for
//! any download (docs/privacy.md). With no public key configured, the app
//! never checks.
//!
//! Installing replaces the app; the capture service is updated afterwards
//! by the window's "Update capture service" button, which asks for an
//! administrator (as on the first install).

use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

use peersig_client::tray::Icon;
use peersig_client::Shared;

/// What the window and the tray show.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Available {
    pub version: String,
    pub notes: Option<String>,
    /// Installed by the package manager's password prompt (Linux), the
    /// MSI's administrator prompt (Windows), or nothing (macOS).
    pub asks_password: bool,
}

/// The update found by the last check, if any.
#[derive(Default)]
pub struct Found(Mutex<Option<Update>>);

impl Found {
    pub fn available(&self) -> Option<Available> {
        self.0.lock().unwrap().as_ref().map(|u| Available {
            version: u.version.clone(),
            notes: u.body.clone().filter(|n| !n.trim().is_empty()),
            asks_password: !cfg!(target_os = "macos"),
        })
    }
}

/// Whether the build carries a public key: without one, updates are off.
pub fn enabled(app: &AppHandle) -> bool {
    app.config()
        .plugins
        .0
        .get("updater")
        .and_then(|u| u.get("pubkey"))
        .and_then(|k| k.as_str())
        .is_some_and(|k| !k.trim().is_empty())
}

const FIRST_CHECK: Duration = Duration::from_secs(60);
const EVERY: Duration = Duration::from_secs(24 * 3600);

/// Checks a minute after start, then every day.
pub async fn run(app: AppHandle) {
    tokio::time::sleep(FIRST_CHECK).await;
    loop {
        check(&app).await;
        tokio::time::sleep(EVERY).await;
    }
}

async fn check(app: &AppHandle) {
    let found = match app.updater() {
        Ok(u) => u.check().await,
        Err(e) => Err(e),
    };
    let update = match found {
        Ok(u) => u,
        Err(e) => {
            // Offline, GitHub unreachable, no update for this package type:
            // try again tomorrow.
            eprintln!("update check: {}", e);
            return;
        }
    };
    let state = app.state::<Found>();
    let before = state.available().map(|a| a.version);
    *state.0.lock().unwrap() = update;
    let now = state.available();
    if let Some(a) = &now {
        if before.as_deref() != Some(a.version.as_str()) {
            crate::notify(app, &format!("PeerSig {} is available. Open PeerSig to install it.", a.version));
        }
    }
    crate::show_update(app, now.as_ref());
}

/// Downloads, checks and installs the update found, then restarts. On
/// Windows the installer exits the app itself and starts it again.
pub async fn install(app: &AppHandle) -> Result<(), String> {
    // Not in the middle of sending a report: it would stop half-way.
    {
        let core = app.state::<Shared>().inner().clone();
        let v = core.lock().await.view();
        if peersig_client::tray::tray(&v).icon == Icon::Sending {
            return Err("A report is being sent: install the update once it is done.".into());
        }
    }
    let Some(update) = app.state::<Found>().0.lock().unwrap().clone() else {
        return Err("No update to install.".into());
    };
    update.download_and_install(|_, _| {}, || {}).await.map_err(|e| format!("The update could not be installed: {}", e))?;
    app.restart();
}
