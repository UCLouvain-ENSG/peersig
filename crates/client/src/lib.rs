//! The participant's side of PeerSig, shared by the desktop app
//! (crates/app) and the Android app (crates/android): the settings, the
//! weekly report (a dedicated observer's daily one), what the window
//! shows, and the commands the window sends. Each app supplies a [`Host`]:
//! how its capture runs, and how the participant is told.
//!
//! - [`core`]: the state, the report cycle, the ballots' schedule;
//! - [`local`]: what the capture left on this device (status, logs);
//! - [`review`]: which items the review shows first, and why;
//! - [`worker`]: the loop that opens, prepares and sends reports;
//! - [`commands`]: what the window asks for;
//! - [`tray`]: what the tray icon (Android: the notification) says.

pub mod commands;
pub mod core;
pub mod local;
pub mod review;
pub mod tray;
pub mod worker;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::{Mutex, Notify};

pub use crate::core::{Core, ReportState, Settings, View};

/// The core, shared by the window's commands and the worker.
pub type Shared = Arc<Mutex<Core>>;

/// Wakes the worker before its next tick (after joining, "send now").
pub type Wake = Arc<Notify>;

/// What differs between the apps.
pub trait Host: Send + Sync + 'static {
    /// `macos`, `windows`, `linux`, `android`: the window adapts its text.
    fn os(&self) -> &'static str {
        std::env::consts::OS
    }
    /// Where the capture writes its daily logs, unless the settings say.
    fn default_logs_dir(&self) -> PathBuf;
    /// The capture is set up: the service is installed, or (Android) the
    /// participant allowed the VPN.
    fn capture_installed(&self) -> bool;
    /// The installed capture is not the one this app ships.
    fn capture_outdated(&self, _tool: Option<&str>) -> bool {
        false
    }
    /// The participant paused the capture.
    fn paused(&self, logs: &Path) -> bool {
        logs.join("paused").exists()
    }
    /// A notification.
    fn notify(&self, body: &str);
    /// Every new state: the tray icon, the window, Android's notification.
    fn show(&self, view: &View);
    /// At the start of each tick (the Linux app keeps its probe running).
    fn tick(&self, _settings: &Settings) {}
    /// Whether the device has a language model of its own to point out
    /// sensitive names in the review (macOS: Apple Intelligence).
    fn has_model(&self) -> bool {
        false
    }
    /// Asks the device's own model which of `names` could say something
    /// sensitive about the person (`review::subjects`). Blocks for about a
    /// second a name. Nothing may leave the device.
    fn ask_model(&self, _names: &[String]) -> review::ModelReply {
        review::ModelReply::Unavailable("no model on this device".into())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A host that shows nothing.
    pub struct Quiet;

    impl Host for Quiet {
        fn default_logs_dir(&self) -> PathBuf {
            std::env::temp_dir().join("peersig-client-logs")
        }
        fn capture_installed(&self) -> bool {
            true
        }
        fn notify(&self, _body: &str) {}
        fn show(&self, _view: &View) {}
    }

    pub fn host() -> Arc<dyn Host> {
        Arc::new(Quiet)
    }
}
