//! What the window asks for, the same in every app: the desktop app's
//! Tauri commands and the Android app's bridge call these. Commands about
//! the capture itself (install, pause, open the logs) are each app's own.

use serde_json::{json, Value};

use crate::core::{self, now, View};
use crate::review;
use crate::{Shared, Wake};

type R<T> = Result<T, String>;

fn e2s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// The state, with the capture's status read now: the worker reads it
/// only every 30 seconds.
pub async fn state(core: &Shared) -> View {
    let mut c = core.lock().await;
    c.probe = crate::local::status(&c.p.settings.logs());
    c.view()
}

/// Items of the epoch being reported, or of the current one (`current`),
/// each with why the review shows it first (`flags`, empty for most). The
/// logs are read without the core's lock: the window and the tray do not
/// wait for them.
pub async fn items(core: &Shared, current: bool) -> Value {
    let (own, answers) = {
        let c = core.lock().await;
        (c.own_words(), c.answers.names.clone())
    };
    let answers = review::Answers { names: answers };
    let r = core::read(core, move |r| {
        let cy = r.cycle;
        let epoch = if current { cy.current } else { cy.report };
        let (items, skipped) = r.items(epoch);
        (cy, epoch, items, skipped, r.excluded.clone())
    })
    .await;
    let Some((cy, epoch, items, skipped, excluded)) = r else { return json!(null) };
    let items: Vec<Value> = items
        .into_iter()
        .map(|o| {
            let flags = review::flags(&o.item, &own, &answers);
            let mut v = serde_json::to_value(&o).unwrap_or_default();
            v["excluded"] = json!(excluded.contains(&o.key));
            v["flags"] = json!(flags);
            v
        })
        .collect();
    json!({
        "epoch": epoch,
        "from": cy.spec.start(epoch),
        "to": cy.spec.end(epoch),
        "current": current,
        "items": items,
        "skipped": skipped,
    })
}

/// Removes items from the reports, or puts them back (an application's
/// items at once). Returns the new state for the window.
pub async fn set_excluded(core: &Shared, keys: Vec<String>, excluded: bool) -> R<View> {
    let mut c = core.lock().await;
    for key in keys {
        if excluded {
            c.p.excluded.insert(key);
        } else {
            c.p.excluded.remove(&key);
        }
    }
    c.save().map_err(e2s)?;
    Ok(c.view())
}

/// Joins the study, after checking the server and that the relay and the
/// server publish the same gateway key.
pub async fn enroll(core: &Shared, wake: &Wake, server: String, relay: String, code: String, share_domains: bool) -> R<()> {
    let mut s = core.lock().await.p.settings.clone();
    s.server = server.trim().trim_end_matches('/').to_string();
    s.relay = relay.trim().trim_end_matches('/').to_string();
    s.code = code.trim().to_uppercase();
    s.share_domains = share_domains;
    if s.server.is_empty() || s.code.is_empty() {
        return Err("The server address and the enrollment code are both needed.".into());
    }
    // A dedicated observer runs unattended: its daily report goes out
    // shortly after midnight (UTC). Settings can add a review.
    if s.observer() {
        s.review_hours = 0;
    }
    // Checks the server, and the relay's and server's keys agree.
    let cfg = s.client().map_err(e2s)?.config().await.map_err(|e| format!("Cannot reach the server: {:#}", e))?;
    s.consented = Some(chrono::Utc::now().to_rfc3339());
    let mut c = core.lock().await;
    c.p.settings = s;
    c.config = Some((now(), cfg));
    c.last_error = None;
    c.save().map_err(e2s)?;
    wake.notify_one();
    Ok(())
}

/// What the Settings tab saves.
#[derive(serde::Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct SettingsForm {
    pub relay: String,
    pub share_domains: bool,
    pub review_hours: u32,
    pub spread_minutes: u32,
    pub flag_words: Vec<String>,
    pub use_model: bool,
}

pub async fn save_settings(core: &Shared, wake: &Wake, f: SettingsForm) -> R<()> {
    let mut c = core.lock().await;
    let s = &mut c.p.settings;
    s.relay = f.relay.trim().trim_end_matches('/').to_string();
    s.share_domains = f.share_domains;
    s.review_hours = f.review_hours.clamp(0, 96);
    s.spread_minutes = f.spread_minutes.clamp(5, 24 * 60);
    s.flag_words = f.flag_words.iter().map(|w| w.trim().to_string()).filter(|w| !w.is_empty()).take(100).collect();
    s.use_model = f.use_model;
    // Turned on again: try the model now.
    c.model.retry_at = 0;
    c.config = None;
    c.save().map_err(e2s)?;
    wake.notify_one();
    Ok(())
}

/// Skips the review of the report under review.
pub async fn send_now(core: &Shared, wake: &Wake) -> R<()> {
    core.lock().await.request_send()?;
    wake.notify_one();
    Ok(())
}

/// Leaves the study: forgets the code and history; optionally deletes the
/// local logs.
pub async fn leave(core: &Shared, delete_logs: bool) -> R<()> {
    let mut c = core.lock().await;
    let logs = c.p.settings.logs();
    c.p.settings.code.clear();
    c.p.settings.consented = None;
    c.p.reports.clear();
    c.p.excluded.clear();
    c.p.seen.clear();
    c.counts = None;
    c.review = None;
    c.config = None;
    c.save().map_err(e2s)?;
    c.forget_enrollment();
    if delete_logs {
        if let Ok(rd) = std::fs::read_dir(&logs) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("peersig-") && n.ends_with(".jsonl") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
    Ok(())
}
