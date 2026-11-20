//! What the tray icon (on Android, the persistent notification) says.

use serde::Serialize;

use crate::core::{self, utc_day, ReportState, View};

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Icon {
    /// Capturing.
    Idle,
    /// Ballots are being sent.
    Sending,
    /// Paused, not capturing, or not enrolled.
    Paused,
}

#[derive(Serialize, Clone, Debug)]
pub struct Tray {
    /// "Capturing (1,234 handshakes seen)".
    pub status: String,
    /// "Week of Mon 16 Nov: sends in 5 h".
    pub report: String,
    /// "Send the week of Mon 16 Nov now", while a report is under review.
    pub send: Option<String>,
    pub paused: bool,
    pub icon: Icon,
}

pub fn tray(v: &View) -> Tray {
    let status = if !v.enrolled {
        "Not enrolled: open PeerSig to join".to_string()
    } else if v.observer && !v.paused && v.probe.running {
        format!("Observing ({} handshakes seen)", v.probe.hellos)
    } else if v.paused {
        "Capture paused".to_string()
    } else if !v.probe.running {
        "Capture is not running".to_string()
    } else {
        format!("Capturing ({} handshakes seen)", v.probe.hellos)
    };
    let of = if v.observer { "Day of" } else { "Week of" };
    let day = |t: i64| if v.observer { utc_day(t) } else { core::day(t) };
    let report = match &v.current {
        Some(r) if r.state == ReportState::Review => {
            let h = ((r.review_until - v.now).max(0) + 3599) / 3600;
            format!("{} {}: sends in {} h", of, day(r.from), h)
        }
        Some(r) if r.state == ReportState::Sending => format!("Sending week of {}: {}/{}", day(r.from), r.sent, r.total),
        Some(r) if r.state == ReportState::Sent => format!("{} {} sent", of, day(r.from)),
        Some(r) => format!("{} {}: not sent", of, day(r.from)),
        None => match &v.cycle {
            Some(c) if c.report >= c.current => format!("First report: from {}", day(c.spec.end(c.current))),
            _ => "Nothing to send yet".to_string(),
        },
    };
    let send = v
        .current
        .as_ref()
        .filter(|r| r.state == ReportState::Review)
        .map(|r| format!("Send the {} of {} now", if v.observer { "day" } else { "week" }, day(r.from)));
    let icon = if v.reports.iter().any(|r| r.state == ReportState::Sending) {
        Icon::Sending
    } else if v.paused || !v.probe.running || !v.enrolled {
        Icon::Paused
    } else {
        Icon::Idle
    };
    Tray { status, report, send, paused: v.paused, icon }
}
