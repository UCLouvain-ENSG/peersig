//! The loop that runs the reports: every 30 seconds (5 while sending), or
//! when woken, it reads the capture's status, refreshes the server's
//! configuration, opens the report of a period that ended, prepares it
//! once its review is over, and sends the ballots whose time has come.

use std::sync::Arc;
use std::time::Duration;

use peersig_proto::Item;

use crate::core::{self, now, utc_day, ReportState};
use crate::{local, Host, Shared};

async fn tick(host: &Arc<dyn Host>, core: &Shared) {
    let settings = {
        let mut c = core.lock().await;
        c.probe = local::status(&c.p.settings.logs());
        c.p.settings.clone()
    };
    host.tick(&settings);
    if !settings.enrolled() {
        return;
    }

    // Configuration: every 30 min, and when an epoch ends.
    let stale = {
        let c = core.lock().await;
        c.config.as_ref().map_or(true, |(t, cfg)| now() - t > 1800 || now() >= cfg.epochs.end(cfg.current_epoch))
    };
    if stale {
        let r = match settings.client() {
            Ok(mut cl) => cl.config().await,
            Err(e) => Err(e),
        };
        let mut c = core.lock().await;
        match r {
            Ok(cfg) => {
                c.config = Some((now(), cfg));
                c.last_error = None;
            }
            Err(e) => c.last_error = Some(format!("Cannot reach the server: {:#}", e)),
        }
    }

    // A new week to report.
    {
        let mut c = core.lock().await;
        if c.open_report() {
            let _ = c.save();
            let observer = c.p.settings.observer();
            let day = |t: i64| if observer { utc_day(t) } else { core::day(t) };
            if let Some(r) = c.current_report() {
                // An observer without a review sends unattended: nothing to announce.
                if !observer || settings.review_hours > 0 {
                    let msg = format!(
                        "Your report for the {} of {} is ready. It will be sent in about {} hours: open PeerSig to see it, or remove items.",
                        if observer { "day" } else { "week" },
                        day(r.from),
                        ((r.review_until - now()) + 1800) / 3600
                    );
                    host.notify(&msg);
                }
            }
        }
    }

    // Review over: build the ballots.
    let due = {
        let mut c = core.lock().await;
        match (c.due_for_preparation(), c.config.as_ref().map(|x| x.1.clone())) {
            (Some(e), Some(cfg)) => {
                let excluded = c.p.excluded.clone();
                let real: Vec<Item> = c.items(e).map(|(o, _)| o).unwrap_or_default().into_iter().filter(|o| !excluded.contains(&o.key)).map(|o| o.item).collect();
                Some((e, cfg, real))
            }
            _ => None,
        }
    };
    if let (Some((e, _, real)), true) = (&due, settings.observer()) {
        let (e, real) = (*e, real.clone());
        // A day with nothing seen is not sent (the server refuses it).
        let r = if real.is_empty() { Ok(None) } else { core::observe(&settings, e, real.clone()).await };
        let mut c = core.lock().await;
        c.send_now = None;
        match r {
            // Counted, or counted before (a retry whose answer was lost).
            Ok(_) => {
                core::observed(&mut c, e, real);
                c.last_error = None;
            }
            Err(err) => {
                let msg = format!("{:#}", err);
                if let Some(r) = c.p.reports.get_mut(&e) {
                    if msg.contains("(400)") || msg.contains("(403)") || msg.contains("(413)") {
                        r.state = ReportState::Failed;
                    } else {
                        r.review_until = now() + 600; // retry in 10 min
                    }
                    r.error = Some(msg.clone());
                }
                c.last_error = Some(msg);
            }
        }
        let _ = c.save();
    } else if let Some((e, cfg, real)) = due {
        let r = core::prepare(&settings, &cfg, real).await;
        let mut c = core.lock().await;
        match r {
            Ok(p) => {
                let window = c.p.reports.get(&e).map(|r| r.send_by - now() - 600).unwrap_or(0).max(60);
                let spread = if c.send_now == Some(e) { 300 } else { settings.spread_minutes as i64 * 60 }.min(window);
                let real_n = p.real.len();
                core::schedule(&mut c, e, p, spread);
                c.send_now = None;
                let _ = c.save();
                host.notify(&format!(
                    "Sending your week's report: {} items, one anonymous ballot each, over the next {} minutes.",
                    real_n,
                    (spread + 59) / 60
                ));
            }
            Err(err) => {
                let msg = format!("{:#}", err);
                c.send_now = None;
                if let Some(r) = c.p.reports.get_mut(&e) {
                    if msg.contains("(403)") || msg.contains("(429)") {
                        r.state = ReportState::Failed;
                    } else {
                        r.review_until = now() + 600; // retry in 10 min
                    }
                    r.error = Some(msg.clone());
                }
                c.last_error = Some(msg);
                let _ = c.save();
            }
        }
    }

    // Ballots whose time has come, one request each.
    let mut client = match settings.client() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut sent = 0;
    loop {
        let next = core.lock().await.next_ballot();
        let Some((e, b)) = next else { break };
        if sent == 0 {
            // The tray shows that ballots are being sent.
            let v = core.lock().await.view();
            host.show(&v);
        }
        match client.ballot(&b).await {
            Ok(()) => {
                let mut c = core.lock().await;
                c.ballot_sent(e, &b.token.nonce);
                sent += 1;
                if sent % 10 == 0 || !c.sending() {
                    let _ = c.save();
                }
            }
            Err(err) => {
                core.lock().await.last_error = Some(format!("Sending: {:#}", err));
                break;
            }
        }
    }
    if sent > 0 {
        let _ = core.lock().await.save();
    }
}

/// Runs the reports for as long as the app runs: nothing is sent
/// otherwise.
pub async fn run(core: Shared, wake: crate::Wake) {
    let host = core.lock().await.host.clone();
    loop {
        tick(&host, &core).await;
        let v = core.lock().await.view();
        host.show(&v);
        let wait = if v.reports.iter().any(|r| r.state == ReportState::Sending) { 5 } else { 30 };
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
            _ = wake.notified() => {}
        }
    }
}
