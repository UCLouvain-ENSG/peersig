//! The loop that runs the reports: every 30 seconds (5 while sending), or
//! when woken, it reads the capture's status, refreshes the server's
//! configuration, reads what is new in the logs (the counts, the review's
//! flags), opens the report of a period that ended, prepares it once its
//! review is over, and sends the ballots whose time has come. Beside it,
//! the device's model looks at new names for the review (`ask_model`).

use std::sync::Arc;
use std::time::Duration;

use peersig_proto::Item;

use crate::core::{self, now, utc_day, ReportState};
use crate::review::{self, ModelReply};
use crate::{local, Host, Shared};

/// Reads what is new in the logs: the handshakes not reported yet and in
/// all, the items of the report under review that the review shows first,
/// and the names the device's model has not seen.
async fn read_logs(core: &Shared) {
    let (since_epoch, own, answers, want_names) = {
        let c = core.lock().await;
        let Some(cy) = c.cycle() else { return };
        let want = c.host.has_model() && c.p.settings.use_model;
        (c.unsent_from(&cy), c.own_words(), review::Answers { names: c.answers.names.clone() }, want)
    };
    let r = core::read(core, move |r| {
        let cy = r.cycle;
        let (per_file, pending) = r.with(|i| (i.hellos_per_file(), (since_epoch..=cy.current).map(|e| i.hellos(e)).sum::<u64>()));
        let reported = r.items(cy.report).0;
        let flagged = reported.iter().filter(|o| !review::flags(&o.item, &own, &answers).is_empty()).count();
        let review = core::Review { epoch: cy.report, items: reported.len(), flagged };
        // The period under review first, then the current one.
        let mut names: Vec<String> = Vec::new();
        if want_names {
            let current = if cy.current != cy.report { r.items(cy.current).0 } else { vec![] };
            let mut seen = std::collections::HashSet::new();
            for o in reported.iter().chain(current.iter()) {
                for n in review::subjects(&o.item) {
                    if seen.insert(n.clone()) {
                        names.push(n);
                    }
                }
            }
        }
        (cy.spec.start(since_epoch), per_file, pending, review, names)
    })
    .await;
    let Some((since, per_file, pending, review, names)) = r else { return };
    let mut c = core.lock().await;
    if c.set_counts(&per_file, since, pending) {
        let _ = c.save();
    }
    c.review = Some(review);
    c.model.names = names.len();
    c.model.checked = names.iter().filter(|n| c.answers.names.contains_key(*n)).count();
    c.subjects = names;
}

/// Asks the device's model about the names it has not seen, 20 at a time
/// (about 20 seconds each), until none is left. Runs beside the worker, one
/// at a time: the review shows its answers as they come.
async fn ask_model(host: Arc<dyn Host>, core: Shared) {
    loop {
        let batch: Vec<String> = {
            let c = core.lock().await;
            if !c.p.settings.use_model {
                break;
            }
            c.subjects.iter().filter(|n| !c.answers.names.contains_key(*n)).take(20).cloned().collect()
        };
        if batch.is_empty() {
            break;
        }
        let (h, b) = (host.clone(), batch.clone());
        let reply = tokio::task::spawn_blocking(move || h.ask_model(&b)).await.unwrap_or_else(|e| ModelReply::Error(e.to_string()));
        let mut c = core.lock().await;
        match reply {
            ModelReply::Flags(flags) => {
                c.answers.record(&batch, &flags);
                let path = c.state_path();
                let _ = c.answers.save(&path);
                c.model.problem = None;
                let names = c.subjects.clone();
                c.model.checked = names.iter().filter(|n| c.answers.names.contains_key(*n)).count();
                let v = c.view();
                drop(c);
                host.show(&v);
            }
            ModelReply::Unavailable(why) | ModelReply::Error(why) => {
                c.model.problem = Some(why);
                c.model.retry_at = now() + 3600;
                break;
            }
        }
    }
    let mut c = core.lock().await;
    c.model.running = false;
    let v = c.view();
    drop(c);
    host.show(&v);
}

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

    // What is new in the logs.
    read_logs(core).await;
    {
        let mut c = core.lock().await;
        let start = c.p.settings.use_model && !c.model.running && now() >= c.model.retry_at && c.subjects.iter().any(|n| !c.answers.names.contains_key(n));
        if start && c.host.has_model() {
            c.model.running = true;
            tokio::spawn(ask_model(host.clone(), core.clone()));
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
                    let first = match &c.review {
                        Some(v) if v.epoch == r.epoch && v.flagged > 0 => format!(" {} of its {} items may say something about you: look at those first.", v.flagged, v.items),
                        _ => String::new(),
                    };
                    let msg = format!(
                        "Your report for the {} of {} is ready. It will be sent in about {} hours: open PeerSig to see it, or remove items.{}",
                        if observer { "day" } else { "week" },
                        day(r.from),
                        ((r.review_until - now()) + 1800) / 3600,
                        first
                    );
                    host.notify(&msg);
                }
            }
        }
    }

    // Review over: build the ballots.
    let due = {
        let c = core.lock().await;
        c.due_for_preparation().zip(c.config.as_ref().map(|x| x.1.clone()))
    };
    let due = match due {
        Some((e, cfg)) => core::read(core, move |r| {
            let real: Vec<Item> = r.items(e).0.into_iter().filter(|o| !r.excluded.contains(&o.key)).map(|o| o.item).collect();
            (e, cfg, real)
        })
        .await,
        None => None,
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
