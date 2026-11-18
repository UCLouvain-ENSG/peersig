//! A participant without the app: the same week as the app's (crates/app,
//! docs/privacy.md), run by the service.
//!
//! During week `e + 1`, week `e` is reported:
//! 1. review: its items wait `review_hours` (24 by default). `peersig
//!    items` lists them, `peersig exclude <id>` leaves one out for good,
//!    `peersig report` ends the review early;
//! 2. prepare (`peersig_proto::participant`): the configuration and token
//!    key fetched again through the relay, the full token budget asked for,
//!    every signature checked;
//! 3. send: each item, and one "took part" ballot, as a separate request
//!    through the relay, at random times over `spread_minutes`.
//!
//! The service keeps its reports (with the tokens not spent yet) in
//! `<state>/participant.json`, so that a restart loses nothing. A week
//! whose window passes while the service is not running is not sent.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use peersig_proto::wire::{Ballot, Config};
use peersig_proto::Item;

use crate::{code_label, now, write_private, Opts};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Review,
    Sending,
    Sent,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Queued {
    pub at: i64,
    pub ballot: Ballot,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Report {
    pub epoch: u32,
    /// The week reported.
    pub from: i64,
    pub to: i64,
    pub stage: Stage,
    pub review_until: i64,
    /// End of the reporting window.
    pub send_by: i64,
    /// The participant's items among the ballots.
    #[serde(default)]
    pub items: usize,
    /// Items over the token budget, left out.
    #[serde(default)]
    pub dropped: usize,
    #[serde(default)]
    pub total: usize,
    #[serde(default)]
    pub sent: usize,
    #[serde(default)]
    pub queue: Vec<Queued>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub finished: Option<i64>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct State {
    pub reports: BTreeMap<u32, Report>,
}

pub fn state_path(o: &Opts) -> PathBuf {
    o.state.join("participant.json")
}

fn send_now_path(o: &Opts) -> PathBuf {
    o.state.join("send-now")
}

impl State {
    pub fn load(path: &Path) -> State {
        std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, path: &Path) -> Result<()> {
        write_private(path, &serde_json::to_vec_pretty(self)?)
    }
}

fn when(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0).map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default()
}

fn week(r: &Report) -> String {
    let d = |t: i64| chrono::DateTime::from_timestamp(t, 0).map(|d| d.date_naive().to_string()).unwrap_or_default();
    format!("week of {} to {}", d(r.from), d(r.to - 1))
}

/// One line on a report, for `status` and the log.
pub fn describe(r: &Report) -> String {
    match r.stage {
        Stage::Review => format!("{}: {} items, sent from {}", week(r), r.items, when(r.review_until)),
        Stage::Sending => format!("{}: sending, {} of {} ballots", week(r), r.sent, r.total),
        Stage::Sent => format!("{}: sent, {} items in {} ballots, {}", week(r), r.items, r.total, when(r.finished.unwrap_or(r.to))),
        Stage::Failed => format!("{}: not sent: {}", week(r), r.error.clone().unwrap_or_default()),
    }
}

/// `peersig report`: ends the review of the week under review; the
/// service sends it at its next turn.
pub fn send_now(o: &Opts) -> Result<()> {
    let st = State::load(&state_path(o));
    match st.reports.values().next_back() {
        Some(r) if r.stage == Stage::Review => {
            write_private(&send_now_path(o), r.epoch.to_string().as_bytes())?;
            eprintln!("The {} goes out within a minute, if the service runs (`peersig status`).", week(r));
            Ok(())
        }
        Some(r) => anyhow::bail!("nothing under review: {}", describe(r)),
        None => anyhow::bail!("nothing under review yet: a week is reported once it is over (`peersig status`)"),
    }
}

/// The items of week `e` that are sent: merged, without those left out.
fn kept(o: &Opts, cfg: &Config, e: u32) -> Vec<Item> {
    o.items(cfg.epochs, e, false).into_iter().filter(|(_, out)| !out).map(|(ob, _)| ob.item).collect()
}

pub async fn run(o: &Opts, code: &str) -> Result<()> {
    eprintln!(
        "peersig {}: participant {}, reports weekly to {} through {}, from {}",
        env!("CARGO_PKG_VERSION"),
        code_label(code),
        o.server,
        o.relay().unwrap_or("no relay (the server sees this machine's address)"),
        o.logs.display()
    );
    let path = state_path(o);
    let mut st = State::load(&path);
    let mut cfg: Option<(i64, Config)> = None;
    loop {
        let wait = tick(o, code, &path, &mut st, &mut cfg).await;
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
}

/// One turn of the service; returns the seconds until the next.
pub async fn tick(o: &Opts, code: &str, path: &Path, st: &mut State, cfg: &mut Option<(i64, Config)>) -> u64 {
    let t = now();
    // The configuration: every 30 minutes, and when the week ends.
    let stale = cfg.as_ref().map_or(true, |(at, c)| t - at > 1800 || t >= c.epochs.end(c.current_epoch));
    if stale {
        match o.config().await {
            Ok(c) => *cfg = Some((t, c)),
            Err(e) => {
                eprintln!("{:#}; trying again in 10 minutes", e);
                if cfg.is_none() {
                    return 600;
                }
            }
        }
    }
    let Some((_, c)) = cfg.clone() else { return 600 };
    let mut changed = false;

    // Windows that closed.
    for r in st.reports.values_mut() {
        if matches!(r.stage, Stage::Review | Stage::Sending) && t >= r.send_by {
            r.error = Some(match r.stage {
                Stage::Review => "the reporting window closed before the week could be sent".into(),
                _ => format!("the reporting window closed with {} ballots unsent", r.queue.len()),
            });
            r.stage = Stage::Failed;
            r.queue.clear();
            eprintln!("{}", describe(r));
            changed = true;
        }
    }

    // A week to report.
    let e = c.report_epoch;
    if e < c.current_epoch && !st.reports.contains_key(&e) {
        let send_by = c.epochs.end(c.current_epoch);
        let spread = o.spread_minutes as i64 * 60;
        let review_until = (t + o.review_hours as i64 * 3600).min(send_by - spread - 3600).max(t);
        let r = Report {
            epoch: e,
            from: c.epochs.start(e),
            to: c.epochs.end(e),
            stage: Stage::Review,
            review_until,
            send_by,
            items: kept(o, &c, e).len(),
            dropped: 0,
            total: 0,
            sent: 0,
            queue: vec![],
            error: None,
            finished: None,
        };
        eprintln!("{}. `sudo peersig items` lists them, `sudo peersig exclude <id>` leaves one out.", describe(&r));
        st.reports.insert(e, r);
        while st.reports.len() > 60 {
            let first = *st.reports.keys().next().unwrap();
            st.reports.remove(&first);
        }
        changed = true;
    }

    // `peersig report`: the review ends now.
    if let Ok(asked) = std::fs::read_to_string(send_now_path(o)) {
        let _ = std::fs::remove_file(send_now_path(o));
        if let Some(r) = st.reports.get_mut(&e).filter(|r| r.stage == Stage::Review && asked.trim() == e.to_string()) {
            r.review_until = t;
            changed = true;
        }
    }

    // Review over: the ballots and their tokens.
    if st.reports.get(&e).is_some_and(|r| r.stage == Stage::Review && t >= r.review_until) {
        let real = kept(o, &c, e);
        let prepared = match o.client() {
            Ok(mut client) => peersig_proto::participant::prepare(&mut client, code, o.share_domains, &c, real).await,
            Err(err) => Err(err),
        };
        let r = st.reports.get_mut(&e).expect("checked");
        match prepared {
            Ok(p) => {
                let window = (r.send_by - t - 600).max(60);
                let spread = (o.spread_minutes as i64 * 60).min(window);
                r.items = p.real.len();
                r.dropped = p.plan.dropped;
                let mut queue: Vec<Queued> =
                    p.ballots().into_iter().map(|ballot| Queued { at: t + (rand::random::<f64>() * spread as f64) as i64, ballot }).collect();
                queue.sort_by_key(|q| q.at);
                r.total = queue.len();
                r.queue = queue;
                r.stage = Stage::Sending;
                r.error = None;
                eprintln!(
                    "{}: sending {} items and one \"took part\" ballot, one anonymous ballot each, over {} minutes{}",
                    week(r),
                    r.items,
                    (spread + 59) / 60,
                    if r.dropped > 0 { format!(" ({} items over the token budget left out)", r.dropped) } else { String::new() }
                );
            }
            Err(err) => {
                let msg = format!("{:#}", err);
                if msg.contains("(403)") || msg.contains("(429)") {
                    r.stage = Stage::Failed;
                } else {
                    r.review_until = t + 600;
                }
                eprintln!("{}: {}{}", week(r), msg, if r.stage == Stage::Failed { "" } else { "; trying again in 10 minutes" });
                r.error = Some(msg);
            }
        }
        changed = true;
    }

    // Ballots whose time has come, one request each.
    let due: Vec<(u32, Ballot)> = st
        .reports
        .values()
        .filter(|r| r.stage == Stage::Sending)
        .flat_map(|r| r.queue.iter().filter(|q| q.at <= t).map(move |q| (r.epoch, q.ballot.clone())))
        .collect();
    if !due.is_empty() {
        match o.client() {
            Ok(mut client) => {
                for (epoch, b) in due {
                    match client.ballot(&b).await {
                        Ok(()) => {
                            let r = st.reports.get_mut(&epoch).expect("listed");
                            r.queue.retain(|q| q.ballot.token.nonce != b.token.nonce);
                            r.sent += 1;
                            if r.queue.is_empty() {
                                r.stage = Stage::Sent;
                                r.finished = Some(now());
                                eprintln!("{}", describe(r));
                            }
                            changed = true;
                        }
                        Err(err) => {
                            eprintln!("sending a ballot: {:#}; trying again", err);
                            break;
                        }
                    }
                }
            }
            Err(err) => eprintln!("{:#}", err),
        }
    }

    if changed {
        if let Err(err) = st.save(path) {
            eprintln!("saving {}: {:#}", path.display(), err);
        }
    }
    // The next ballot, or a minute.
    let next = st.reports.values().filter(|r| r.stage == Stage::Sending).flat_map(|r| r.queue.iter().map(|q| q.at)).min();
    next.map(|n| (n - now()).clamp(1, 60)).unwrap_or(60) as u64
}

/// The latest report, for `status`.
pub fn latest(o: &Opts) -> Option<Report> {
    State::load(&state_path(o)).reports.values().next_back().cloned()
}
