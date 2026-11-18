//! A dedicated observer (`OBS-…` code): each day (UTC), shortly after
//! midnight, the day before goes in one report authenticated by the code
//! (`POST /v1/observe`); the server publishes each day's items without
//! threshold. No state: the server counts a day once per observer and
//! answers "already reported" after.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use peersig_proto::wire::{ObserverReport, OBSERVER_LATE_DAYS, OBSERVER_MAX_ITEMS};
use peersig_proto::{EpochSpec, Item};

use crate::{check_logs, code_label, date, now, print_items, Opts};

/// Seconds after midnight UTC before reporting the day before: the probe
/// writes its server-name records every 5 minutes.
const AFTER_MIDNIGHT: i64 = 15 * 60;
const RETRY: i64 = 10 * 60;

/// yesterday, today, or YYYY-MM-DD, as a day number.
pub fn parse_day(days: EpochSpec, today: u32, s: &str) -> Result<u32> {
    match s {
        "today" => Ok(today),
        "yesterday" => today.checked_sub(1).context("the collection started today"),
        _ => {
            let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").context("--day: yesterday, today or YYYY-MM-DD")?;
            days.at(d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()).context("--day: before the collection started")
        }
    }
}

pub enum Sent {
    Counted(usize, String),
    Already,
    Empty,
}

/// The day layout and today, from the server.
async fn days(o: &Opts) -> Result<(EpochSpec, u32)> {
    let days = o.config().await?.epochs.days();
    Ok((days, days.at(now()).context("the collection has not started")?))
}

/// The items of `day` that are sent: exact, without those left out, the
/// most seen first, at most what one report may carry.
fn kept(o: &Opts, days: EpochSpec, day: u32) -> Vec<Item> {
    let items: Vec<Item> = o.items(days, day, true).into_iter().filter(|(_, out)| !out).map(|(ob, _)| ob.item).collect();
    if items.len() > OBSERVER_MAX_ITEMS {
        eprintln!("{}: {} items, only the {} most seen are sent", date(days, day), items.len(), OBSERVER_MAX_ITEMS);
    }
    items.into_iter().take(OBSERVER_MAX_ITEMS).collect()
}

pub async fn report(o: &Opts, code: &str, days: EpochSpec, day: u32) -> Result<Sent> {
    let items = kept(o, days, day);
    if items.is_empty() {
        return Ok(Sent::Empty);
    }
    let r = ObserverReport { code: code.to_string(), day, items };
    // Direct to the server: the code says who sends it anyway.
    Ok(match o.client()?.observe(&r).await? {
        Some(receipt) => Sent::Counted(receipt.items, receipt.label),
        None => Sent::Already,
    })
}

/// `peersig report` for an observer: one day, now.
pub async fn report_now(o: &Opts, code: &str, day: Option<&str>, dry_run: bool) -> Result<()> {
    check_logs(&o.logs)?;
    let (days, today) = days(o).await?;
    let d = parse_day(days, today, day.unwrap_or("yesterday"))?;
    if d >= today {
        bail!("{} is not over: a day is reported from the next one on", date(days, d));
    }
    if dry_run {
        let items = o.items(days, d, true);
        print_items(&items, true);
        eprintln!("{}: {} items would be sent (dry run)", date(days, d), items.iter().filter(|x| !x.1).count());
        return Ok(());
    }
    match report(o, code, days, d).await? {
        Sent::Counted(n, label) => eprintln!("{}: reported {} items as {}", date(days, d), n, label),
        Sent::Already => eprintln!("{}: already reported", date(days, d)),
        Sent::Empty => eprintln!("{}: nothing to report (was the probe running?)", date(days, d)),
    }
    Ok(())
}

/// The service: each day after midnight UTC, the day before; retries while
/// the server cannot be reached, for as long as it accepts the day.
pub async fn run(o: &Opts, code: &str) -> Result<()> {
    eprintln!("peersig {}: dedicated observer {}, reports daily to {}, from {}", env!("CARGO_PKG_VERSION"), code_label(code), o.server, o.logs.display());
    let mut pending: BTreeMap<u32, i64> = BTreeMap::new();
    let mut last_today: Option<u32> = None;
    loop {
        let wait = match days(o).await {
            Err(e) => {
                eprintln!("{:#}; trying again in {} minutes", e, RETRY / 60);
                RETRY
            }
            Ok((days, today)) => {
                if last_today != Some(today) {
                    // Yesterday, once the probe wrote its last records of it.
                    if let Some(y) = today.checked_sub(1) {
                        pending.entry(y).or_insert(days.start(today) + AFTER_MIDNIGHT);
                    }
                    last_today = Some(today);
                }
                pending.retain(|d, _| {
                    let keep = *d + OBSERVER_LATE_DAYS >= today;
                    if !keep {
                        eprintln!("{}: not reported, the server no longer accepts it", date(days, *d));
                    }
                    keep
                });
                let due: Vec<u32> = pending.iter().filter(|(_, at)| **at <= now()).map(|(d, _)| *d).collect();
                for d in due {
                    let name = date(days, d);
                    match report(o, code, days, d).await {
                        Ok(Sent::Counted(n, label)) => {
                            eprintln!("{}: reported {} items as {}", name, n, label);
                            pending.remove(&d);
                        }
                        Ok(Sent::Already) => {
                            eprintln!("{}: already reported", name);
                            pending.remove(&d);
                        }
                        Ok(Sent::Empty) => {
                            eprintln!("{}: nothing to report (was the probe running?)", name);
                            pending.remove(&d);
                        }
                        // The server refused it: sending it again will not help.
                        Err(e) if format!("{:#}", e).contains("(4") => {
                            eprintln!("{}: refused: {:#}", name, e);
                            pending.remove(&d);
                        }
                        Err(e) => {
                            eprintln!("{}: {:#}; trying again in {} minutes", name, e, RETRY / 60);
                            pending.insert(d, now() + RETRY);
                        }
                    }
                }
                // Wake for the next due day or the next midnight, at least hourly.
                let next_day = days.start(today + 1) + AFTER_MIDNIGHT;
                let next = pending.values().copied().chain([next_day]).min().unwrap_or(next_day);
                (next - now()).clamp(5, 3600)
            }
        };
        tokio::time::sleep(Duration::from_secs(wait as u64)).await;
    }
}
