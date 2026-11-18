//! The app's state and its weekly cycle.
//!
//! During epoch `e + 1` the app reports epoch `e`:
//! 1. review: for `review_hours` the participant sees what will be sent
//!    and can remove items;
//! 2. prepare: get blind tokens (always the same number), and schedule
//!    each item's ballot, and one presence ballot, at a random time over the
//!    next `spread_minutes`;
//! 3. send: one ballot per request, through the relay.
//!
//! Nothing is sent while the app is not running, so the participant always
//! knows. A week whose window passes without the app running is skipped.
//!
//! With an observer's code (`OBS-…`), the computer is a dedicated observer:
//! it reports each day (UTC) during the next, in one request with its code
//! (no tokens, no spreading), and the server publishes the day's items
//! without threshold. The review works the same, 0 hours by default.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use peersig_proto::client::Client;
use peersig_proto::item::{Observed, Skipped};
use peersig_proto::merge;
use peersig_proto::wire::{Ballot, Config, ObserverReceipt, ObserverReport};
use peersig_proto::{code, EpochSpec, Item};

use crate::local::{self, ProbeStatus};
use crate::probe;

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// "Mon 23 Nov", local time.
pub fn day(t: i64) -> String {
    chrono::DateTime::from_timestamp(t, 0)
        .map(|d| d.with_timezone(&chrono::Local).format("%a %-d %b").to_string())
        .unwrap_or_default()
}

/// Seconds after midnight UTC before an observer reports the day before.
pub const OBSERVER_AFTER_MIDNIGHT: i64 = 15 * 60;

/// The UTC day that starts at `t`, named in local time: noon UTC is the
/// same date everywhere between UTC−12 and UTC+12.
pub fn utc_day(t: i64) -> String {
    day(t + 12 * 3600)
}

/// The study's collection server and relay, filled in on the join screen.
/// Participants enrolled elsewhere keep the addresses they joined with.
pub const DEFAULT_SERVER: &str = "https://peersig.org";
pub const DEFAULT_RELAY: &str = "https://relay.peersig.org";

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub server: String,
    pub relay: String,
    pub code: String,
    /// Opt-in: names contacted by non-browser apps.
    pub share_domains: bool,
    pub review_hours: u32,
    pub spread_minutes: u32,
    pub logs_dir: String,
    /// When the participant agreed, RFC 3339.
    pub consented: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            server: DEFAULT_SERVER.into(),
            relay: DEFAULT_RELAY.into(),
            code: String::new(),
            share_domains: false,
            review_hours: 24,
            spread_minutes: 120,
            logs_dir: probe::default_logs_dir().display().to_string(),
            consented: None,
        }
    }
}

impl Settings {
    pub fn enrolled(&self) -> bool {
        !self.server.is_empty() && !self.code.is_empty() && self.consented.is_some()
    }
    pub fn logs(&self) -> PathBuf {
        PathBuf::from(&self.logs_dir)
    }
    pub fn client(&self) -> Result<Client> {
        Client::new(&self.server, Some(self.relay.as_str()).filter(|r| !r.is_empty()))
    }
    /// A dedicated observer: reports daily, published without threshold.
    pub fn observer(&self) -> bool {
        code::is_observer(&self.code)
    }
}

/// The reporting periods: weeks for a participant, days for an observer.
#[derive(Serialize, Clone, Copy, Debug)]
pub struct Cycle {
    pub spec: EpochSpec,
    pub current: u32,
    /// The period being reported; equal to `current` when there is none yet.
    pub report: u32,
    pub observer: bool,
}

impl Cycle {
    pub fn new(cfg: &Config, observer: bool) -> Cycle {
        if !observer {
            return Cycle { spec: cfg.epochs, current: cfg.current_epoch, report: cfg.report_epoch, observer };
        }
        let spec = cfg.epochs.days();
        let current = spec.at(now()).unwrap_or(0);
        Cycle { spec, current, report: current.saturating_sub(1), observer }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReportState {
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
    pub state: ReportState,
    pub review_until: i64,
    /// End of the reporting window.
    pub send_by: i64,
    /// Real items among the ballots (what the server learns from us).
    #[serde(default)]
    pub real: Vec<Item>,
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
    pub started: Option<i64>,
    #[serde(default)]
    pub finished: Option<i64>,
    #[serde(default)]
    pub key_id: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Persisted {
    pub settings: Settings,
    /// Items the participant removed (by key); they are never sent.
    pub excluded: BTreeSet<String>,
    pub reports: BTreeMap<u32, Report>,
}

pub struct Core {
    path: PathBuf,
    pub p: Persisted,
    pub config: Option<(i64, Config)>,
    pub last_error: Option<String>,
    pub probe: ProbeStatus,
    pub cache: local::Cache,
    /// The report (epoch) whose review the participant asked to skip. Only
    /// that one: a click never carries over to a later week's review.
    pub send_now: Option<u32>,
}

/// What the window shows.
#[derive(Serialize, Clone)]
pub struct View {
    pub settings: Settings,
    pub enrolled: bool,
    /// A dedicated observer (daily reports, published without threshold).
    pub observer: bool,
    pub cycle: Option<Cycle>,
    pub probe: ProbeStatus,
    pub probe_installed: bool,
    pub paused: bool,
    pub os: &'static str,
    pub config: Option<Config>,
    pub current: Option<Report>,
    pub reports: Vec<Report>,
    pub last_error: Option<String>,
    pub now: i64,
}

impl Core {
    pub fn load(dir: &Path) -> Core {
        let path = dir.join("state.json");
        let mut p: Persisted = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        // Saved before the defaults existed, and never enrolled.
        if p.settings.server.is_empty() && p.settings.consented.is_none() {
            p.settings.server = DEFAULT_SERVER.into();
            p.settings.relay = DEFAULT_RELAY.into();
        }
        Core { path, p, config: None, last_error: None, probe: ProbeStatus::default(), cache: local::Cache::default(), send_now: None }
    }

    pub fn save(&self) -> Result<()> {
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.p)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn cycle(&self) -> Option<Cycle> {
        Some(Cycle::new(&self.config.as_ref()?.1, self.p.settings.observer()))
    }

    pub fn current_report(&self) -> Option<&Report> {
        self.p.reports.get(&self.cycle()?.report)
    }

    pub fn view(&self) -> View {
        let mut settings = self.p.settings.clone();
        if settings.code.len() > 4 {
            settings.code = format!("••••-••••-{}", &settings.code[settings.code.len() - 4..]);
        }
        View {
            settings,
            enrolled: self.p.settings.enrolled(),
            observer: self.p.settings.observer(),
            cycle: self.cycle(),
            probe: self.probe.clone(),
            probe_installed: probe::installed(),
            paused: probe::is_paused(&self.p.settings.logs()),
            os: std::env::consts::OS,
            config: self.config.as_ref().map(|c| c.1.clone()),
            current: self.current_report().cloned(),
            reports: self.p.reports.values().rev().cloned().map(|mut r| {
                r.queue.clear();
                r
            }).collect(),
            last_error: self.last_error.clone(),
            now: now(),
        }
    }

    /// Items of an epoch (a day for an observer), as the participant sees
    /// them: near-identical items merged, except those the participant
    /// removed. An observer's are not merged: exact versions are what it
    /// is for, it has no token budget, and it is published anyway.
    pub fn items(&mut self, epoch: u32) -> Option<(Vec<Observed>, Skipped)> {
        let cy = self.cycle()?;
        let s = &self.p.settings;
        let (items, skipped) = self.cache.get(&s.logs(), cy.spec, epoch, s.share_domains);
        Some((if cy.observer { items } else { merge::merge(items, &self.p.excluded) }, skipped))
    }

    /// Opens the report of the current reporting epoch if none exists.
    /// Returns true when a new review starts.
    pub fn open_report(&mut self) -> bool {
        let Some(cy) = self.cycle() else { return false };
        // A review the app could not end before its window closed.
        let t = now();
        for r in self.p.reports.values_mut().filter(|r| r.state == ReportState::Review && t >= r.send_by) {
            r.state = ReportState::Failed;
            r.error = Some("the reporting window closed before the report could be sent".into());
        }
        if cy.report >= cy.current || self.p.reports.contains_key(&cy.report) {
            return false;
        }
        let e = cy.report;
        let send_by = cy.spec.end(cy.current);
        // An observer sends its report in one request.
        let spread = if cy.observer { 0 } else { self.p.settings.spread_minutes as i64 * 60 };
        // Leave time to send before the window closes.
        let mut review_until = (now() + self.p.settings.review_hours as i64 * 3600).min(send_by - spread - 3600).max(now());
        // An observer waits for the probe's last records of the day (server
        // names are written every 5 minutes), as `peersig run` does.
        if cy.observer {
            review_until = review_until.max(cy.spec.start(cy.current) + OBSERVER_AFTER_MIDNIGHT);
        }
        self.p.reports.insert(
            e,
            Report {
                epoch: e,
                from: cy.spec.start(e),
                to: cy.spec.end(e),
                state: ReportState::Review,
                review_until,
                send_by,
                real: vec![],
                dropped: 0,
                total: 0,
                sent: 0,
                queue: vec![],
                error: None,
                started: None,
                finished: None,
                key_id: None,
            },
        );
        // Keep a year of history (two months of days for an observer).
        while self.p.reports.len() > 60 {
            let first = *self.p.reports.keys().next().unwrap();
            self.p.reports.remove(&first);
        }
        true
    }

    /// The report whose review is over (or was skipped with "send now").
    pub fn due_for_preparation(&self) -> Option<u32> {
        let r = self.current_report()?;
        (r.state == ReportState::Review && (self.send_now == Some(r.epoch) || now() >= r.review_until)).then_some(r.epoch)
    }

    /// "Send now": skips the review of the report under review. When there
    /// is none, says why nothing can be sent.
    pub fn request_send(&mut self) -> Result<u32, String> {
        if !self.p.settings.enrolled() {
            return Err("Join the study first.".into());
        }
        let Some(cy) = self.cycle() else {
            return Err("PeerSig has not reached the server yet; try again in a minute.".into());
        };
        let next = day(cy.spec.end(cy.current));
        let (this, period) = if cy.observer { ("Today's", "day") } else { ("This week's", "week") };
        let day = |t: i64| if cy.observer { utc_day(t) } else { day(t) };
        match self.current_report() {
            Some(r) if r.state == ReportState::Review => {
                let e = r.epoch;
                self.send_now = Some(e);
                Ok(e)
            }
            Some(r) if r.state == ReportState::Sending => Err(format!("The report is being sent: {} of {} ballots so far.", r.sent, r.total)),
            Some(r) if r.state == ReportState::Sent => {
                Err(format!("The report for the {} of {} was sent. {} can be sent from {}.", period, day(r.from), this, next))
            }
            Some(r) => Err(format!("The report for the {} of {} could not be sent: {}", period, day(r.from), r.error.clone().unwrap_or_default())),
            None if cy.report >= cy.current => Err(format!(
                "Nothing to send yet: a {p} is reported once it is over. The first report covers this {p}; it can be sent from {}.",
                next,
                p = period
            )),
            None => Err("The report is being prepared; try again in a minute.".into()),
        }
    }

    /// Next ballot to send, if its time has come.
    pub fn next_ballot(&mut self) -> Option<(u32, Ballot)> {
        let t = now();
        for r in self.p.reports.values_mut() {
            if r.state != ReportState::Sending {
                continue;
            }
            if t >= r.send_by {
                r.state = ReportState::Failed;
                r.error = Some(format!("the reporting window closed with {} ballots unsent", r.queue.len()));
                r.queue.clear();
                continue;
            }
            if let Some(i) = r.queue.iter().position(|q| q.at <= t) {
                return Some((r.epoch, r.queue[i].ballot.clone()));
            }
        }
        None
    }

    pub fn ballot_sent(&mut self, epoch: u32, nonce: &[u8]) {
        if let Some(r) = self.p.reports.get_mut(&epoch) {
            r.queue.retain(|q| q.ballot.token.nonce != nonce);
            r.sent += 1;
            if r.queue.is_empty() {
                r.state = ReportState::Sent;
                r.finished = Some(now());
            }
        }
    }

    pub fn sending(&self) -> bool {
        self.p.reports.values().any(|r| r.state == ReportState::Sending)
    }
}

/// An observer's report of `day`: every item, in one request with its
/// code. `None`: the server had that day already.
pub async fn observe(settings: &Settings, day: u32, real: Vec<Item>) -> Result<Option<ObserverReceipt>> {
    let client = settings.client()?;
    client.observe(&ObserverReport { code: settings.code.clone(), day, items: real }).await
}

/// Marks an observer's report sent.
pub fn observed(core: &mut Core, day: u32, real: Vec<Item>) {
    let Some(r) = core.p.reports.get_mut(&day) else { return };
    let t = now();
    r.total = real.len();
    r.sent = real.len();
    r.real = real;
    r.state = ReportState::Sent;
    r.started = Some(t);
    r.finished = Some(t);
    r.error = None;
}

pub use peersig_proto::participant::Prepared;

/// Builds the ballots of `cfg.report_epoch` and their tokens
/// (`peersig_proto::participant`). Runs without the core lock: it talks to
/// the server.
pub async fn prepare(settings: &Settings, cfg: &Config, real: Vec<Item>) -> Result<Prepared> {
    peersig_proto::participant::prepare(&mut settings.client()?, &settings.code, settings.share_domains, cfg, real).await
}

/// Installs prepared ballots into the report, each at a random time.
pub fn schedule(core: &mut Core, epoch: u32, p: Prepared, spread: i64) {
    let Some(r) = core.p.reports.get_mut(&epoch) else { return };
    let start = now();
    let mut queue: Vec<Queued> = p
        .plan
        .ballots
        .into_iter()
        .zip(p.tokens)
        .map(|(item, token)| Queued { at: start + (rand::random::<f64>() * spread as f64) as i64, ballot: Ballot { item, token } })
        .collect();
    queue.sort_by_key(|q| q.at);
    r.total = queue.len();
    r.real = p.real;
    r.dropped = p.plan.dropped;
    r.queue = queue;
    r.state = ReportState::Sending;
    r.started = Some(start);
    r.key_id = Some(p.key_id);
    r.error = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use peersig_proto::EpochSpec;
    use peersig_server::{api, db, system_clock, State};
    use std::io::Write;

    /// "Send now" skips the review of the report under review, and only of
    /// that one; with nothing to send, it says why and arms nothing.
    #[test]
    fn send_now_applies_to_one_report() {
        let tmp = std::env::temp_dir().join(format!("peersig-send-now-{}", std::process::id()));
        let mut core = Core::load(&tmp);
        core.p.settings.code = "K7QF-2M9D-XW4P".into();
        core.p.settings.consented = Some("now".into());
        let t = now();
        let cfg = |cur: u32| Config {
            server_version: "test".into(),
            epochs: EpochSpec { origin: t - cur as i64 * EpochSpec::WEEK - 3600, length: EpochSpec::WEEK },
            current_epoch: cur,
            report_epoch: cur.saturating_sub(1),
            token_key: peersig_proto::wire::TokenKey { epoch: 0, public_key: vec![], key_id: "k".into() },
            tokens_per_epoch: 1,
            k_hello: 3,
            k_domain: 5,
            about_url: None,
        };
        // First week of the collection: nothing to report yet.
        core.config = Some((t, cfg(0)));
        let why = core.request_send().unwrap_err();
        assert!(why.contains("Nothing to send yet"), "{}", why);
        assert_eq!(core.send_now, None);
        // A report under review is sent when asked.
        core.config = Some((t, cfg(1)));
        assert!(core.open_report());
        assert_eq!(core.due_for_preparation(), None, "under review");
        assert_eq!(core.request_send(), Ok(0));
        assert_eq!(core.due_for_preparation(), Some(0));
        // The next week's report keeps its review.
        core.p.reports.get_mut(&0).unwrap().state = ReportState::Sent;
        core.config = Some((t, cfg(2)));
        assert!(core.open_report());
        assert_eq!(core.due_for_preparation(), None, "a click last week must not skip this review");
    }

    /// An observer's code: daily periods, one report, counted apart.
    #[tokio::test(flavor = "multi_thread")]
    async fn observer_reports_the_day_before() {
        let t0 = now();
        let origin = t0 - t0.rem_euclid(EpochSpec::DAY) - EpochSpec::WEEK;
        let conn = db::open(":memory:").unwrap();
        let code = db::new_observer_code();
        db::add_observer_code(&conn, &code, "O01").unwrap();
        let st = peersig_server::Settings { epochs: EpochSpec { origin, length: EpochSpec::WEEK }, tokens_per_epoch: 16, k_hello: 3, k_domain: 5, about_url: None };
        let state = State::new(conn, st, system_clock()).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let app = api::router(state.clone());
        tokio::spawn(async move { axum::serve(l, app).await });

        let tmp = std::env::temp_dir().join(format!("peersig-app-observer-{}", std::process::id()));
        let logs = tmp.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let today = (t0 - origin) / EpochSpec::DAY;
        let y = origin + (today - 1) * EpochSpec::DAY + 43200;
        let ts = chrono::DateTime::from_timestamp(y, 0).unwrap().to_rfc3339();
        let name = chrono::DateTime::from_timestamp(y, 0).unwrap().format("peersig-%Y%m%d.jsonl").to_string();
        let mut f = std::fs::File::create(logs.join(name)).unwrap();
        for v in [
            serde_json::json!({"type":"start","os":{"os":"macos","version":"27.0.1"}}),
            serde_json::json!({"type":"hello","ts":ts,"transport":"tcp","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","proc":"curl","app":{"name":"curl","version":"8.7.1","kind":"cli"}}),
        ] {
            writeln!(f, "{}", v).unwrap();
        }
        drop(f);

        let mut core = Core::load(&tmp);
        core.p.settings = Settings {
            server: url,
            relay: String::new(),
            code: code.clone(),
            review_hours: 0,
            logs_dir: logs.display().to_string(),
            consented: Some("now".into()),
            ..Settings::default()
        };
        assert!(core.p.settings.observer());
        let cfg = core.p.settings.client().unwrap().config().await.unwrap();
        core.config = Some((now(), cfg));
        let cy = core.cycle().unwrap();
        assert_eq!((cy.observer, cy.spec.length, cy.current as i64, cy.report as i64), (true, EpochSpec::DAY, today, today - 1));
        assert!(core.open_report());
        let r = core.current_report().unwrap();
        assert!(r.review_until <= (now() + 1).max(cy.spec.start(cy.current) + OBSERVER_AFTER_MIDNIGHT));
        if r.review_until > now() {
            core.request_send().unwrap(); // in the first minutes of the day (UTC)
        }
        let e = core.due_for_preparation().expect("no review");
        assert_eq!(e as i64, today - 1);
        let r = core.current_report().unwrap();
        assert_eq!((r.from, r.to), (cy.spec.start(e), cy.spec.end(e)));
        let real: Vec<Item> = core.items(e).unwrap().0.into_iter().map(|o| o.item).collect();
        assert_eq!(real.len(), 1);
        assert!(observe(&core.p.settings, e, real.clone()).await.unwrap().is_some());
        observed(&mut core, e, real.clone());
        assert_eq!(core.current_report().unwrap().state, ReportState::Sent);
        assert!(core.request_send().unwrap_err().contains("Today's can be sent from"));
        // Sent again (a lost answer): not counted twice.
        assert!(observe(&core.p.settings, e, real).await.unwrap().is_none());
        let (observers, items) = db::observed_day(&state.db.lock().unwrap(), e).unwrap();
        assert_eq!((observers, items.len()), (1, 1));
        let counts: i64 = state.db.lock().unwrap().query_row("SELECT COUNT(*) FROM counts", [], |r| r.get(0)).unwrap();
        assert_eq!(counts, 0, "an observer's items never reach the participants' counts");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A week of logs, reviewed, prepared, sent: what reaches the server.
    #[tokio::test(flavor = "multi_thread")]
    async fn weekly_report_reaches_the_server() {
        let t0 = now();
        let conn = db::open(":memory:").unwrap();
        let code = db::new_code();
        db::add_code(&conn, &code, "P01").unwrap();
        let st = peersig_server::Settings {
            epochs: EpochSpec { origin: t0 - 1500, length: 1000 },
            tokens_per_epoch: 16,
            k_hello: 1,
            k_domain: 1,
            about_url: None,
        };
        let state = State::new(conn, st, system_clock()).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let app = api::router(state.clone());
        tokio::spawn(async move { axum::serve(l, app).await });

        // Probe logs: epoch 0 is [t0 - 1500, t0 - 500).
        let tmp = std::env::temp_dir().join(format!("peersig-app-test-{}", std::process::id()));
        let logs = tmp.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let ts = chrono::DateTime::from_timestamp(t0 - 1000, 0).unwrap().to_rfc3339();
        let day = chrono::Local::now().format("%Y%m%d");
        let mut f = std::fs::File::create(logs.join(format!("peersig-{}.jsonl", day))).unwrap();
        let hello = |app: &str, kind: &str, ja4: &str| {
            serde_json::json!({"type":"hello","ts":ts,"transport":"tcp","ja4":ja4,"src":"10.0.0.2:5000","dst":"1.2.3.4:443",
                "proc":"helper","app":{"name":app,"version":"1.0","kind":kind}})
        };
        for v in [
            serde_json::json!({"type":"start","os":{"os":"macos","version":"27.0.1"}}),
            hello("Kept", "app", "t13d1516h2_8daaf6152771_e5627efa2ab1"),
            hello("Removed", "app", "t13d1516h2_8daaf6152771_000000000001"),
            hello("Nobody", "unknown", "t13d1516h2_8daaf6152771_000000000002"),
            serde_json::json!({"type":"domain","last":ts,"app":"Microsoft Defender","app_kind":"app","domain":"eu-v20.events.data.microsoft.com",
                "via":["sni"],"ja4":["t13d3012h1_1d37bd780c83_882d495ac381"],"count":2}),
            serde_json::json!({"type":"domain","last":ts,"app":"Safari","app_kind":"browser","domain":"news.example.org",
                "via":["sni"],"ja4":["t13d1516h2_8daaf6152771_e5627efa2ab1"],"count":1}),
        ] {
            writeln!(f, "{}", v).unwrap();
        }
        drop(f);

        let mut core = Core::load(&tmp);
        core.p.settings = Settings {
            server: url,
            relay: String::new(),
            code: code.to_lowercase(),
            share_domains: true,
            review_hours: 0,
            spread_minutes: 5,
            logs_dir: logs.display().to_string(),
            consented: Some("now".into()),
            ..Settings::default()
        };
        let cfg = core.p.settings.client().unwrap().config().await.unwrap();
        assert_eq!((cfg.current_epoch, cfg.report_epoch), (1, 0));
        core.config = Some((now(), cfg.clone()));
        assert!(core.open_report());
        assert!(!core.open_report(), "one report per epoch");

        let (obs, skipped) = core.items(0).unwrap();
        assert_eq!(obs.len(), 3, "{:?}", obs.iter().map(|o| o.item.label()).collect::<Vec<_>>());
        assert_eq!((skipped.unattributed, skipped.browser_domains), (1, 1));
        let removed = obs.iter().find(|o| o.item.label().contains("Removed")).unwrap().key.clone();
        core.p.excluded.insert(removed.clone());

        let e = core.due_for_preparation().expect("review of 0 h is over");
        let real: Vec<Item> = obs.into_iter().filter(|o| !core.p.excluded.contains(&o.key)).map(|o| o.item).collect();
        let p = prepare(&core.p.settings, &cfg, real).await.unwrap();
        schedule(&mut core, e, p, 0);
        let mut client = core.p.settings.client().unwrap();
        while let Some((e, b)) = core.next_ballot() {
            client.ballot(&b).await.unwrap();
            core.ballot_sent(e, &b.token.nonce);
        }
        let r = core.p.reports.get(&0).unwrap();
        assert_eq!(r.state, ReportState::Sent);
        assert_eq!((r.real.len(), r.total, r.sent), (2, 3, 3));
        core.save().unwrap();

        let counted: Vec<String> = {
            let db = state.db.lock().unwrap();
            let mut q = db.prepare("SELECT item FROM counts").unwrap();
            let v = q.query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap).collect();
            v
        };
        assert_eq!(counted.len(), 3, "{:?}", counted);
        assert!(!counted.contains(&removed), "a removed item reached the server");
        assert!(counted.iter().any(|k| k.contains("eu-v20.events.data.microsoft.com")));
        assert!(!counted.iter().any(|k| k.contains("news.example.org") || k.contains("10.0.0.2") || k.contains("helper")));
        // The tokens asked for are always the full budget.
        let issued: u32 = state.db.lock().unwrap().query_row("SELECT tokens FROM issuance", [], |r| r.get(0)).unwrap();
        assert_eq!(issued, 16);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
