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
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use peersig_proto::client::Client;
use peersig_proto::item::{Observed, Skipped};
use peersig_proto::merge;
use peersig_proto::wire::{Ballot, Config, ObserverReceipt, ObserverReport};
use peersig_proto::{code, EpochSpec, Item};

use crate::local::{self, ProbeStatus};
use crate::review::{self, Answers};
use crate::{Host, Shared};

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
    /// Words that would name the person (their company, their town...):
    /// the review shows the items that contain them first, with those of
    /// the account's name. Stay on this device.
    pub flag_words: Vec<String>,
    /// Ask the device's own language model (macOS: Apple Intelligence)
    /// which names could say something sensitive, for the review.
    pub use_model: bool,
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
            // The app's own (`Host::default_logs_dir`), set by `Core::load`.
            logs_dir: String::new(),
            consented: None,
            flag_words: Vec::new(),
            use_model: true,
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
    /// ClientHellos in each daily log (`20261123`), kept after the probe
    /// deletes the log (two weeks), for the total the window shows.
    pub seen: BTreeMap<String, u64>,
}

/// The handshakes counted in the logs, for the window: those not reported
/// yet, and all of them. Read from the logs, not from the probe, whose
/// count starts again with each start (an update, a restart).
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Counts {
    /// Start of the first period not sent yet: the one under review, or
    /// the current one once the last is sent.
    pub since: i64,
    pub pending: u64,
    pub total: u64,
    /// The first day counted (noon, local time).
    pub first: Option<i64>,
}

/// The report under review, for the overview.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Review {
    pub epoch: u32,
    pub items: usize,
    /// Items the review shows first (`review::flags`).
    pub flagged: usize,
}

/// The device's model (`Host::ask_model`), for the window.
#[derive(Serialize, Clone, Debug, Default)]
pub struct Model {
    /// Names of the periods shown that it has looked at, and all of them.
    pub checked: usize,
    pub names: usize,
    pub running: bool,
    /// Why it cannot run (Apple Intelligence off...), or what went wrong.
    pub problem: Option<String>,
    /// Not before this time again, after a problem.
    #[serde(skip)]
    pub retry_at: i64,
}

pub struct Core {
    path: PathBuf,
    /// Why the saved state could not be read as it was, for the window.
    pub state_problem: Option<String>,
    /// False while `state.json` exists but cannot be read: nothing is
    /// saved over it (`retry_load`).
    can_save: bool,
    /// The enrollment as last copied to `enrollment.json`.
    copied: Option<EnrollmentCopy>,
    pub host: Arc<dyn Host>,
    pub p: Persisted,
    pub config: Option<(i64, Config)>,
    pub last_error: Option<String>,
    pub probe: ProbeStatus,
    pub logs: local::SharedLogs,
    /// The report (epoch) whose review the participant asked to skip. Only
    /// that one: a click never carries over to a later week's review.
    pub send_now: Option<u32>,
    /// The account's own words (`local::own_words`).
    pub own: Vec<String>,
    /// What the device's model said (`review::Answers`).
    pub answers: Answers,
    /// Names of the periods shown, for the device's model, most needed
    /// first.
    pub subjects: Vec<String>,
    pub model: Model,
    pub counts: Option<Counts>,
    pub review: Option<Review>,
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
    /// The service runs an older (or other) probe than this app ships.
    pub probe_outdated: bool,
    pub paused: bool,
    pub os: &'static str,
    pub config: Option<Config>,
    pub current: Option<Report>,
    pub reports: Vec<Report>,
    pub last_error: Option<String>,
    /// The saved state could not be read as it was (`Core::load`).
    pub state_problem: Option<String>,
    pub now: i64,
    /// Handshakes not reported yet, and in all.
    pub counts: Option<Counts>,
    /// The report under review: how many items, how many to look at first.
    pub review: Option<Review>,
    /// The device's model, where it has one.
    pub model: Option<Model>,
    /// Words the review looks for: the account's, then the participant's.
    pub own_words: Vec<String>,
}

/// What reading the logs needs, taken from the core under its lock and
/// used without it (`read`): the first read of two weeks of logs takes
/// seconds.
#[derive(Clone)]
pub struct Reader {
    logs: local::SharedLogs,
    dir: PathBuf,
    pub cycle: Cycle,
    share_domains: bool,
    pub excluded: BTreeSet<String>,
}

impl Reader {
    /// Reads what is new in the logs, then runs `f` on them.
    pub fn with<T>(&self, f: impl FnOnce(&peersig_proto::logs::Index) -> T) -> T {
        let mut logs = self.logs.lock().unwrap_or_else(|e| e.into_inner());
        logs.with(&self.dir, self.cycle.spec, self.share_domains, f)
    }

    /// Items of an epoch (a day for an observer), as the participant sees
    /// them: near-identical items merged, except those the participant
    /// removed. An observer's are not merged: exact versions are what it
    /// is for, it has no token budget, and it is published anyway.
    pub fn items(&self, epoch: u32) -> (Vec<Observed>, Skipped) {
        let (items, skipped) = self.with(|i| i.items(epoch));
        (if self.cycle.observer { items } else { merge::merge(items, &self.excluded) }, skipped)
    }
}

/// Runs `f` on the logs, on a thread that may block, without the core's
/// lock. `None` before the server's configuration is known.
pub async fn read<T: Send + 'static>(core: &Shared, f: impl FnOnce(&Reader) -> T + Send + 'static) -> Option<T> {
    let r = core.lock().await.reader()?;
    tokio::task::spawn_blocking(move || f(&r)).await.ok()
}

impl Core {
    pub fn load(dir: &Path, host: Arc<dyn Host>) -> Core {
        let path = dir.join("state.json");
        let Loaded { mut p, problem, can_save } = read_state(&path);
        // Saved before the defaults existed, and never enrolled.
        if p.settings.server.is_empty() && p.settings.consented.is_none() {
            p.settings.server = DEFAULT_SERVER.into();
            p.settings.relay = DEFAULT_RELAY.into();
        }
        if p.settings.logs_dir.is_empty() {
            p.settings.logs_dir = host.default_logs_dir().display().to_string();
        }
        let answers = if host.has_model() { Answers::load(&path) } else { Answers::default() };
        Core {
            path,
            state_problem: problem,
            can_save,
            copied: None,
            host,
            p,
            config: None,
            last_error: None,
            probe: ProbeStatus::default(),
            logs: local::SharedLogs::default(),
            send_now: None,
            own: local::own_words(),
            answers,
            subjects: Vec::new(),
            model: Model::default(),
            counts: None,
            review: None,
        }
    }

    /// While the saved state cannot be read (`can_save` false), tries
    /// again; once it can, takes it, as at start. Returns whether the
    /// state can be saved now.
    pub fn retry_load(&mut self) -> bool {
        if self.can_save {
            return true;
        }
        let Some(dir) = self.path.parent().map(Path::to_path_buf) else { return false };
        let fresh = Core::load(&dir, self.host.clone());
        if !fresh.can_save {
            return false;
        }
        self.p = fresh.p;
        self.state_problem = fresh.state_problem;
        self.can_save = true;
        self.config = None;
        self.counts = None;
        self.review = None;
        true
    }

    /// Where the state is saved (`state.json`).
    pub fn state_path(&self) -> PathBuf {
        self.path.clone()
    }

    /// What reading the logs needs (`read`).
    pub fn reader(&self) -> Option<Reader> {
        Some(Reader {
            logs: self.logs.clone(),
            dir: self.p.settings.logs(),
            cycle: self.cycle()?,
            share_domains: self.p.settings.share_domains,
            excluded: self.p.excluded.clone(),
        })
    }

    /// Words the review looks for (`review::own_words`).
    pub fn own_words(&self) -> Vec<String> {
        review::own_words(&self.own, &self.p.settings.flag_words)
    }

    /// The first period whose handshakes are not reported yet: the one
    /// being reported until its report is sent (or can no longer be), then
    /// the current one.
    pub fn unsent_from(&self, cy: &Cycle) -> u32 {
        if cy.report >= cy.current {
            return cy.current;
        }
        match self.p.reports.get(&cy.report) {
            Some(r) if matches!(r.state, ReportState::Sent | ReportState::Failed) => cy.current,
            _ => cy.report,
        }
    }

    /// Takes in the handshakes counted in each daily log (each kept at its
    /// highest: the probe deletes logs after two weeks), and the count of
    /// those not reported yet. Returns whether a day was added (worth
    /// saving: the last day's count changes all the time).
    pub fn set_counts(&mut self, per_file: &[(String, u64)], since: i64, pending: u64) -> bool {
        let mut new_day = false;
        for (day, n) in per_file {
            let e = self.p.seen.entry(day.clone()).or_insert_with(|| {
                new_day = true;
                0
            });
            *e = (*e).max(*n);
        }
        let first = self.p.seen.keys().next().and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y%m%d").ok()).and_then(|d| {
            d.and_hms_opt(12, 0, 0)?.and_local_timezone(chrono::Local).single().map(|t| t.timestamp())
        });
        self.counts = Some(Counts { since, pending, total: self.p.seen.values().sum(), first });
        new_day
    }

    pub fn save(&mut self) -> Result<()> {
        if !self.can_save {
            anyhow::bail!(
                "PeerSig cannot read its saved state ({}), so it saves nothing over it. Quit PeerSig and start it again.",
                self.path.display()
            );
        }
        write_private(&self.path, &serde_json::to_vec_pretty(&self.p)?)?;
        // The enrollment's own copy, when it changed.
        let copy = EnrollmentCopy::of(&self.p.settings);
        if copy.is_some() && copy != self.copied {
            if let Some(c) = &copy {
                write_private(&EnrollmentCopy::path(&self.path), &serde_json::to_vec_pretty(c)?)?;
            }
            self.copied = copy;
        }
        Ok(())
    }

    /// Leaving the study: the enrollment's copy goes too. Nothing else
    /// removes it.
    pub fn forget_enrollment(&mut self) {
        let _ = std::fs::remove_file(EnrollmentCopy::path(&self.path));
        self.copied = None;
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
            probe_installed: self.host.capture_installed(),
            probe_outdated: self.host.capture_outdated(self.probe.tool.as_deref()),
            paused: self.host.paused(&self.p.settings.logs()),
            os: self.host.os(),
            config: self.config.as_ref().map(|c| c.1.clone()),
            // The window needs no tokens: the queue stays here.
            current: self.current_report().cloned().map(|mut r| {
                r.queue.clear();
                r
            }),
            reports: self.p.reports.values().rev().cloned().map(|mut r| {
                r.queue.clear();
                r
            }).collect(),
            last_error: self.last_error.clone(),
            state_problem: self.state_problem.clone(),
            now: now(),
            counts: self.counts.clone(),
            review: self.review.clone().filter(|r| self.current_report().is_some_and(|c| c.epoch == r.epoch)),
            model: self.host.has_model().then(|| self.model.clone()),
            own_words: self.own_words(),
        }
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

/// Writes `bytes` to `path` through a temporary file (readable by this
/// account only), so the file is always whole.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The enrollment, also kept in a file of its own (`enrollment.json`,
/// next to the state), and put back if the state ever comes without it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
struct EnrollmentCopy {
    server: String,
    relay: String,
    code: String,
    consented: Option<String>,
    share_domains: bool,
}

impl EnrollmentCopy {
    fn path(state: &Path) -> PathBuf {
        state.with_file_name("enrollment.json")
    }

    fn of(s: &Settings) -> Option<EnrollmentCopy> {
        s.enrolled().then(|| EnrollmentCopy {
            server: s.server.clone(),
            relay: s.relay.clone(),
            code: s.code.clone(),
            consented: s.consented.clone(),
            share_domains: s.share_domains,
        })
    }

    fn read(state: &Path) -> Option<EnrollmentCopy> {
        let c: EnrollmentCopy = serde_json::from_slice(&std::fs::read(Self::path(state)).ok()?).ok()?;
        (!c.server.is_empty() && !c.code.is_empty() && c.consented.is_some()).then_some(c)
    }

    fn restore(self, s: &mut Settings) {
        s.server = self.server;
        s.relay = self.relay;
        s.code = self.code;
        s.consented = self.consented;
        s.share_domains = self.share_domains;
    }
}

/// What `read_state` found.
struct Loaded {
    p: Persisted,
    problem: Option<String>,
    can_save: bool,
}

/// Reads `state.json`. A missing file is a first start; nothing else may
/// end a participation. An update of PeerSig once started without the
/// participant's code and asked for it again, and what it saved next
/// replaced the state. So:
///
/// - a file that cannot be opened (another program holds it: an
///   antivirus, the copy of PeerSig being replaced) is tried again for a
///   few seconds, then left alone: nothing is saved over it until it can
///   be read (`Core::retry_load`);
/// - a file that is not what this version reads (written by another) is
///   copied aside, and what can be read of it is kept: the enrollment, the
///   items removed, the reports, the counts;
/// - the enrollment has a copy of its own (`EnrollmentCopy`), put back
///   when the state lacks it.
fn read_state(path: &Path) -> Loaded {
    let mut tries = 0;
    let bytes = loop {
        match std::fs::read(path) {
            Ok(b) => break Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break None,
            Err(e) => {
                tries += 1;
                if tries >= 10 {
                    let mut p = Persisted::default();
                    if let Some(c) = EnrollmentCopy::read(path) {
                        c.restore(&mut p.settings);
                    }
                    return Loaded {
                        p,
                        problem: Some(format!(
                            "PeerSig cannot read its saved state ({}: {}). It saves nothing until it can, and tries again every 30 seconds.",
                            path.display(),
                            e
                        )),
                        can_save: false,
                    };
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
    };
    let (mut p, mut problem) = match bytes {
        None => (Persisted::default(), None),
        Some(b) => match serde_json::from_slice::<Persisted>(&b) {
            Ok(p) => (p, None),
            Err(e) => {
                let aside = path.with_file_name(format!("state.unreadable-{}.json", now()));
                let kept = std::fs::write(&aside, &b).is_ok();
                #[cfg(unix)]
                if kept {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&aside, std::fs::Permissions::from_mode(0o600));
                }
                let p = salvage(&b).unwrap_or_default();
                let copy = if kept { format!(" A copy of it is kept as {}.", aside.display()) } else { String::new() };
                (p, Some(format!("PeerSig could not read all of its saved state ({}), and kept what it could.{}", e, copy)))
            }
        },
    };
    if !p.settings.enrolled() {
        if let Some(c) = EnrollmentCopy::read(path) {
            c.restore(&mut p.settings);
            problem.get_or_insert_with(|| "PeerSig's saved state had no enrollment: it was put back from its copy (enrollment.json).".into());
        }
    }
    Loaded { p, problem, can_save: true }
}

/// What can be read of a state this version does not read whole: each
/// setting, report and count on its own.
fn salvage(bytes: &[u8]) -> Option<Persisted> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let v = v.as_object()?;
    let mut p = Persisted::default();
    if let Some(s) = v.get("settings") {
        p.settings = lenient(s);
    }
    if let Some(a) = v.get("excluded").and_then(|x| x.as_array()) {
        p.excluded = a.iter().filter_map(|k| k.as_str().map(String::from)).collect();
    }
    if let Some(m) = v.get("reports").and_then(|x| x.as_object()) {
        for (k, r) in m {
            if let (Ok(e), Ok(r)) = (k.parse::<u32>(), serde_json::from_value::<Report>(r.clone())) {
                p.reports.insert(e, r);
            }
        }
    }
    if let Some(m) = v.get("seen").and_then(|x| x.as_object()) {
        p.seen = m.iter().filter_map(|(d, n)| Some((d.clone(), n.as_u64()?))).collect();
    }
    Some(p)
}

/// `T` from `v`, field by field: a field this version cannot read keeps
/// its default, the others are kept.
fn lenient<T: Serialize + serde::de::DeserializeOwned + Default>(v: &serde_json::Value) -> T {
    let mut base = match serde_json::to_value(T::default()) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => return T::default(),
    };
    for (k, x) in v.as_object().into_iter().flatten() {
        let mut trial = base.clone();
        trial.insert(k.clone(), x.clone());
        if serde_json::from_value::<T>(serde_json::Value::Object(trial.clone())).is_ok() {
            base = trial;
        }
    }
    serde_json::from_value(serde_json::Value::Object(base)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::host;
    use peersig_proto::EpochSpec;
    use peersig_server::{api, db, system_clock, State};
    use std::io::Write;

    fn enrolled_state(dir: &Path) -> Core {
        let _ = std::fs::remove_dir_all(dir);
        let mut core = Core::load(dir, host());
        core.p.settings.code = "K7QF-2M9D-XW4P".into();
        core.p.settings.consented = Some("2026-11-17T12:09:18+00:00".into());
        core.p.excluded.insert("removed-item".into());
        core.p.seen.insert("20261117".into(), 30735);
        core.save().unwrap();
        core
    }

    /// A state this version cannot read whole (here, a setting of another
    /// type, as a future or past version could write) keeps the
    /// enrollment, the items removed and the counts, and a copy of the
    /// file is kept aside.
    #[test]
    fn unparsable_state_keeps_the_enrollment() {
        let tmp = std::env::temp_dir().join(format!("peersig-salvage-{}", std::process::id()));
        enrolled_state(&tmp);
        // The copy would put the enrollment back on its own: this test is
        // about the state file.
        std::fs::remove_file(tmp.join("enrollment.json")).unwrap();
        let path = tmp.join("state.json");
        let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["settings"]["review_hours"] = serde_json::json!("a day");
        v["reports"] = serde_json::json!({"3": {"epoch": "three"}});
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(serde_json::from_slice::<Persisted>(&std::fs::read(&path).unwrap()).is_err());

        let core = Core::load(&tmp, host());
        assert!(core.p.settings.enrolled());
        assert_eq!(core.p.settings.code, "K7QF-2M9D-XW4P");
        assert_eq!(core.p.settings.review_hours, 24);
        assert!(core.p.excluded.contains("removed-item"));
        assert_eq!(core.p.seen.get("20261117"), Some(&30735));
        assert!(core.p.reports.is_empty());
        assert!(core.state_problem.as_deref().is_some_and(|p| p.contains("state.unreadable-")), "{:?}", core.state_problem);
        let aside = std::fs::read_dir(&tmp).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with("state.unreadable-")).count();
        assert_eq!(aside, 1);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The enrollment's copy comes back when the state lost it (a broken
    /// file, a file replaced); leaving removes the copy.
    #[tokio::test]
    async fn enrollment_copy() {
        let tmp = std::env::temp_dir().join(format!("peersig-copy-{}", std::process::id()));
        enrolled_state(&tmp);
        std::fs::write(tmp.join("state.json"), b"{\"settings\": {\"code\": \"\"").unwrap();
        let core = Core::load(&tmp, host());
        assert_eq!(core.p.settings.code, "K7QF-2M9D-XW4P");
        assert!(core.p.settings.enrolled() && core.state_problem.is_some());

        std::fs::remove_file(tmp.join("state.json")).unwrap();
        let core = Core::load(&tmp, host());
        assert!(core.p.settings.enrolled());
        assert!(core.state_problem.as_deref().is_some_and(|p| p.contains("enrollment.json")));

        let shared: crate::Shared = Arc::new(tokio::sync::Mutex::new(core));
        crate::commands::leave(&shared, false).await.unwrap();
        assert!(!tmp.join("enrollment.json").exists());
        let core = Core::load(&tmp, host());
        assert!(!core.p.settings.enrolled() && core.state_problem.is_none());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// A state that exists but cannot be read is never replaced: nothing
    /// is saved until it can be read, and then it is taken as it is.
    #[test]
    fn unreadable_state_is_not_replaced() {
        let tmp = std::env::temp_dir().join(format!("peersig-unreadable-{}", std::process::id()));
        let saved = std::fs::read(enrolled_state(&tmp).state_path()).unwrap();
        let path = tmp.join("state.json");
        std::fs::remove_file(&path).unwrap();
        // A directory in its place: reading fails, and not with NotFound.
        std::fs::create_dir(&path).unwrap();
        let mut core = Core::load(&tmp, host());
        assert!(core.state_problem.is_some());
        // The copy gives the enrollment back for the window...
        assert!(core.p.settings.enrolled());
        // ...but nothing is written.
        assert!(core.save().is_err());
        assert!(!core.retry_load());
        std::fs::remove_dir(&path).unwrap();
        std::fs::write(&path, &saved).unwrap();
        assert!(core.retry_load());
        assert!(core.state_problem.is_none());
        assert!(core.p.excluded.contains("removed-item"));
        core.save().unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// "Send now" skips the review of the report under review, and only of
    /// that one; with nothing to send, it says why and arms nothing.
    #[test]
    fn send_now_applies_to_one_report() {
        let tmp = std::env::temp_dir().join(format!("peersig-send-now-{}", std::process::id()));
        let mut core = Core::load(&tmp, host());
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

    /// The handshakes not sent yet start from the week under review until
    /// its report is sent, then from the current week; the total keeps the
    /// days whose logs the probe deleted, and never goes down.
    #[test]
    fn counts_start_again_after_a_report() {
        let tmp = std::env::temp_dir().join(format!("peersig-counts-{}", std::process::id()));
        let mut core = Core::load(&tmp, host());
        let t = now();
        let spec = EpochSpec { origin: t - EpochSpec::WEEK - 3600, length: EpochSpec::WEEK };
        let cy = Cycle { spec, current: 1, report: 0, observer: false };
        assert_eq!(core.unsent_from(&cy), 0, "no report yet: last week is not sent");
        let r = Report {
            epoch: 0, from: spec.start(0), to: spec.end(0), state: ReportState::Review, review_until: t, send_by: spec.end(1),
            real: vec![], dropped: 0, total: 0, sent: 0, queue: vec![], error: None, started: None, finished: None, key_id: None,
        };
        core.p.reports.insert(0, r);
        assert_eq!(core.unsent_from(&cy), 0, "under review");
        core.p.reports.get_mut(&0).unwrap().state = ReportState::Sent;
        assert_eq!(core.unsent_from(&cy), 1, "sent: the count starts again");
        assert_eq!(core.unsent_from(&Cycle { spec, current: 0, report: 0, observer: false }), 0, "first week");

        let day = |d: &str, n: u64| (d.to_string(), n);
        assert!(core.set_counts(&[day("20261117", 10), day("20261118", 5)], spec.start(1), 5));
        assert!(!core.set_counts(&[day("20261117", 10), day("20261118", 7)], spec.start(1), 7), "the same days");
        // The 17th's log is gone: its count stays.
        assert!(core.set_counts(&[day("20261118", 7), day("20261119", 1)], spec.start(1), 8));
        let c = core.counts.clone().unwrap();
        assert_eq!((c.pending, c.total), (8, 18));
        assert_eq!(day_of(c.first.unwrap()), "20261117");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn day_of(t: i64) -> String {
        chrono::DateTime::from_timestamp(t, 0).unwrap().with_timezone(&chrono::Local).format("%Y%m%d").to_string()
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

        let mut core = Core::load(&tmp, host());
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
        let real: Vec<Item> = core.reader().unwrap().items(e).0.into_iter().map(|o| o.item).collect();
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

        let mut core = Core::load(&tmp, host());
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

        let (obs, skipped) = core.reader().unwrap().items(0);
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
