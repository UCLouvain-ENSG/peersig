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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use peersig_proto::client::Client;
use peersig_proto::item::{Observed, Skipped};
use peersig_proto::plan;
use peersig_proto::token;
use peersig_proto::wire::{Ballot, Config, IssueRequest};
use peersig_proto::Item;

use crate::local::{self, ProbeStatus};
use crate::probe;

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
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
    /// Ask the worker to send the current report now.
    pub send_now: bool,
}

/// What the window shows.
#[derive(Serialize, Clone)]
pub struct View {
    pub settings: Settings,
    pub enrolled: bool,
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
        Core { path, p, config: None, last_error: None, probe: ProbeStatus::default(), cache: local::Cache::default(), send_now: false }
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

    pub fn current_report(&self) -> Option<&Report> {
        let cfg = &self.config.as_ref()?.1;
        self.p.reports.get(&cfg.report_epoch)
    }

    pub fn view(&self) -> View {
        let mut settings = self.p.settings.clone();
        if settings.code.len() > 4 {
            settings.code = format!("••••-••••-{}", &settings.code[settings.code.len() - 4..]);
        }
        View {
            settings,
            enrolled: self.p.settings.enrolled(),
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

    /// Items of an epoch, as the participant sees them.
    pub fn items(&mut self, epoch: u32) -> Option<(Vec<Observed>, Skipped)> {
        let spec = self.config.as_ref()?.1.epochs;
        let s = &self.p.settings;
        Some(self.cache.get(&s.logs(), spec, epoch, s.share_domains))
    }

    /// Opens the report of the current reporting epoch if none exists.
    /// Returns true when a new review starts.
    pub fn open_report(&mut self) -> bool {
        let Some((_, cfg)) = &self.config else { return false };
        if cfg.report_epoch >= cfg.current_epoch || self.p.reports.contains_key(&cfg.report_epoch) {
            return false;
        }
        let e = cfg.report_epoch;
        let send_by = cfg.epochs.end(cfg.current_epoch);
        let spread = self.p.settings.spread_minutes as i64 * 60;
        // Leave time to send before the window closes.
        let review_until = (now() + self.p.settings.review_hours as i64 * 3600).min(send_by - spread - 3600).max(now());
        self.p.reports.insert(
            e,
            Report {
                epoch: e,
                from: cfg.epochs.start(e),
                to: cfg.epochs.end(e),
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
        // Keep a year of history.
        while self.p.reports.len() > 60 {
            let first = *self.p.reports.keys().next().unwrap();
            self.p.reports.remove(&first);
        }
        true
    }

    /// The report whose review is over (or was skipped with "send now").
    pub fn due_for_preparation(&self) -> Option<u32> {
        let r = self.current_report()?;
        (r.state == ReportState::Review && (self.send_now || now() >= r.review_until)).then_some(r.epoch)
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

/// Builds the ballots of `epoch` and its tokens. Runs without the core
/// lock: it talks to the server.
pub struct Prepared {
    pub real: Vec<Item>,
    pub plan: plan::Plan,
    pub tokens: Vec<peersig_proto::Token>,
    pub key_id: String,
}

pub async fn prepare(settings: &Settings, cfg: &Config, real: Vec<Item>) -> Result<Prepared> {
    let e = cfg.report_epoch;
    let mut client = settings.client()?;
    // Fetched anonymously: the same key everyone gets.
    let fresh = client.config().await.context("configuration")?;
    if fresh.report_epoch != e || fresh.token_key != cfg.token_key {
        bail!("the server's configuration changed; will retry");
    }
    let budget = cfg.tokens_per_epoch as usize;
    let pl = plan::plan(e, &real, settings.share_domains, budget, &mut || rand::random::<f64>());
    // Always the full budget: the server must not learn how many items we have.
    let blinded = token::blind(&cfg.token_key.public_key, e, budget)?;
    let resp = client
        .issue(&IssueRequest { code: settings.code.clone(), epoch: e, blinded: blinded.iter().map(|b| b.blind_message.clone()).collect() })
        .await
        .context("tokens")?;
    // Checks every signature against the key fetched anonymously.
    let tokens = token::finalize(&cfg.token_key.public_key, &blinded, &resp.signatures)?;
    let real_keys: BTreeSet<String> = real.iter().map(Item::key).collect();
    let real_sent = pl.ballots.iter().filter(|i| real_keys.contains(&i.key())).cloned().collect();
    Ok(Prepared { real: real_sent, plan: pl, tokens, key_id: resp.key_id })
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
