//! `peersig-observer`: a dedicated observer from the command line, for
//! machines without a desktop (lab servers) or that should not need one.
//!
//! The probe (`peersig-probe run --dir <logs>`) captures and writes its
//! daily logs; this program reads them and, once a day (UTC), sends the
//! previous day's items to the server in one report authenticated by the
//! observer's code (`OBS-XXXX-XXXX-XXXX`, from `peersig-server codes add
//! --observer`). The server publishes each day's items without threshold:
//! use it only on machines whose traffic may be published. See
//! docs/observers.md.
//!
//! The `peersig-observer` package (.deb, .rpm) installs both with their
//! systemd units; `configure` writes `/etc/peersig/observer.conf` (see
//! [`config`]) and starts them.

mod config;
mod setup;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use peersig_proto::client::Client;
use peersig_proto::item::Observed;
use peersig_proto::wire::{ObserverReport, OBSERVER_LATE_DAYS, OBSERVER_MAX_ITEMS};
use peersig_proto::{code, logs, EpochSpec, Item};

#[derive(Parser)]
#[command(name = "peersig-observer", version, about = "PeerSig dedicated observer: reports this machine's items daily")]
struct Cli {
    #[command(flatten)]
    opts: Opts,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Opts {
    /// Settings file (KEY=VALUE), read before the options and the
    /// environment, which override it.
    #[arg(long, global = true, env = "PEERSIG_CONFIG", default_value = config::DEFAULT_PATH)]
    config: PathBuf,
    /// Collection server.
    #[arg(long, global = true, env = "PEERSIG_SERVER", default_value = "https://peersig.org")]
    server: String,
    /// The observer's code (OBS-XXXX-XXXX-XXXX). Prefer --code-file: a
    /// command line is visible to every user of the machine.
    #[arg(long, global = true, env = "PEERSIG_CODE", hide_env_values = true)]
    code: Option<String>,
    /// A file holding the code.
    #[arg(long, global = true, env = "PEERSIG_CODE_FILE")]
    code_file: Option<PathBuf>,
    /// The probe's log directory (`peersig-probe run --dir`).
    #[arg(long, global = true, env = "PEERSIG_LOGS", default_value = "/var/lib/peersig/logs")]
    logs: PathBuf,
    /// Also send the server names (SNI) non-browser applications connect
    /// to, each with its JA4.
    #[arg(long, global = true, env = "PEERSIG_SHARE_DOMAINS")]
    share_domains: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Show the items of a day, as they would be sent.
    Items {
        /// yesterday, today, or YYYY-MM-DD (UTC days).
        #[arg(long, default_value = "yesterday")]
        day: String,
        /// One JSON item per line: exactly what is sent.
        #[arg(long)]
        json: bool,
    },
    /// Send the report of one day (yesterday by default). A day already
    /// reported is not counted twice.
    Report {
        /// yesterday, or YYYY-MM-DD: one of the last 7 days.
        #[arg(long, default_value = "yesterday")]
        day: String,
        /// Show what would be sent, send nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Keep running: report each day shortly after midnight UTC, retrying
    /// while the server cannot be reached.
    Run,
    /// Set this machine up as an observer: check the code with the
    /// server, write the settings file, start the services. Asks for what
    /// it is not given.
    Configure {
        /// Do not send server names (the default unless --share-domains),
        /// whatever the settings file says.
        #[arg(long)]
        no_share_domains: bool,
        /// Do not check the code with the server first.
        #[arg(long)]
        no_check: bool,
        /// Write the settings, start nothing.
        #[arg(long)]
        no_start: bool,
    },
    /// The settings, the code's observer and last report, the probe, the
    /// services.
    Status,
}

/// Minutes after midnight UTC before reporting the day before: the probe
/// writes its server-name records every 5 minutes.
const AFTER_MIDNIGHT: i64 = 15 * 60;
const RETRY: i64 = 10 * 60;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn day_name(days: EpochSpec, d: u32) -> String {
    chrono::DateTime::from_timestamp(days.start(d), 0).map(|t| t.date_naive().to_string()).unwrap_or_default()
}

/// yesterday, today, or YYYY-MM-DD, as a day number.
fn parse_day(days: EpochSpec, today: u32, s: &str) -> Result<u32> {
    match s {
        "today" => Ok(today),
        "yesterday" => today.checked_sub(1).context("the collection started today"),
        _ => {
            let d = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").context("--day: yesterday, today or YYYY-MM-DD")?;
            days.at(d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()).context("--day: before the collection started")
        }
    }
}

impl Opts {
    fn code(&self) -> Result<String> {
        let code = match (&self.code, &self.code_file) {
            (Some(c), _) => c.clone(),
            (None, Some(f)) => std::fs::read_to_string(f).with_context(|| f.display().to_string())?,
            (None, None) => bail!("no observer code: run `sudo peersig-observer configure`, or give --code-file"),
        };
        let code = code.trim().to_uppercase();
        if !code::is_observer(&code) {
            bail!("not an observer's code (OBS-XXXX-XXXX-XXXX): participants use the PeerSig app");
        }
        Ok(code)
    }

    fn client(&self) -> Result<Client> {
        Client::new(&self.server, None)
    }

    /// The day layout and today, from the server.
    async fn days(&self) -> Result<(EpochSpec, u32)> {
        let cfg = self.client()?.config().await.with_context(|| format!("cannot reach {}", self.server))?;
        let days = cfg.epochs.days();
        Ok((days, days.at(now()).context("the collection has not started")?))
    }

    /// A day's items, most seen first, at most what one report may carry.
    fn items(&self, days: EpochSpec, day: u32) -> (Vec<Observed>, usize) {
        let (mut obs, _) = logs::collect(&self.logs, days, day, self.share_domains);
        obs.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        let dropped = obs.len().saturating_sub(OBSERVER_MAX_ITEMS);
        obs.truncate(OBSERVER_MAX_ITEMS);
        (obs, dropped)
    }
}

enum Sent {
    Counted(usize, String),
    Already,
    Empty,
}

/// Reads and sends the report of `day`.
async fn report(o: &Opts, code: &str, days: EpochSpec, day: u32) -> Result<Sent> {
    let (obs, dropped) = o.items(days, day);
    if dropped > 0 {
        eprintln!("{}: {} items, only the {} most seen are sent", day_name(days, day), obs.len() + dropped, OBSERVER_MAX_ITEMS);
    }
    if obs.is_empty() {
        return Ok(Sent::Empty);
    }
    let items: Vec<Item> = obs.into_iter().map(|o| o.item).collect();
    let r = ObserverReport { code: code.to_string(), day, items };
    Ok(match o.client()?.observe(&r).await? {
        Some(receipt) => Sent::Counted(receipt.items, receipt.label),
        None => Sent::Already,
    })
}

fn print_items(obs: &[Observed], json: bool) {
    for o in obs {
        if json {
            println!("{}", o.key);
            continue;
        }
        let (what, ja4) = match &o.item {
            Item::Hello { transport, ja4, .. } => (transport.clone(), ja4.clone()),
            Item::Domain { domain, ja4, .. } => (domain.clone(), ja4.clone()),
            Item::Presence { .. } => continue,
        };
        let app = match &o.item {
            Item::Hello { app, .. } | Item::Domain { app, .. } => app,
            Item::Presence { .. } => continue,
        };
        let name = match &app.version {
            Some(v) => format!("{} {}", app.name, v),
            None => app.name.clone(),
        };
        println!("{:>7}  {:<36}  {:<6}  {:<40}  {}", o.count, ja4, app.kind, name, what);
    }
}

async fn run(o: &Opts, code: &str) -> Result<()> {
    eprintln!("peersig-observer {}: {} reports to {}, from {}", env!("CARGO_PKG_VERSION"), code_label(code), o.server, o.logs.display());
    // Days to report, and when to try each next.
    let mut pending: std::collections::BTreeMap<u32, i64> = std::collections::BTreeMap::new();
    let mut last_today: Option<u32> = None;
    loop {
        let wait = match o.days().await {
            Err(e) => {
                eprintln!("{:#}; trying again in {} minutes", e, RETRY / 60);
                RETRY
            }
            Ok((days, today)) => {
                if last_today != Some(today) {
                    // Yesterday, once the probe wrote its last records of it.
                    let at = days.start(today) + AFTER_MIDNIGHT;
                    if let Some(y) = today.checked_sub(1) {
                        pending.entry(y).or_insert(at);
                    }
                    last_today = Some(today);
                }
                pending.retain(|d, _| {
                    let keep = *d + OBSERVER_LATE_DAYS >= today;
                    if !keep {
                        eprintln!("{}: not reported, the server no longer accepts it", day_name(days, *d));
                    }
                    keep
                });
                let due: Vec<u32> = pending.iter().filter(|(_, at)| **at <= now()).map(|(d, _)| *d).collect();
                for d in due {
                    let name = day_name(days, d);
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

/// `OBS-…-XW4P`: enough to tell codes apart in a log.
fn code_label(code: &str) -> String {
    format!("OBS-…-{}", &code[code.len().saturating_sub(4)..])
}

/// Whether this user can list the log directory (it is the probe's
/// user's only).
fn logs_readable(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok()
}

fn check_logs(dir: &Path) -> Result<()> {
    if let Err(e) = std::fs::read_dir(dir) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            bail!("cannot read {}: run as root or as the probe's user (sudo -u peersig peersig-observer ...)", dir.display());
        }
    }
    if logs::files(dir).is_empty() {
        bail!("no probe logs (peersig-<date>.jsonl) in {}: is the probe running (`peersig-observer status`)?", dir.display());
    }
    Ok(())
}

fn main() -> Result<()> {
    // The settings file first, while there is one thread: it only fills
    // in what the environment does not set.
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let loaded = config::load(&config::path_from(&args));
    let cli = Cli::parse_from(args);
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(start(cli, loaded))
}

async fn start(cli: Cli, loaded: config::Loaded) -> Result<()> {
    let o = &cli.opts;
    let configuring = matches!(cli.cmd, Cmd::Configure { .. } | Cmd::Status);
    if let (config::Loaded::Unreadable(why), false) = (&loaded, configuring) {
        eprintln!("{}: run as root or as peersig", why);
    }
    match cli.cmd {
        Cmd::Configure { no_share_domains, no_check, no_start } => {
            setup::configure(o, &loaded, &setup::ConfigureArgs { no_share_domains, no_check, no_start }).await?;
        }
        Cmd::Status => setup::status(o, &loaded).await?,
        Cmd::Items { day, json } => {
            check_logs(&o.logs)?;
            let (days, today) = o.days().await?;
            let d = parse_day(days, today, &day)?;
            let (obs, dropped) = o.items(days, d);
            print_items(&obs, json);
            eprintln!("{}: {} items{}", day_name(days, d), obs.len(), if dropped > 0 { format!(", and {} beyond the limit of one report", dropped) } else { String::new() });
        }
        Cmd::Report { day, dry_run } => {
            check_logs(&o.logs)?;
            let code = o.code()?;
            let (days, today) = o.days().await?;
            let d = parse_day(days, today, &day)?;
            if d >= today {
                bail!("{} is not over: a day is reported from the next one on", day_name(days, d));
            }
            if dry_run {
                let (obs, _) = o.items(days, d);
                print_items(&obs, true);
                eprintln!("{}: {} items would be sent (dry run)", day_name(days, d), obs.len());
                return Ok(());
            }
            match report(o, &code, days, d).await? {
                Sent::Counted(n, label) => eprintln!("{}: reported {} items as {}", day_name(days, d), n, label),
                Sent::Already => eprintln!("{}: already reported", day_name(days, d)),
                Sent::Empty => eprintln!("{}: nothing to report (was the probe running?)", day_name(days, d)),
            }
        }
        Cmd::Run => {
            let code = o.code()?;
            if let Err(e) = check_logs(&o.logs) {
                eprintln!("{:#}", e);
            }
            run(o, &code).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use peersig_server::{api, db, system_clock, Settings, State};
    use std::io::Write;

    /// A day of probe logs, reported once, then refused a second time.
    #[tokio::test(flavor = "multi_thread")]
    async fn reports_yesterday() {
        let t = now();
        let days = EpochSpec { origin: t - t.rem_euclid(EpochSpec::DAY) - 3 * EpochSpec::WEEK, length: EpochSpec::WEEK }.days();
        let today = days.at(t).unwrap();
        let conn = db::open(":memory:").unwrap();
        let code = db::new_observer_code();
        db::add_observer_code(&conn, &code, "O01").unwrap();
        let st = Settings { epochs: EpochSpec { origin: days.origin, length: EpochSpec::WEEK }, tokens_per_epoch: 4, k_hello: 3, k_domain: 5, about_url: None };
        let state = State::new(conn, st, system_clock()).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let router = api::router(state.clone());
        tokio::spawn(async move { axum::serve(l, router).await });

        let dir = std::env::temp_dir().join(format!("peersig-observer-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let y = days.start(today - 1) + 12 * 3600;
        let ts = chrono::DateTime::from_timestamp(y, 0).unwrap().to_rfc3339();
        let file = chrono::DateTime::from_timestamp(y, 0).unwrap().format("peersig-%Y%m%d.jsonl").to_string();
        let mut f = std::fs::File::create(dir.join(file)).unwrap();
        for v in [
            serde_json::json!({"type":"start","os":{"os":"linux","version":"6.8.0"}}),
            serde_json::json!({"type":"hello","ts":ts,"transport":"tcp","ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","proc":"curl","app":{"name":"curl","version":"8.5.0","kind":"cli"}}),
            serde_json::json!({"type":"hello","ts":ts,"transport":"tcp","ja4":"t13d1516h2_8daaf6152771_000000000002","proc":"x","app":{"name":"x","kind":"unknown"}}),
            serde_json::json!({"type":"domain","last":ts,"app":"curl","app_kind":"cli","domain":"api.example.com","via":["sni"],"ja4":["t13d1516h2_8daaf6152771_e5627efa2ab1"],"count":1}),
        ] {
            writeln!(f, "{}", v).unwrap();
        }
        drop(f);

        let o = Opts { config: dir.join("none.conf"), server: url, code: Some(code.to_lowercase()), code_file: None, logs: dir.clone(), share_domains: true };
        let code = o.code().unwrap();
        let (d2, t2) = o.days().await.unwrap();
        assert_eq!((d2, t2), (days, today));
        assert_eq!(parse_day(days, today, "yesterday").unwrap(), today - 1);
        assert_eq!(parse_day(days, today, &day_name(days, today - 2)).unwrap(), today - 2);
        assert!(matches!(report(&o, &code, days, today - 1).await.unwrap(), Sent::Counted(2, ref l) if l == "O01"));
        assert!(matches!(report(&o, &code, days, today - 1).await.unwrap(), Sent::Already));
        assert!(matches!(report(&o, &code, days, today - 2).await.unwrap(), Sent::Empty));
        let (_, counted) = db::observed_day(&state.db.lock().unwrap(), today - 1).unwrap();
        assert_eq!(counted.len(), 2);
        assert!(counted.keys().any(|k| k.contains("api.example.com")) && counted.keys().all(|k| !k.contains("unknown")));
        // Not an observer's code.
        let p = Opts { code: Some("K7QF-2M9D-XW4P".into()), ..o };
        assert!(p.code().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
