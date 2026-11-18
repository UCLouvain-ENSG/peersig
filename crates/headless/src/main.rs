//! `peersig`: PeerSig without a desktop, for Linux servers and any machine
//! that should not need the app.
//!
//! The probe (`peersig-probe run --dir <logs>`) captures and writes its
//! daily logs; `peersig run` reads them and reports, with the code from
//! the study:
//!
//! - a participant's code: once a week, as the app does
//!   ([`participant`]): the week's items wait `review_hours` (`peersig
//!   items` lists them, `peersig exclude` leaves one out), then each goes
//!   as a separate anonymous ballot, with a blind-signed token, through the
//!   relay, at a random time;
//! - a dedicated observer's code (`OBS-…`): once a day, in one report the
//!   server knows comes from that observer, published without threshold
//!   ([`observer`]).
//!
//! The `peersig-headless` package (.deb, .rpm) installs both programs and
//! their systemd units; `configure` writes `/etc/peersig/peersig.conf`
//! ([`config`]) and starts them. See docs/headless.md.

mod config;
mod observer;
mod participant;
mod setup;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use peersig_proto::client::Client;
use peersig_proto::item::Observed;
use peersig_proto::wire::Config;
use peersig_proto::{code, EpochSpec, Item};

#[derive(Parser)]
#[command(name = "peersig", version, about = "PeerSig without a desktop: reports what the probe saw, as a participant or a dedicated observer")]
struct Cli {
    #[command(flatten)]
    opts: Opts,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
pub struct Opts {
    /// Settings file (KEY=VALUE), read before the options and the
    /// environment, which override it.
    #[arg(long, global = true, env = "PEERSIG_CONFIG", default_value = config::DEFAULT_PATH)]
    pub config: PathBuf,
    /// Collection server.
    #[arg(long, global = true, env = "PEERSIG_SERVER", default_value = "https://peersig.org")]
    pub server: String,
    /// Oblivious HTTP relay: it hides this machine's address from the
    /// server. "none" for no relay.
    #[arg(long, global = true, env = "PEERSIG_RELAY", default_value = "https://relay.peersig.org")]
    pub relay: String,
    /// The enrollment code: a participant's (XXXX-XXXX-XXXX) or a dedicated
    /// observer's (OBS-XXXX-XXXX-XXXX). Prefer the settings file or
    /// --code-file: a command line is visible to every user.
    #[arg(long, global = true, env = "PEERSIG_CODE", hide_env_values = true)]
    pub code: Option<String>,
    /// A file holding the code.
    #[arg(long, global = true, env = "PEERSIG_CODE_FILE")]
    pub code_file: Option<PathBuf>,
    /// The probe's log directory (`peersig-probe run --dir`).
    #[arg(long, global = true, env = "PEERSIG_LOGS", default_value = "/var/lib/peersig/logs")]
    pub logs: PathBuf,
    /// Where `peersig run` keeps its state, and the items left out.
    #[arg(long, global = true, env = "PEERSIG_STATE", default_value = "/var/lib/peersig")]
    pub state: PathBuf,
    /// Also send the server names (SNI) non-browser applications connect
    /// to, each with its JA4.
    #[arg(long, global = true, env = "PEERSIG_SHARE_DOMAINS")]
    pub share_domains: bool,
    /// Participants: hours each week's items wait before they are sent.
    #[arg(long, global = true, env = "PEERSIG_REVIEW_HOURS", default_value_t = 24)]
    pub review_hours: u32,
    /// Participants: minutes over which a week's ballots are spread.
    #[arg(long, global = true, env = "PEERSIG_SPREAD_MINUTES", default_value_t = 120)]
    pub spread_minutes: u32,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set this machine up: check the code with the server, write the
    /// settings file, start the services. Asks for what it is not given.
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
        /// Agree without being asked (no terminal).
        #[arg(long)]
        yes: bool,
    },
    /// The settings, what the code is, the report under way, the probe, the
    /// services.
    Status,
    /// The items of the period being reported (last week for a participant,
    /// yesterday for an observer), as they would be sent.
    Items {
        /// The period so far instead.
        #[arg(long)]
        current: bool,
        /// Observers: this day (YYYY-MM-DD, UTC).
        #[arg(long)]
        day: Option<String>,
        /// One JSON item per line: exactly what is sent.
        #[arg(long)]
        json: bool,
    },
    /// Leave items out (by the id `items` shows): they are never sent.
    Exclude { ids: Vec<String> },
    /// Put items left out back.
    Include { ids: Vec<String> },
    /// Participants: end the review now, the running service sends the
    /// week within a minute. Observers: send a day now (default
    /// yesterday).
    Report {
        /// Observers: this day (YYYY-MM-DD), one of the last 7.
        #[arg(long)]
        day: Option<String>,
        /// Observers: show what would be sent, send nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Keep running (the service): report each week or day.
    Run,
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// YYYY-MM-DD (UTC) of the start of period `e`.
pub fn date(spec: EpochSpec, e: u32) -> String {
    chrono::DateTime::from_timestamp(spec.start(e), 0).map(|t| t.date_naive().to_string()).unwrap_or_default()
}

/// `OBS-…-XW4P`, `…-XW4P`: enough to tell codes apart in a log.
pub fn code_label(code: &str) -> String {
    let tail = &code[code.len().saturating_sub(4)..];
    if code::is_observer(code) {
        format!("OBS-…-{}", tail)
    } else {
        format!("…-{}", tail)
    }
}

/// A short id for an item, for `exclude`.
pub fn item_id(key: &str) -> String {
    peersig_proto::short_hash(key.as_bytes(), 4)
}

impl Opts {
    /// The code, upper case; a participant's or an observer's.
    pub fn code(&self) -> Result<String> {
        let code = match (&self.code, &self.code_file) {
            (Some(c), _) => c.clone(),
            (None, Some(f)) => std::fs::read_to_string(f).with_context(|| f.display().to_string())?,
            (None, None) => bail!("no enrollment code: run `sudo peersig configure`"),
        };
        Ok(code.trim().to_uppercase())
    }

    pub fn relay(&self) -> Option<&str> {
        Some(self.relay.trim()).filter(|r| !r.is_empty() && *r != "none")
    }

    pub fn client(&self) -> Result<Client> {
        Client::new(&self.server, self.relay())
    }

    /// The configuration, fetched anonymously (through the relay).
    pub async fn config(&self) -> Result<Config> {
        self.client()?.config().await.with_context(|| format!("cannot reach {}", self.server))
    }

    fn excluded_path(&self) -> PathBuf {
        self.state.join("excluded")
    }

    /// Items left out (their keys), one per line.
    pub fn excluded(&self) -> BTreeSet<String> {
        std::fs::read_to_string(self.excluded_path()).map(|t| t.lines().filter(|l| !l.is_empty()).map(String::from).collect()).unwrap_or_default()
    }

    pub fn save_excluded(&self, keys: &BTreeSet<String>) -> Result<()> {
        let text: String = keys.iter().map(|k| format!("{}\n", k)).collect();
        write_private(&self.excluded_path(), text.as_bytes())
    }

    /// A period's items, near-identical ones merged for a participant
    /// (exact for an observer), with those left out marked.
    pub fn items(&self, spec: EpochSpec, e: u32, observer: bool) -> Vec<(Observed, bool)> {
        let excluded = self.excluded();
        let (obs, _) = peersig_proto::logs::collect(&self.logs, spec, e, self.share_domains);
        let obs = if observer { obs } else { peersig_proto::merge::merge(obs, &excluded) };
        let mut v: Vec<(Observed, bool)> = obs.into_iter().map(|o| {
            let out = excluded.contains(&o.key);
            (o, out)
        }).collect();
        v.sort_by(|a, b| b.0.count.cmp(&a.0.count).then_with(|| a.0.key.cmp(&b.0.key)));
        v
    }
}

/// Writes a file only its owner reads, owned like its directory (the
/// service's user), whoever runs the command.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().context("no directory")?;
    std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| tmp.display().to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        if let Ok(m) = std::fs::metadata(dir) {
            let _ = std::os::unix::fs::chown(&tmp, Some(m.uid()), Some(m.gid()));
        }
    }
    std::fs::rename(&tmp, path).with_context(|| path.display().to_string())?;
    Ok(())
}

pub fn print_items(items: &[(Observed, bool)], json: bool) {
    for (o, out) in items {
        if json {
            if !out {
                println!("{}", o.key);
            }
            continue;
        }
        let (what, ja4, app) = match &o.item {
            Item::Hello { transport, ja4, app, .. } => (transport.clone(), ja4.clone(), app),
            Item::Domain { domain, ja4, app, .. } => (domain.clone(), ja4.clone(), app),
            Item::Presence { .. } => continue,
        };
        let name = match &app.version {
            Some(v) => format!("{} {}", app.name, v),
            None => app.name.clone(),
        };
        println!(
            "{} {}  {:>7}  {:<36}  {:<6}  {:<40}  {}",
            item_id(&o.key),
            if *out { "out" } else { "   " },
            o.count,
            ja4,
            app.kind,
            name,
            what
        );
    }
}

/// Whether this user can list the log directory (the probe's user's only).
pub fn logs_readable(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok()
}

pub fn check_logs(dir: &Path) -> Result<()> {
    if let Err(e) = std::fs::read_dir(dir) {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            bail!("cannot read {}: run as root or as the probe's user (sudo peersig ...)", dir.display());
        }
    }
    if peersig_proto::logs::files(dir).is_empty() {
        bail!("no probe logs (peersig-<date>.jsonl) in {}: is the probe running (`peersig status`)?", dir.display());
    }
    Ok(())
}

/// Turns ids (or keys) into item keys, among the given items.
fn resolve(ids: &[String], items: &[(Observed, bool)], known: &BTreeSet<String>) -> Result<Vec<String>> {
    ids.iter()
        .map(|id| {
            let id = id.trim().to_lowercase();
            items
                .iter()
                .map(|(o, _)| o.key.clone())
                .chain(known.iter().cloned())
                .find(|k| item_id(k) == id || *k == id)
                .with_context(|| format!("no item {} (ids are in `peersig items`)", id))
        })
        .collect()
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
        eprintln!("{}: run with sudo", why);
    }
    match cli.cmd {
        Cmd::Configure { no_share_domains, no_check, no_start, yes } => {
            setup::configure(o, &loaded, &setup::ConfigureArgs { no_share_domains, no_check, no_start, yes }).await?;
        }
        Cmd::Status => setup::status(o, &loaded).await?,
        Cmd::Items { current, day, json } => {
            check_logs(&o.logs)?;
            let observer = o.code().map(|c| code::is_observer(&c)).unwrap_or(false);
            let cfg = o.config().await?;
            let (spec, e, what) = if observer || day.is_some() {
                let days = cfg.epochs.days();
                let today = days.at(now()).context("the collection has not started")?;
                let d = match (&day, current) {
                    (Some(d), _) => observer::parse_day(days, today, d)?,
                    (None, true) => today,
                    (None, false) => today.checked_sub(1).context("the collection started today")?,
                };
                (days, d, format!("{} (UTC)", date(days, d)))
            } else {
                let e = if current { cfg.current_epoch } else { cfg.report_epoch };
                let w = cfg.epochs;
                (w, e, format!("week of {}", date(w, e)))
            };
            let items = o.items(spec, e, observer);
            print_items(&items, json);
            let out = items.iter().filter(|x| x.1).count();
            eprintln!(
                "{}: {} items{}. `sudo peersig exclude <id>` leaves one out.",
                what,
                items.len(),
                if out > 0 { format!(", {} left out", out) } else { String::new() }
            );
        }
        Cmd::Exclude { ids } | Cmd::Include { ids } if ids.is_empty() => bail!("which items? give their ids, from `peersig items`"),
        Cmd::Exclude { ids } => {
            let mut known = o.excluded();
            let cfg = o.config().await?;
            let observer = o.code().map(|c| code::is_observer(&c)).unwrap_or(false);
            let (spec, e) = if observer {
                let days = cfg.epochs.days();
                (days, days.at(now()).unwrap_or(1).saturating_sub(1))
            } else {
                (cfg.epochs, cfg.report_epoch)
            };
            let mut items = o.items(spec, e, observer);
            items.extend(o.items(spec, e + 1, observer));
            let keys = resolve(&ids, &items, &BTreeSet::new())?;
            known.extend(keys.iter().cloned());
            o.save_excluded(&known)?;
            eprintln!("Left out {} item{}: never sent.", keys.len(), if keys.len() == 1 { "" } else { "s" });
        }
        Cmd::Include { ids } => {
            let mut known = o.excluded();
            let keys = resolve(&ids, &[], &known)?;
            for k in &keys {
                known.remove(k);
            }
            o.save_excluded(&known)?;
            eprintln!("Put back {} item{}.", keys.len(), if keys.len() == 1 { "" } else { "s" });
        }
        Cmd::Report { day, dry_run } => {
            let code = o.code()?;
            if code::is_observer(&code) {
                observer::report_now(o, &code, day.as_deref(), dry_run).await?;
            } else {
                if day.is_some() || dry_run {
                    bail!("--day and --dry-run are for observers; `peersig items` shows the week");
                }
                participant::send_now(o)?;
            }
        }
        Cmd::Run => {
            let code = o.code()?;
            if let Err(e) = check_logs(&o.logs) {
                eprintln!("{:#}", e);
            }
            if code::is_observer(&code) {
                observer::run(o, &code).await?;
            } else {
                participant::run(o, &code).await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
