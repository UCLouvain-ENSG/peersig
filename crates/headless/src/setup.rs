//! `configure` and `status`: setting a machine up from the
//! `peersig-headless` package, which installs the probe and two systemd
//! units (`peersig-probe`, `peersig`) that wait for
//! `/etc/peersig/peersig.conf`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use peersig_proto::code;

use crate::config::{self, Loaded, Settings};
use crate::{code_label, date, logs_readable, now, participant, Opts};

pub const UNITS: [&str; 2] = ["peersig-probe.service", "peersig.service"];

fn ask(question: &str) -> Result<String> {
    eprint!("{}", question);
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// systemd runs, and the package's units are installed.
fn systemd_units() -> bool {
    Path::new("/run/systemd/system").exists()
        && ["/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"].iter().any(|d| Path::new(d).join(UNITS[1]).exists())
}

pub struct ConfigureArgs {
    pub no_share_domains: bool,
    pub no_check: bool,
    pub no_start: bool,
    pub yes: bool,
}

/// What leaves the machine, shown before it agrees.
fn terms(observer: bool, share: bool, review_hours: u32) -> String {
    let what = format!(
        "which applications (name, bundle id, version, signing team, kind, engine) sent which TLS fingerprint (JA4), and the distribution with its major release (linux debian 12){}",
        if share { "; and the server names (SNI) non-browser applications connect to, each with its JA4" } else { "" }
    );
    if observer {
        format!(
            "This machine becomes a DEDICATED OBSERVER. Every day, it sends {} in one report the server knows comes from \
             this observer, and each day's items are published as they are, without threshold. Use it only on a machine \
             run for the study, whose traffic may be published.",
            what
        )
    } else {
        format!(
            "Once a week, this machine sends {}. Never addresses, times, how often, paths, user or host names. Each item goes \
             as a separate anonymous ballot, through the relay; an item is published only once enough participants reported \
             it. Each week's list waits {} hours first: `sudo peersig items` shows it, `sudo peersig exclude <id>` leaves an \
             item out.",
            what, review_hours
        )
    }
}

/// Writes the configuration (asking for what is missing on a terminal),
/// after checking the code with the server and getting the operator's
/// agreement, then starts the services.
pub async fn configure(o: &Opts, loaded: &Loaded, a: &ConfigureArgs) -> Result<()> {
    let tty = std::io::stdin().is_terminal();
    if let Loaded::Unreadable(why) = loaded {
        bail!("{}: run it with sudo", why);
    }

    // The code: given, already configured, or asked for.
    let code = match (&o.code, &o.code_file) {
        (Some(c), _) => c.clone(),
        (None, Some(f)) => std::fs::read_to_string(f).with_context(|| f.display().to_string())?,
        (None, None) if tty => ask("Enrollment code (from peersig.org, or OBS-… from the study team): ")?,
        (None, None) => bail!("give the enrollment code: --code XXXX-XXXX-XXXX"),
    };
    let code = code.trim().to_uppercase();
    let observer = code::is_observer(&code);
    if code::normalize(&code).len() != if observer { 15 } else { 12 } {
        bail!("{:?} is not an enrollment code (XXXX-XXXX-XXXX, or OBS-XXXX-XXXX-XXXX for a dedicated observer)", code);
    }

    if a.no_check {
        eprintln!("Not checking the code with {} (--no-check).", o.server);
    } else {
        match o.client()?.code_info(&code).await {
            Ok(i) if i.observer != observer => bail!("the server does not know this code as {}", if observer { "an observer's" } else { "a participant's" }),
            Ok(i) if i.observer => eprintln!(
                "{} is dedicated observer {} on {}{}.",
                code_label(&code),
                i.label.unwrap_or_default(),
                o.server,
                match &i.last_day {
                    Some(d) => format!(" (last report {}, {} days so far)", d, i.days),
                    None => ", no report yet".to_string(),
                }
            ),
            Ok(_) => eprintln!("{} is a participant's code on {}.", code_label(&code), o.server),
            Err(e) => {
                let why = format!("{:#}", e);
                if why.contains("(403)") {
                    bail!("the server refuses this code: {}", why);
                } else if why.contains("HTTP 404") {
                    eprintln!("{} cannot check codes yet: the code is checked when it is first used.", o.server);
                } else {
                    eprintln!("Could not check the code ({}); it is checked when it is first used.", why);
                }
            }
        }
    }

    // Server names: an option, the environment or the file decides;
    // otherwise asked for on a terminal, and off.
    let given = std::env::args().any(|x| x == "--share-domains") || std::env::var_os("PEERSIG_SHARE_DOMAINS").is_some();
    let share = if a.no_share_domains {
        false
    } else if given || !tty {
        o.share_domains
    } else {
        eprintln!(
            "Also send the server names (SNI) that non-browser applications on this machine connect to?{}",
            if observer { " They are published every day with the observer's other items, internal host names too." } else { "" }
        );
        matches!(ask("Share server names? [y/N] ")?.to_lowercase().as_str(), "y" | "yes")
    };

    eprintln!("\n{}\n", terms(observer, share, o.review_hours));
    if !a.yes {
        if !tty {
            bail!("agree with --yes (no terminal to ask)");
        }
        if !matches!(ask(if observer { "Make this machine an observer? [y/N] " } else { "Take part? [y/N] " })?.to_lowercase().as_str(), "y" | "yes") {
            bail!("nothing written");
        }
    }

    let s = Settings {
        server: o.server.trim_end_matches('/').to_string(),
        relay: (!observer).then(|| o.relay().unwrap_or("none").trim_end_matches('/').to_string()),
        code,
        share_domains: share,
        review_hours: (!observer).then_some(o.review_hours),
        logs: o.logs.clone(),
    };
    config::write(&o.config, &s).map_err(|e| {
        let denied = e.chain().any(|c| c.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied));
        if denied {
            anyhow::anyhow!("{:#}: run it with sudo", e)
        } else {
            e
        }
    })?;
    eprintln!(
        "Wrote {}: {}, server {}{}, server names {}.",
        o.config.display(),
        if observer { "dedicated observer" } else { "participant" },
        s.server,
        s.relay.as_deref().map(|r| format!(", relay {}", r)).unwrap_or_default(),
        if share { "shared" } else { "not shared" },
    );

    if a.no_start {
        return Ok(());
    }
    if !systemd_units() {
        eprintln!(
            "No peersig service here (the package installs it): run `peersig-probe run --dir {}` and `peersig run` yourself.",
            s.logs.display()
        );
        return Ok(());
    }
    // The reporting unit pulls in the probe's.
    for args in [&["enable", "--now"][..], &["restart"][..]] {
        let st = Command::new("systemctl").args(args).args(UNITS).status().context("systemctl")?;
        if !st.success() {
            bail!("systemctl {} {} failed", args.join(" "), UNITS.join(" "));
        }
    }
    eprintln!(
        "Started {}. {} `sudo peersig status` shows what is going on.",
        UNITS.join(" and "),
        if observer {
            "The first report goes out after midnight UTC."
        } else {
            "This week is reported next week, after its review; `sudo peersig items --current` shows it so far."
        }
    );
    Ok(())
}

/// The probe's status file, as the app reads it.
fn probe_status(logs: &Path) -> String {
    let path = logs.join("status.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return format!("cannot read {}: run with sudo", path.display()),
        Err(_) => return format!("not started ({} is missing)", path.display()),
    };
    let Ok(v) = serde_json::from_str::<Value>(&text) else { return "unreadable status".into() };
    let age = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok()).map(|d| d.as_secs());
    let hellos: u64 = v.get("hellos").map(|h| ["tcp", "quic", "dtls"].iter().filter_map(|k| h.get(*k)?.as_u64()).sum()).unwrap_or(0);
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_string();
    match age {
        Some(a) if a < 30 => match v.get("error").and_then(|x| x.as_str()) {
            Some(err) => format!("cannot capture: {}", err),
            None if v.get("paused").and_then(|x| x.as_bool()) == Some(true) => "paused (a `paused` file is in the log directory)".into(),
            None => format!("capturing: {} handshakes since {}", hellos, s("started")),
        },
        _ => format!("not running (last heard of {} s ago)", age.map(|a| a.to_string()).unwrap_or_else(|| "?".into())),
    }
}

pub async fn status(o: &Opts, loaded: &Loaded) -> Result<()> {
    match loaded {
        Loaded::Missing => println!("configuration  none at {}: run `sudo peersig configure`", o.config.display()),
        Loaded::Unreadable(why) => println!("configuration  {}: run with sudo", why),
        Loaded::Read => println!("configuration  {}", o.config.display()),
    }
    let code = o.code.as_deref().map(|c| c.trim().to_uppercase());
    let observer = code.as_deref().is_some_and(code::is_observer);
    println!("server         {}", o.server);
    if !observer {
        println!("relay          {}", o.relay().unwrap_or("none: the server sees this machine's address"));
    }
    println!("server names   {}", if o.share_domains { "shared" } else { "not shared" });
    println!("logs           {}", o.logs.display());
    match &code {
        None => println!("code           none"),
        Some(c) => {
            let checked = match o.client() {
                Ok(client) => client.code_info(c).await,
                Err(e) => Err(e),
            };
            let what = match checked {
                Ok(i) if i.observer => format!(
                    "dedicated observer {}, {}",
                    i.label.unwrap_or_default(),
                    match i.last_day {
                        Some(d) => format!("{} day{} reported, the last {}", i.days, if i.days == 1 { "" } else { "s" }, d),
                        None => "no report yet".into(),
                    }
                ),
                Ok(_) => "participant: weekly anonymous ballots".into(),
                Err(e) if format!("{:#}", e).contains("HTTP 404") => "the server cannot check codes (older than 0.1.7)".into(),
                Err(e) => format!("{:#}", e),
            };
            println!("code           {}: {}", code_label(c), what);
        }
    }
    if code.is_some() && !observer {
        match participant::latest(o) {
            Some(r) => println!("report         {}", participant::describe(&r)),
            None => println!("report         none yet: a week is reported once it is over, after {} hours of review", o.review_hours),
        }
    }
    println!("probe          {}", probe_status(&o.logs));
    if logs_readable(&o.logs) {
        match peersig_proto::logs::system(&o.logs) {
            Some(Ok(os)) => println!("system         {}: sent with each item", os),
            Some(Err(raw)) => println!("system         not recognised ({}): no handshake can become an item", raw),
            None => {}
        }
        if let Ok(cfg) = o.config().await {
            if observer {
                let days = cfg.epochs.days();
                if let Some(today) = days.at(now()) {
                    println!("today so far   {} items ({}, UTC)", o.items(days, today, true).len(), date(days, today));
                }
            } else {
                println!("this week      {} items so far (week of {})", o.items(cfg.epochs, cfg.current_epoch, false).len(), date(cfg.epochs, cfg.current_epoch));
            }
        }
    }
    if Path::new("/run/systemd/system").exists() {
        if let Ok(out) = Command::new("systemctl").arg("is-active").args(UNITS).output() {
            let states: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect();
            let shown: Vec<String> = UNITS.iter().zip(states.iter()).map(|(u, s)| format!("{} {}", u.trim_end_matches(".service"), s)).collect();
            println!("services       {}", shown.join(", "));
        }
    }
    Ok(())
}
