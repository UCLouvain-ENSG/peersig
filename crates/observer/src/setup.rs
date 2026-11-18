//! `configure` and `status`: setting up a headless observer from the
//! `peersig-observer` package, which installs the probe and two systemd
//! units (`peersig-probe`, `peersig-observer`) that wait for
//! `/etc/peersig/observer.conf`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use peersig_proto::code;

use crate::config::{self, Loaded, Settings};
use crate::{code_label, day_name, logs_readable, Opts};

pub const UNITS: [&str; 2] = ["peersig-probe.service", "peersig-observer.service"];

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
        && ["/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system"]
            .iter()
            .any(|d| Path::new(d).join(UNITS[1]).exists())
}

pub struct ConfigureArgs {
    pub no_share_domains: bool,
    pub no_check: bool,
    pub no_start: bool,
}

/// Writes the configuration (asking for what is missing on a terminal),
/// after checking the code with the server, then starts the services.
pub async fn configure(o: &Opts, loaded: &Loaded, a: &ConfigureArgs) -> Result<()> {
    let tty = std::io::stdin().is_terminal();
    if let Loaded::Unreadable(why) = loaded {
        bail!("{}: run it with sudo", why);
    }

    // The code: given, already configured, or asked for.
    let mut code = match (&o.code, &o.code_file) {
        (Some(c), _) => c.clone(),
        (None, Some(f)) => std::fs::read_to_string(f).with_context(|| f.display().to_string())?,
        (None, None) if tty => ask("Observer code from the study team (OBS-XXXX-XXXX-XXXX): ")?,
        (None, None) => bail!("give the observer's code: --code OBS-XXXX-XXXX-XXXX"),
    };
    code = code.trim().to_uppercase();
    if !code::is_observer(&code) {
        bail!("{:?} is not an observer's code (OBS-XXXX-XXXX-XXXX). Participants use the PeerSig app.", code);
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
            "Also send the server names (SNI) that non-browser applications on this machine connect to?\n\
             They are published every day with the observer's other items, internal host names too."
        );
        matches!(ask("Share server names? [y/N] ")?.to_lowercase().as_str(), "y" | "yes")
    };

    if a.no_check {
        eprintln!("Not checking the code with {} (--no-check).", o.server);
    } else {
        match o.client()?.observer_status(&code).await {
            Ok(s) => eprintln!(
                "{} is observer {} on {}{}.",
                code_label(&code),
                s.label,
                o.server,
                match &s.last_day {
                    Some(d) => format!(" (last report: {}, {} days so far)", d, s.days),
                    None => ", no report yet".to_string(),
                }
            ),
            Err(e) => {
                let why = format!("{:#}", e);
                if why.contains("(403)") {
                    bail!("the server refuses this code: {}", why);
                } else if why.contains("HTTP 404") {
                    eprintln!("{} cannot check codes yet: the code is checked at its first report.", o.server);
                } else {
                    eprintln!("Could not check the code ({}); it will be checked at the first report.", why);
                }
            }
        }
    }

    let s = Settings { server: o.server.trim_end_matches('/').to_string(), code, share_domains: share, logs: o.logs.clone() };
    config::write(&o.config, &s).map_err(|e| {
        let denied = e.chain().any(|c| c.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied));
        if denied {
            anyhow::anyhow!("{:#}: run it with sudo", e)
        } else {
            e
        }
    })?;
    eprintln!(
        "Wrote {}: server {}, server names {}, logs in {}.",
        o.config.display(),
        s.server,
        if share { "shared" } else { "not shared" },
        s.logs.display()
    );

    if a.no_start {
        return Ok(());
    }
    if !systemd_units() {
        eprintln!(
            "No peersig-observer service here (the package installs it): run `peersig-probe run --dir {}` and `peersig-observer run` yourself.",
            s.logs.display()
        );
        return Ok(());
    }
    // The observer's unit pulls in the probe's.
    for args in [&["enable", "--now"][..], &["restart"][..]] {
        let st = Command::new("systemctl").args(args).args(UNITS).status().context("systemctl")?;
        if !st.success() {
            bail!("systemctl {} {} failed", args.join(" "), UNITS.join(" "));
        }
    }
    eprintln!(
        "Started {}. The first report goes out after midnight UTC; `peersig-observer status` shows what is going on.",
        UNITS.join(" and ")
    );
    Ok(())
}

/// The probe's status file, as the app reads it.
fn probe_status(logs: &Path) -> String {
    let path = logs.join("status.json");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return format!("cannot read {}: run as root or as peersig", path.display())
        }
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
        Loaded::Missing => println!("configuration  none at {}: run `sudo peersig-observer configure`", o.config.display()),
        Loaded::Unreadable(why) => println!("configuration  {}: run as root or as peersig", why),
        Loaded::Read => println!("configuration  {}", o.config.display()),
    }
    println!("server         {}", o.server);
    println!("server names   {}", if o.share_domains { "shared" } else { "not shared" });
    println!("logs           {}", o.logs.display());
    match o.code.as_deref().map(|c| c.trim().to_uppercase()) {
        None => println!("code           none"),
        Some(c) => {
            let checked = match o.client() {
                Ok(client) => client.observer_status(&c).await,
                Err(e) => Err(e),
            };
            let who = match checked {
                Ok(s) => format!(
                    "observer {}, {}",
                    s.label,
                    match s.last_day {
                        Some(d) => format!("{} day{} reported, the last {}", s.days, if s.days == 1 { "" } else { "s" }, d),
                        None => "no report yet".into(),
                    }
                ),
                Err(e) if format!("{:#}", e).contains("HTTP 404") => "the server cannot check codes (older than 0.1.6)".into(),
                Err(e) => format!("{:#}", e),
            };
            println!("code           {}: {}", code_label(&c), who);
        }
    }
    println!("probe          {}", probe_status(&o.logs));
    if logs_readable(&o.logs) {
        if let Ok((days, today)) = o.days().await {
            let (obs, _) = o.items(days, today);
            println!("today so far   {} items ({}, UTC)", obs.len(), day_name(days, today));
        }
    }
    if Path::new("/run/systemd/system").exists() {
        let out = Command::new("systemctl").arg("is-active").args(UNITS).output();
        if let Ok(out) = out {
            let states: Vec<String> = String::from_utf8_lossy(&out.stdout).lines().map(String::from).collect();
            let shown: Vec<String> = UNITS.iter().zip(states.iter()).map(|(u, s)| format!("{} {}", u.trim_end_matches(".service"), s)).collect();
            println!("services       {}", shown.join(", "));
        }
    }
    Ok(())
}
