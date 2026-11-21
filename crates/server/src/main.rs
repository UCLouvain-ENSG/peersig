//! `peersig-server`: run the collection server, and administer it from the
//! host (enrollment codes, statistics, exports) or from its /admin page
//! (codes and bans, for the GitHub accounts in --admin-github).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use peersig_proto::{EpochSpec, Item};
use peersig_server::enroll::{Block, Enrollment, GitHub, Mail, Network};
use peersig_server::{api, db, release, system_clock, web, Settings, State};

#[derive(Parser)]
#[command(name = "peersig-server", version, about = "PeerSig collection server")]
struct Cli {
    /// SQLite database.
    #[arg(long, global = true, env = "PEERSIG_DB", default_value = "peersig.db")]
    db: String,
    #[command(flatten)]
    params: Params,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
struct Params {
    /// Tokens per participant and epoch, the same for everyone. A computer
    /// that shares server names sees about 2000 items a week.
    #[arg(long, global = true, env = "PEERSIG_TOKENS", default_value_t = 4096)]
    tokens_per_epoch: u32,
    /// Participants needed to release a hello item.
    #[arg(long, global = true, env = "PEERSIG_K_HELLO", default_value_t = 3)]
    k_hello: u32,
    /// Participants needed to release a domain item.
    #[arg(long, global = true, env = "PEERSIG_K_DOMAIN", default_value_t = 5)]
    k_domain: u32,
    /// Page describing the study, shown in the app.
    #[arg(long, global = true, env = "PEERSIG_ABOUT_URL")]
    about_url: Option<String>,
    /// First day of epoch 0 (UTC, YYYY-MM-DD). Fixed when the database is
    /// created; default: the Monday of that week.
    #[arg(long, global = true, env = "PEERSIG_EPOCH_ORIGIN")]
    epoch_origin: Option<String>,
    /// Epoch length in days. Fixed when the database is created.
    #[arg(long, global = true, env = "PEERSIG_EPOCH_DAYS")]
    epoch_days: Option<u32>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the API and the web page.
    Serve {
        #[arg(long, env = "PEERSIG_LISTEN", default_value = "127.0.0.1:8080")]
        listen: String,
        #[command(flatten)]
        web: WebArgs,
    },
    /// Enrollment codes.
    Codes {
        #[command(subcommand)]
        cmd: CodesCmd,
    },
    /// Participants, ballots and items per epoch.
    Stats,
    /// Released items.
    Export {
        /// json, or classifier: one {ja4_hash, desc, source, fetched} record per JA4
        #[arg(long, default_value = "json")]
        format: String,
        /// The dedicated observers' daily table instead (no threshold):
        /// every day, or the days from --day on.
        #[arg(long)]
        observers: bool,
        /// With --observers: this day only (YYYY-MM-DD, UTC), or with
        /// --since, from this day on.
        #[arg(long, requires = "observers")]
        day: Option<String>,
        /// With --observers and --day: that day and the following ones.
        #[arg(long, requires = "day")]
        since: bool,
    },
}

/// The web page, and enrollment from it. Without --smtp-url or a GitHub
/// app, the page tells visitors that the study team gives out codes.
#[derive(Args)]
struct WebArgs {
    /// The server's public address (https://...): links, and GitHub's callback.
    #[arg(long, env = "PEERSIG_PUBLIC_URL")]
    public_url: Option<String>,
    /// The relay participants should use, shown on the page and in messages.
    #[arg(long, env = "PEERSIG_RELAY_URL")]
    relay_url: Option<String>,
    /// The study team's e-mail address, shown on the page and in messages.
    #[arg(long, env = "PEERSIG_CONTACT")]
    contact: Option<String>,
    /// Codes one e-mail address or GitHub account can get (one per computer or phone).
    #[arg(long, env = "PEERSIG_CODES_PER_IDENTITY", default_value_t = 3)]
    codes_per_identity: u32,
    /// Codes the page hands out per hour, all methods together.
    #[arg(long, env = "PEERSIG_ENROLL_PER_HOUR", default_value_t = 60)]
    enroll_per_hour: u32,
    /// SMTP server for codes by e-mail: smtp://host:25 (no TLS, a local
    /// MTA), smtp://user:pass@host:587?tls=required or smtps://user:pass@host:465.
    #[arg(long, env = "PEERSIG_SMTP_URL", hide_env_values = true)]
    smtp_url: Option<String>,
    /// Sender of those messages, e.g. "PeerSig <peersig@example.org>".
    #[arg(long, env = "PEERSIG_MAIL_FROM")]
    mail_from: Option<String>,
    /// GitHub OAuth app for codes with a GitHub account. Its callback URL
    /// is <public-url>/enroll/github/callback.
    #[arg(long, env = "PEERSIG_GITHUB_CLIENT_ID")]
    github_client_id: Option<String>,
    #[arg(long, env = "PEERSIG_GITHUB_CLIENT_SECRET", hide_env_values = true)]
    github_client_secret: Option<String>,
    /// GitHub accounts younger than this many days get no code.
    #[arg(long, env = "PEERSIG_GITHUB_MIN_AGE_DAYS", default_value_t = 30)]
    github_min_age_days: u32,
    /// Address blocks whose visitors get a code with one click (CIDR,
    /// comma-separated), e.g. a university's network and VPN.
    #[arg(long, env = "PEERSIG_ENROLL_NETWORKS", value_delimiter = ',')]
    enroll_networks: Vec<String>,
    /// That network's name on the page.
    #[arg(long, env = "PEERSIG_ENROLL_NETWORK_NAME", default_value = "institution's")]
    enroll_network_name: String,
    /// Behind a reverse proxy on this machine: the header in which it puts
    /// the client's address, on /enroll/ only, overwriting what the client
    /// sent (Apache: RequestHeader set X-PeerSig-Client "expr=%{REMOTE_ADDR}").
    /// Used to check the network, and for --enroll-per-address.
    #[arg(long, env = "PEERSIG_CLIENT_ADDRESS_HEADER")]
    client_address_header: Option<String>,
    /// Requests for a code by e-mail or GitHub one client address (an IPv4
    /// address, an IPv6 /64) can make per hour, counted in memory only
    /// under a keyed hash; 0: no limit. Behind a proxy, needs
    /// --client-address-header.
    #[arg(long, env = "PEERSIG_ENROLL_PER_ADDRESS", default_value_t = 5)]
    enroll_per_address: u32,
    /// GitHub logins (comma-separated) allowed into /admin, signing in
    /// through the GitHub app above (its callback covers /admin's). Unset:
    /// no /admin.
    #[arg(long, env = "PEERSIG_ADMIN_GITHUB", value_delimiter = ',')]
    admin_github: Vec<String>,
    /// A note shown at the top of the page, e.g. the limits of a pilot.
    #[arg(long, env = "PEERSIG_NOTICE")]
    notice: Option<String>,
    /// Where the note says more (a "More on this" link after it), e.g.
    /// /privacy#relay.
    #[arg(long, env = "PEERSIG_NOTICE_URL")]
    notice_url: Option<String>,
}

/// An empty variable (as in an env file) counts as unset.
fn set(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn enrollment(w: &WebArgs) -> Result<Enrollment> {
    let blocks: Vec<Block> = w.enroll_networks.iter().map(|b| b.trim()).filter(|b| !b.is_empty()).map(str::parse).collect::<Result<_>>()?;
    let wants_mail = set(&w.smtp_url).is_some();
    let wants_github = set(&w.github_client_id).is_some();
    let public = set(&w.public_url);
    if (wants_mail || wants_github || !blocks.is_empty()) && public.is_none() {
        bail!("enrollment from the web page needs --public-url");
    }
    let mut e = Enrollment::new(public.unwrap_or(""), set(&w.relay_url), w.codes_per_identity, w.enroll_per_hour);
    e.contact = set(&w.contact).map(String::from);
    e.per_address = w.enroll_per_address;
    e.address_header = set(&w.client_address_header).map(String::from);
    e.admins = w.admin_github.iter().map(|l| l.trim().trim_start_matches('@').to_ascii_lowercase()).filter(|l| !l.is_empty()).collect();
    if !e.admins.is_empty() && public.is_none() {
        bail!("--admin-github needs --public-url");
    }
    if let Some(url) = set(&w.smtp_url) {
        let from = set(&w.mail_from).context("--smtp-url needs --mail-from")?;
        e.mail = Some(Mail::smtp(url, from)?);
    }
    if !blocks.is_empty() {
        e.network = Some(Network {
            name: w.enroll_network_name.trim().to_string(),
            blocks,
            address_header: set(&w.client_address_header).map(String::from),
        });
    }
    if let Some(id) = set(&w.github_client_id) {
        let secret = set(&w.github_client_secret).context("--github-client-id needs --github-client-secret")?;
        e.github = Some(GitHub::new(id, secret, w.github_min_age_days)?);
    }
    if !e.admins.is_empty() && e.github.is_none() {
        bail!("--admin-github needs the GitHub app (--github-client-id)");
    }
    Ok(e)
}

#[derive(Subcommand)]
enum CodesCmd {
    /// Create codes; prints them once (only their hash is stored).
    Add {
        #[arg(long, default_value_t = 1)]
        count: u32,
        /// Labels are <prefix>01, <prefix>02... Default: P, or O with
        /// --observer.
        #[arg(long)]
        prefix: Option<String>,
        /// Codes for dedicated observers (OBS-XXXX-XXXX-XXXX): machines run
        /// for the study, which report daily and whose items are published
        /// without threshold. Never give one to a participant.
        #[arg(long)]
        observer: bool,
    },
    /// Labels, and the epochs each one took part in.
    List,
    /// Withdraw a code (by code or label): no more tokens for it.
    Revoke { code_or_label: String },
}

/// The epoch layout is stored with the data: changing it would mix epochs.
fn epochs(c: &rusqlite::Connection, p: &Params) -> Result<EpochSpec> {
    if let Some(v) = db::meta_get(c, "epochs")? {
        let stored: EpochSpec = serde_json::from_slice(&v)?;
        if p.epoch_days.is_some_and(|d| d as i64 * 86400 != stored.length) {
            bail!("the database uses {}-day epochs; --epoch-days cannot change it", stored.length / 86400);
        }
        return Ok(stored);
    }
    let origin = match &p.epoch_origin {
        Some(d) => chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").context("--epoch-origin")?,
        None => {
            let today = chrono::Utc::now().date_naive();
            today - chrono::Days::new(chrono::Datelike::weekday(&today).num_days_from_monday() as u64)
        }
    };
    let spec = EpochSpec {
        origin: origin.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp(),
        length: p.epoch_days.unwrap_or(7) as i64 * 86400,
    };
    db::meta_set(c, "epochs", &serde_json::to_vec(&spec)?)?;
    Ok(spec)
}

fn settings(c: &rusqlite::Connection, p: &Params) -> Result<Settings> {
    Ok(Settings {
        epochs: epochs(c, p)?,
        tokens_per_epoch: p.tokens_per_epoch,
        k_hello: p.k_hello,
        k_domain: p.k_domain,
        about_url: p.about_url.clone(),
    })
}

/// "Microsoft Teams 26289 (app, chromium 156, macos 27)".
fn classifier_desc(os: &str, app: &peersig_proto::AppRef) -> String {
    let mut d = app.name.clone();
    if let Some(v) = &app.version {
        d.push_str(&format!(" {}", v));
    }
    d.push_str(&format!(" ({}{}, {})", app.kind, app.engine.as_deref().map(|e| format!(", {}", e)).unwrap_or_default(), os));
    d
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    let conn = db::open(&cli.db)?;
    let s = settings(&conn, &cli.params)?;
    match cli.cmd {
        Cmd::Serve { listen, web: w } => {
            let enroll = enrollment(&w)?;
            let methods: Vec<&str> =
                [enroll.mail.as_ref().map(|_| "e-mail"), enroll.github.as_ref().map(|_| "GitHub"), enroll.network.as_ref().map(|_| "network")]
                    .into_iter()
                    .flatten()
                    .collect();
            let admin = if enroll.admin_enabled() { format!("; /admin for {} GitHub account(s)", enroll.admins.len()) } else { String::new() };
            let state = State::new(conn, s.clone(), system_clock())?;
            let notice = set(&w.notice).map(|text| web::Notice { text: text.into(), url: set(&w.notice_url).map(String::from) });
            let app = api::router(state.clone()).merge(web::router(std::sync::Arc::new(web::Web { state, enroll, notice })));
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async move {
                let l = tokio::net::TcpListener::bind(&listen).await.with_context(|| listen.clone())?;
                tracing::info!(
                    "listening on {}; epochs of {} days from {}; k={}/{}; enrollment: {}{}",
                    listen,
                    s.epochs.length / 86400,
                    chrono::DateTime::from_timestamp(s.epochs.origin, 0).unwrap().date_naive(),
                    s.k_hello,
                    s.k_domain,
                    if methods.is_empty() { "codes from the study team only".to_string() } else { methods.join(", ") },
                    admin
                );
                // The connection's address reaches the network enrollment only.
                axum::serve(l, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                    .with_graceful_shutdown(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await?;
                anyhow::Ok(())
            })?;
        }
        Cmd::Codes { cmd: CodesCmd::Add { count, prefix, observer } } => {
            let mut conn = conn;
            let made = if observer {
                db::add_observer_codes(&mut conn, count, prefix.as_deref().unwrap_or("O"))?
            } else {
                db::add_codes(&mut conn, count, prefix.as_deref().unwrap_or("P"))?
            };
            for (label, code) in made {
                println!("{}\t{}", label, code);
            }
            if observer {
                eprintln!("Only a hash of each code is stored. Each code makes one machine a dedicated observer: its items are published every day, without threshold.");
            } else {
                eprintln!("Only a hash of each code is stored: give each participant theirs now.");
            }
        }
        Cmd::Codes { cmd: CodesCmd::List } => {
            let day = |d: u32| chrono::DateTime::from_timestamp(s.epochs.days().start(d), 0).map(|t| t.date_naive().to_string()).unwrap_or_default();
            println!("label\tcreated\tstatus\tepochs (tokens), or for observers: days (items)");
            for r in db::list_codes(&conn)? {
                let ep: Vec<String> = if r.observer {
                    r.epochs.iter().rev().map(|(d, n)| format!("{} ({})", day(*d), n)).collect()
                } else {
                    r.epochs.iter().map(|(e, t)| format!("{} ({})", e, t)).collect()
                };
                let status = match (r.revoked, r.observer) {
                    (true, _) => "revoked",
                    (false, true) => "observer",
                    (false, false) => "active",
                };
                println!("{}\t{}\t{}\t{}", r.label, r.created, status, ep.join(", "));
            }
        }
        Cmd::Codes { cmd: CodesCmd::Revoke { code_or_label } } => {
            let n = db::revoke(&conn, &code_or_label)?;
            if n == 0 {
                bail!("no such code or label");
            }
            println!("revoked {}", n);
        }
        Cmd::Stats => {
            println!("epoch\tstart\tcodes\ttokens\treporters\tballots\tdistinct items");
            for e in db::stats(&conn)? {
                let start = chrono::DateTime::from_timestamp(s.epochs.start(e.epoch), 0).unwrap().date_naive();
                println!("{}\t{}\t{}\t{}\t{}\t{}\t{}", e.epoch, start, e.codes, e.tokens, e.presence, e.ballots, e.items);
            }
            let days = db::observed_days(&conn)?;
            if !days.is_empty() {
                println!("\nobservers' day\tobservers\tdistinct items");
                for (d, observers, items) in days.into_iter().take(14) {
                    let start = chrono::DateTime::from_timestamp(s.epochs.days().start(d), 0).unwrap().date_naive();
                    println!("{}\t{}\t{}", start, observers, items);
                }
            }
        }
        Cmd::Export { format, observers: true, day, since } => {
            let days = s.epochs.days();
            let number = |name: &str| -> Result<u32> {
                let d = chrono::NaiveDate::parse_from_str(name, "%Y-%m-%d").context("--day: YYYY-MM-DD")?;
                days.at(d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()).context("--day: before the collection")
            };
            let wanted: Vec<u32> = match (&day, since) {
                (Some(d), false) => vec![number(d)?],
                (Some(d), true) => {
                    let from = number(d)?;
                    db::observed_days(&conn)?.into_iter().map(|x| x.0).filter(|x| *x >= from).rev().collect()
                }
                (None, _) => db::observed_days(&conn)?.into_iter().map(|x| x.0).rev().collect(),
            };
            let table: Vec<_> = wanted.into_iter().map(|d| release::observed(&conn, &s, d)).collect::<Result<_>>()?;
            match format.as_str() {
                "json" if day.is_some() && !since => println!("{}", serde_json::to_string_pretty(&table[0])?),
                "json" => println!("{}", serde_json::to_string_pretty(&table)?),
                "classifier" => {
                    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let mut by_ja4: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
                    for d in &table {
                        for oi in &d.items {
                            if let Item::Hello { os, ja4, app, .. } = &oi.item {
                                by_ja4.entry(ja4.clone()).or_default().insert(classifier_desc(os, app));
                            }
                        }
                    }
                    let rows: Vec<serde_json::Value> = by_ja4
                        .into_iter()
                        .map(|(ja4, apps)| {
                            serde_json::json!({
                                "ja4_hash": ja4,
                                "desc": format!("{} (PeerSig observers)", apps.into_iter().collect::<Vec<_>>().join("; ")),
                                "source": "peersig-observer",
                                "fetched": today,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                f => bail!("unknown format {}", f),
            }
        }
        Cmd::Export { format, .. } => {
            let now = chrono::Utc::now().timestamp();
            let until = s.epochs.at(now).unwrap_or(0).saturating_sub(1);
            let r = release::released(&conn, &s, until)?;
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&r)?),
                "classifier" => {
                    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let mut by_ja4: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
                    for ri in &r.items {
                        if let Item::Hello { os, ja4, app, .. } = &ri.item {
                            by_ja4.entry(ja4.clone()).or_default().insert(classifier_desc(os, app));
                        }
                    }
                    let rows: Vec<serde_json::Value> = by_ja4
                        .into_iter()
                        .map(|(ja4, apps)| {
                            serde_json::json!({
                                "ja4_hash": ja4,
                                "desc": format!("{} (PeerSig, k>={})", apps.into_iter().collect::<Vec<_>>().join("; "), r.k_hello),
                                "source": "peersig",
                                "fetched": today,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&rows)?);
                }
                f => bail!("unknown format {}", f),
            }
        }
    }
    Ok(())
}
