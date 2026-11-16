//! `peersig-server`: run the collection server, and administer it from the
//! host (enrollment codes, statistics, exports). There is no admin HTTP API.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

use peersig_proto::{rr, EpochSpec, Item};
use peersig_server::{api, db, release, system_clock, Settings, State};

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
    /// Tokens per participant and epoch, the same for everyone.
    #[arg(long, global = true, env = "PEERSIG_TOKENS", default_value_t = 512)]
    tokens_per_epoch: u32,
    /// Local differential privacy of randomized response, per item and epoch.
    #[arg(long, global = true, env = "PEERSIG_RR_EPSILON", default_value_t = 9f64.ln())]
    rr_epsilon: f64,
    /// Participants needed to release a hello item.
    #[arg(long, global = true, env = "PEERSIG_K_HELLO", default_value_t = 3)]
    k_hello: u32,
    /// Participants needed to release a domain item.
    #[arg(long, global = true, env = "PEERSIG_K_DOMAIN", default_value_t = 5)]
    k_domain: u32,
    /// Epsilon of the Laplace noise on released supports.
    #[arg(long, global = true, env = "PEERSIG_EPSILON_CENTRAL", default_value_t = 1.0)]
    epsilon_central: f64,
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
    /// Serve the API.
    Serve {
        #[arg(long, env = "PEERSIG_LISTEN", default_value = "127.0.0.1:8080")]
        listen: String,
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
        /// json, or classifier (the Iris traffic classifier's ja4_fingerprints.json format)
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
enum CodesCmd {
    /// Create codes; prints them once (only their hash is stored).
    Add {
        #[arg(long, default_value_t = 1)]
        count: u32,
        /// Labels are <prefix>01, <prefix>02...
        #[arg(long, default_value = "P")]
        prefix: String,
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
    if !(p.rr_epsilon > 0.0) || !(p.epsilon_central > 0.0) {
        bail!("epsilons must be positive");
    }
    Ok(Settings {
        epochs: epochs(c, p)?,
        tokens_per_epoch: p.tokens_per_epoch,
        rr_p: rr::p_for_epsilon(p.rr_epsilon),
        k_hello: p.k_hello,
        k_domain: p.k_domain,
        epsilon_central: p.epsilon_central,
        about_url: p.about_url.clone(),
    })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let cli = Cli::parse();
    let conn = db::open(&cli.db)?;
    let s = settings(&conn, &cli.params)?;
    match cli.cmd {
        Cmd::Serve { listen } => {
            let state = State::new(conn, s.clone(), system_clock())?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async move {
                let l = tokio::net::TcpListener::bind(&listen).await.with_context(|| listen.clone())?;
                tracing::info!(
                    "listening on {}; epochs of {} days from {}; rr p={:.3}, k={}/{}",
                    listen,
                    s.epochs.length / 86400,
                    chrono::DateTime::from_timestamp(s.epochs.origin, 0).unwrap().date_naive(),
                    s.rr_p,
                    s.k_hello,
                    s.k_domain
                );
                axum::serve(l, api::router(state))
                    .with_graceful_shutdown(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await?;
                anyhow::Ok(())
            })?;
        }
        Cmd::Codes { cmd: CodesCmd::Add { count, prefix } } => {
            let existing = db::list_codes(&conn)?.len();
            for i in 0..count {
                let code = db::new_code();
                let label = format!("{}{:02}", prefix, existing as u32 + i + 1);
                db::add_code(&conn, &code, &label)?;
                println!("{}\t{}", label, code);
            }
            eprintln!("Only a hash of each code is stored: give each participant theirs now.");
        }
        Cmd::Codes { cmd: CodesCmd::List } => {
            println!("label\tcreated\tstatus\tepochs (tokens)");
            for r in db::list_codes(&conn)? {
                let ep: Vec<String> = r.epochs.iter().map(|(e, t)| format!("{} ({})", e, t)).collect();
                println!("{}\t{}\t{}\t{}", r.label, r.created, if r.revoked { "revoked" } else { "active" }, ep.join(", "));
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
        }
        Cmd::Export { format } => {
            let now = chrono::Utc::now().timestamp();
            let until = s.epochs.at(now).unwrap_or(0).saturating_sub(1);
            let r = release::released(&conn, &s, until)?;
            match format.as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&r)?),
                "classifier" => {
                    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let mut by_ja4: BTreeMap<String, Vec<String>> = BTreeMap::new();
                    for ri in &r.items {
                        if let Item::Hello { os, ja4, app, .. } = &ri.item {
                            let mut d = app.name.clone();
                            if let Some(v) = &app.version {
                                d.push_str(&format!(" {}", v));
                            }
                            d.push_str(&format!(" ({}{}, {})", app.kind, app.engine.as_deref().map(|e| format!(", {}", e)).unwrap_or_default(), os));
                            by_ja4.entry(ja4.clone()).or_default().push(d);
                        }
                    }
                    let rows: Vec<serde_json::Value> = by_ja4
                        .into_iter()
                        .map(|(ja4, apps)| {
                            serde_json::json!({
                                "ja4_hash": ja4,
                                "desc": format!("{} (PeerSig, k>={})", apps.join("; "), r.k_hello),
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
