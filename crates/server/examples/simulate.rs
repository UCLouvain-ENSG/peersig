//! Simulates one week of collection from local probe logs, to see what a
//! release would look like.
//!
//! The items are derived from the logs exactly as the app derives them.
//! `--users` fake participants each keep a random part of them (`--keep`);
//! some of them (`--share`) also share server names. Each one goes through
//! the real flow against an in-process server: config, the full budget of
//! blind tokens, one Oblivious HTTP ballot per item. The database left in
//! `--db` is an ordinary one whose epochs put today two weeks after the
//! simulated one, so the server's own commands show what would be published:
//!
//!     cargo run --release -p peersig-server --example simulate -- \
//!         --db sim.db captures/*.jsonl
//!     peersig-server --db sim.db export --format classifier

use std::io::BufRead;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use peersig_proto::client::Client;
use peersig_proto::item::Collector;
use peersig_proto::plan::plan;
use peersig_proto::token;
use peersig_proto::wire::{Ballot, IssueRequest};
use peersig_proto::{Class, EpochSpec, Item};
use peersig_server::{api, db, release, Settings, State};

#[derive(Parser)]
struct Args {
    /// Database to create (replaced if it exists).
    #[arg(long, default_value = "sim.db")]
    db: String,
    /// Fake participants.
    #[arg(long, default_value_t = 20)]
    users: usize,
    /// Probability that a participant has each item of the logs.
    #[arg(long, default_value_t = 0.6)]
    keep: f64,
    /// Fraction of participants who share server names.
    #[arg(long, default_value_t = 0.5)]
    share: f64,
    #[arg(long, default_value_t = 512)]
    tokens: u32,
    #[arg(long, default_value_t = 3)]
    k_hello: u32,
    #[arg(long, default_value_t = 5)]
    k_domain: u32,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Probe logs (peersig-*.jsonl).
    #[arg(required = true)]
    logs: Vec<String>,
}

/// xorshift64*: reproducible uniform numbers in [0, 1).
fn uniform(seed: u64) -> impl FnMut() -> f64 {
    let mut x = seed.max(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    move || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 11) as f64 / (1u64 << 53) as f64
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();

    // Every item of the logs, whatever its date, with sharing on.
    let all_time = EpochSpec { origin: 0, length: 100 * 365 * 86400 };
    let mut col = Collector::new(all_time, 0, true);
    for f in &a.logs {
        let r = std::io::BufReader::new(std::fs::File::open(f).with_context(|| f.clone())?);
        for line in r.lines() {
            if let Ok(v) = serde_json::from_str(&line?) {
                col.record(&v);
            }
        }
    }
    let (observed, skipped) = col.finish();
    let of = |c: Class| observed.iter().filter(|o| o.item.class() == c).map(|o| o.item.clone()).collect::<Vec<Item>>();
    let (hellos, names) = (of(Class::Hello), of(Class::Domain));
    println!(
        "Logs: {} hello items, {} server-name items. Not items: {} handshakes with no known application, {} names from browsers, {} local names, {} names never in a ClientHello.",
        hellos.len(),
        names.len(),
        skipped.unattributed,
        skipped.browser_domains,
        skipped.private_domains,
        skipped.not_sni
    );

    // The simulated week is epoch 0; it is reported during epoch 1; today is in epoch 2.
    let now = chrono::Utc::now().timestamp();
    let spec = EpochSpec { origin: now - 2 * EpochSpec::WEEK - 3600, length: EpochSpec::WEEK };
    let _ = std::fs::remove_file(&a.db);
    let conn = db::open(&a.db)?;
    db::meta_set(&conn, "epochs", &serde_json::to_vec(&spec)?)?;
    let mut codes = Vec::new();
    for i in 0..a.users {
        let c = db::new_code();
        db::add_code(&conn, &c, &format!("SIM{:02}", i + 1))?;
        codes.push(c);
    }
    let settings = Settings { epochs: spec, tokens_per_epoch: a.tokens, k_hello: a.k_hello, k_domain: a.k_domain, about_url: None };
    let during_report = spec.start(1) + 3600;
    let state = State::new(conn, settings, Arc::new(move || during_report))?;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", l.local_addr()?);
    let app = api::router(state.clone());
    tokio::spawn(async move { axum::serve(l, app).await });

    let mut u = uniform(a.seed);
    for (i, code) in codes.iter().enumerate() {
        let shares = u() < a.share;
        let mut real = Vec::new();
        for it in &hellos {
            if u() < a.keep {
                real.push(it.clone());
            }
        }
        if shares {
            for it in &names {
                if u() < a.keep {
                    real.push(it.clone());
                }
            }
        }
        let mut c = Client::new(&url, None)?;
        let cfg = c.config().await?;
        let budget = cfg.tokens_per_epoch as usize;
        let pl = plan(cfg.report_epoch, &real, shares, budget, &mut u);
        let blinded = token::blind(&cfg.token_key.public_key, cfg.report_epoch, budget)?;
        let req = IssueRequest { code: code.clone(), epoch: cfg.report_epoch, blinded: blinded.iter().map(|b| b.blind_message.clone()).collect() };
        let resp = c.issue(&req).await?;
        let tokens = token::finalize(&cfg.token_key.public_key, &blinded, &resp.signatures)?;
        for (item, token) in pl.ballots.into_iter().zip(tokens) {
            c.ballot(&Ballot { item, token }).await?;
        }
        println!(
            "participant {:2}: {:3} items{}{}",
            i + 1,
            pl.real,
            if shares { ", shares server names" } else { "" },
            if pl.dropped > 0 { format!(", {} over budget", pl.dropped) } else { String::new() }
        );
    }

    let r = release::released(&state.db.lock().unwrap(), &state.settings, 1)?;
    let n = |c: Class| r.items.iter().filter(|i| i.item.class() == c).count();
    println!(
        "Released: {} of {} hello items (k = {}), {} of {} server-name items (k = {}). Database: {}.",
        n(Class::Hello),
        hellos.len(),
        a.k_hello,
        n(Class::Domain),
        names.len(),
        a.k_domain,
        a.db
    );
    Ok(())
}
