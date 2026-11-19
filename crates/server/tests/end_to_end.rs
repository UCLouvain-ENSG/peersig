//! Participants enroll, get blind tokens, send ballots through Oblivious
//! HTTP, and the server releases what enough of them reported.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peersig_proto::client::Client;
use peersig_proto::plan::plan;
use peersig_proto::token;
use peersig_proto::wire::{Ballot, IssueRequest, Released, PATH_BALLOT, PATH_RELEASED};
use peersig_proto::{AppRef, EpochSpec, Item};
use peersig_server::{api, db, Settings, State};

fn hello(app: &str, ja4: &str) -> Item {
    Item::Hello {
        os: "macos 27".into(),
        transport: "tcp".into(),
        ja4: ja4.into(),
        app: AppRef { name: app.into(), id: None, version: Some("1.0".into()), team_id: None, kind: "app".into(), engine: None },
    }
}

const TOKENS: u32 = 8;

async fn participate(url: &str, code: &str, real: &[Item]) -> anyhow::Result<usize> {
    let mut c = Client::new(url, None)?;
    let cfg = c.config().await?;
    let epoch = cfg.report_epoch;
    let pl = plan(epoch, real, false, cfg.tokens_per_epoch as usize, &mut || rand::random::<f64>());
    let blinded = token::blind(&cfg.token_key.public_key, epoch, cfg.tokens_per_epoch as usize)?;
    let req = IssueRequest { code: code.into(), epoch, blinded: blinded.iter().map(|b| b.blind_message.clone()).collect() };
    let resp = c.issue(&req).await?;
    assert_eq!(resp.key_id, cfg.token_key.key_id);
    let tokens = token::finalize(&cfg.token_key.public_key, &blinded, &resp.signatures)?;
    let n = pl.ballots.len();
    for (item, token) in pl.ballots.into_iter().zip(tokens) {
        c.ballot(&Ballot { item, token }).await?;
    }
    Ok(n)
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_vote_release() {
    let now = Arc::new(AtomicI64::new(1500)); // epoch 1: reporting epoch 0
    let clock = {
        let now = now.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    let conn = db::open(":memory:").unwrap();
    let codes: Vec<String> = (0..4).map(|_| db::new_code()).collect();
    for (i, c) in codes.iter().enumerate() {
        db::add_code(&conn, c, &format!("P{}", i)).unwrap();
    }
    let settings = Settings {
        epochs: EpochSpec { origin: 0, length: 1000 },
        tokens_per_epoch: TOKENS,
        k_hello: 3,
        k_domain: 5,
        about_url: None,
    };
    let state = State::new(conn, settings, clock).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = api::router(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await });

    let common = hello("Common", "t13d1516h2_8daaf6152771_e5627efa2ab1");
    let rare = hello("Rare", "t13d1516h2_8daaf6152771_000000000001");

    // Epoch 0, reported during epoch 1.
    for (i, code) in codes.iter().enumerate() {
        let mut real = vec![common.clone()];
        if i == 0 {
            real.push(rare.clone());
        }
        // Lower-case and without dashes still works.
        let code = if i == 1 { code.to_lowercase().replace('-', "") } else { code.clone() };
        participate(&url, &code, &real).await.unwrap();
    }

    // Refusals.
    let mut c = Client::new(&url, None).unwrap();
    let cfg = c.config().await.unwrap();
    let blinded = token::blind(&cfg.token_key.public_key, 0, 1).unwrap();
    let one = |code: &str| IssueRequest { code: code.into(), epoch: 0, blinded: vec![blinded[0].blind_message.clone()] };
    let e = c.issue(&one("AAAA-BBBB-CCCC")).await.unwrap_err().to_string();
    assert!(e.contains("unknown enrollment code"), "{}", e);
    let e = c.issue(&one(&codes[0])).await.unwrap_err().to_string();
    assert!(e.contains("already issued"), "{}", e);
    db::revoke(&state.db.lock().unwrap(), "P3").unwrap();
    let e = c.issue(&one(&codes[3])).await.unwrap_err().to_string();
    assert!(e.contains("withdrawn"), "{}", e);
    // A token spent twice, and a forged one.
    let extra = db::new_code();
    db::add_code(&state.db.lock().unwrap(), &extra, "X").unwrap();
    let resp = c.issue(&one(&extra)).await.unwrap();
    let t = token::finalize(&cfg.token_key.public_key, &blinded[..1], &resp.signatures).unwrap().remove(0);
    let body = serde_json::to_vec(&Ballot { item: common.clone(), token: t.clone() }).unwrap();
    assert_eq!(c.oblivious("POST", PATH_BALLOT, &body).await.unwrap().0, 204);
    assert_eq!(c.oblivious("POST", PATH_BALLOT, &body).await.unwrap().0, 409);
    let mut forged = t.clone();
    forged.nonce[0] ^= 1;
    let body = serde_json::to_vec(&Ballot { item: common.clone(), token: forged }).unwrap();
    assert_eq!(c.oblivious("POST", PATH_BALLOT, &body).await.unwrap().0, 403);

    // What the database holds: counters, nothing about who or when.
    {
        let db = state.db.lock().unwrap();
        let mut st = db.prepare("SELECT epoch, item, n FROM counts ORDER BY item").unwrap();
        let rows: Vec<(u32, String, i64)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect();
        let n = |it: &Item| rows.iter().find(|r| r.1 == it.key()).map(|r| r.2);
        assert_eq!(n(&common), Some(5));
        assert_eq!(n(&rare), Some(1));
        assert_eq!(n(&Item::Presence { shares_domains: false }), Some(4));
        assert!(rows.iter().all(|r| r.0 == 0 && !r.1.contains("127.0.0.1")));
    }

    // Epoch 2: epoch 0 is complete. The common item is released, the rare one is not.
    now.store(2500, Ordering::SeqCst);
    let (status, body) = c.oblivious("GET", PATH_RELEASED, b"").await.unwrap();
    assert_eq!(status, 200);
    let rel: Released = serde_json::from_slice(&body).unwrap();
    let keys: Vec<String> = rel.items.iter().map(|i| i.item.key()).collect();
    assert!(keys.contains(&common.key()), "{:?}", keys);
    assert!(!keys.contains(&rare.key()));
    // Supports are exact: 4 participants plus the extra ballot of the double-spend check.
    assert_eq!(rel.items.iter().find(|i| i.item == common).map(|i| i.support), Some(5));

    let cfg = c.config().await.unwrap();
    assert_eq!(cfg.report_epoch, 1);
    // Ballots for the wrong epoch are refused.
    let b = token::blind(&cfg.token_key.public_key, 0, 1).unwrap();
    let e = c.issue(&IssueRequest { code: codes[0].clone(), epoch: 0, blinded: vec![b[0].blind_message.clone()] }).await.unwrap_err();
    assert!(e.to_string().contains("epoch 1 only"), "{}", e);
}
