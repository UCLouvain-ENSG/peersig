//! A participant reaches the server through the relay.

use std::net::SocketAddr;
use std::sync::Arc;

use peersig_proto::client::Client;
use peersig_proto::plan::plan;
use peersig_proto::token;
use peersig_proto::wire::{Ballot, IssueRequest};
use peersig_proto::{AppRef, EpochSpec, Item};
use peersig_server::{api, db, Settings, State};

async fn serve(app: axum::Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await });
    url
}

#[tokio::test(flavor = "multi_thread")]
async fn through_the_relay() {
    let conn = db::open(":memory:").unwrap();
    let code = db::new_code();
    db::add_code(&conn, &code, "P01").unwrap();
    let settings = Settings {
        epochs: EpochSpec { origin: 0, length: 1000 },
        tokens_per_epoch: 4,
        rr_p: 0.9,
        k_hello: 1,
        k_domain: 1,
        epsilon_central: 100.0,
        about_url: None,
    };
    let state = State::new(conn, settings, Arc::new(|| 1500)).unwrap();
    let server = serve(api::router(state.clone())).await;
    let relay = serve(peersig_relay::router(peersig_relay::Relay::new(&server, 100).unwrap())).await;

    let mut c = Client::new(&server, Some(&relay)).unwrap();
    let cfg = c.config().await.unwrap();
    let item = Item::Hello {
        os: "linux 6".into(),
        transport: "quic".into(),
        ja4: "q13d0311h3_55b375c5d22e_5a1f323ef56d".into(),
        ja4_legacy: None,
        app: AppRef { name: "curl".into(), id: None, version: Some("8.21.0".into()), team_id: None, kind: "cli".into(), engine: None },
    };
    let pl = plan(cfg.report_epoch, &[item.clone()], &[], cfg.rr_p, false, 4, &mut || rand::random::<f64>());
    let blinded = token::blind(&cfg.token_key.public_key, cfg.report_epoch, 4).unwrap();
    let resp = c
        .issue(&IssueRequest { code, epoch: cfg.report_epoch, blinded: blinded.iter().map(|b| b.blind_message.clone()).collect() })
        .await
        .unwrap();
    let tokens = token::finalize(&cfg.token_key.public_key, &blinded, &resp.signatures).unwrap();
    for (item, token) in pl.ballots.into_iter().zip(tokens) {
        c.ballot(&Ballot { item, token }).await.unwrap();
    }
    let n: i64 = state
        .db
        .lock()
        .unwrap()
        .query_row("SELECT n FROM counts WHERE item = ?1", [item.key()], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 1);
}
