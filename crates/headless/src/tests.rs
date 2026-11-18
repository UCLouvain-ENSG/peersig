//! `peersig run` against an in-process server: a participant's week, and
//! an observer's day.

use std::io::Write;

use peersig_proto::EpochSpec;
use peersig_server::{api, db, system_clock, Settings, State};

use crate::participant::{self, Stage};
use crate::{now, observer, Opts};

async fn serve(st: Settings, conn: rusqlite::Connection) -> (String, std::sync::Arc<State>) {
    let state = State::new(conn, st, system_clock()).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let router = api::router(state.clone());
    tokio::spawn(async move { axum::serve(l, router).await });
    (url, state)
}

fn log(dir: &std::path::Path, t: i64, records: &[serde_json::Value]) {
    std::fs::create_dir_all(dir).unwrap();
    let ts = chrono::DateTime::from_timestamp(t, 0).unwrap();
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(ts.format("peersig-%Y%m%d.jsonl").to_string())).unwrap();
    writeln!(f, "{}", serde_json::json!({"type":"start","os":{"os":"linux","distro":"debian","version":"Debian GNU/Linux 12 (bookworm)","build":"12","kernel":"6.1.0-27-amd64"}})).unwrap();
    for r in records {
        let mut r = r.clone();
        let k = if r["type"] == "domain" { "last" } else { "ts" };
        r[k] = serde_json::json!(ts.to_rfc3339());
        writeln!(f, "{}", r).unwrap();
    }
}

fn opts(dir: &std::path::Path, url: &str, code: &str) -> Opts {
    Opts {
        config: dir.join("none.conf"),
        server: url.into(),
        relay: "none".into(),
        code: Some(code.to_lowercase()),
        code_file: None,
        logs: dir.join("logs"),
        state: dir.join("state"),
        share_domains: true,
        review_hours: 0,
        spread_minutes: 0,
    }
}

fn hello(name: &str, ja4: &str) -> serde_json::Value {
    serde_json::json!({"type":"hello","transport":"tcp","ja4":ja4,"proc":name,"app":{"name":name,"version":"1.0","kind":"cli"}})
}

/// A participant's week: reviewed (0 h), the full token budget, one
/// anonymous ballot per item and one "took part", an item left out.
#[tokio::test(flavor = "multi_thread")]
async fn participant_week() {
    let t0 = now();
    let conn = db::open(":memory:").unwrap();
    let code = db::new_code();
    db::add_code(&conn, &code, "P01").unwrap();
    // Epoch 0 is [t0 - 1500, t0 - 500), reported during epoch 1.
    let st = Settings { epochs: EpochSpec { origin: t0 - 1500, length: 1000 }, tokens_per_epoch: 8, k_hello: 1, k_domain: 1, about_url: None };
    let (url, state) = serve(st, conn).await;
    let dir = std::env::temp_dir().join(format!("peersig-headless-week-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    log(
        &dir.join("logs"),
        t0 - 1000,
        &[
            hello("curl", "t13d1516h2_8daaf6152771_e5627efa2ab1"),
            hello("wget", "t13d1516h2_8daaf6152771_000000000001"),
            serde_json::json!({"type":"domain","app":"curl","app_kind":"cli","domain":"api.example.com","via":["sni"],"ja4":["t13d1516h2_8daaf6152771_e5627efa2ab1"],"count":1}),
        ],
    );
    let o = opts(&dir, &url, &code);
    let cfg = o.config().await.unwrap();
    let items = o.items(cfg.epochs, 0, false);
    assert_eq!(items.len(), 3);
    let wget = items.iter().find(|(i, _)| i.key.contains("wget")).unwrap().0.key.clone();
    o.save_excluded(&[wget.clone()].into_iter().collect()).unwrap();

    let path = participant::state_path(&o);
    let mut st = participant::State::load(&path);
    let mut c = None;
    participant::tick(&o, &o.code().unwrap(), &path, &mut st, &mut c).await;
    let r = participant::State::load(&path).reports.remove(&0).expect("the week was opened and kept");
    assert_eq!((r.stage, r.items, r.total, r.sent), (Stage::Sent, 2, 3, 3), "{}", participant::describe(&r));

    let db = state.db.lock().unwrap();
    let counted: Vec<String> = db.prepare("SELECT item FROM counts").unwrap().query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    assert_eq!(counted.len(), 3, "{:?}", counted);
    assert!(counted.iter().any(|k| k.contains("api.example.com")) && counted.iter().any(|k| k.contains("presence")));
    assert!(!counted.contains(&wget), "an item left out reached the server");
    let issued: u32 = db.query_row("SELECT tokens FROM issuance", [], |r| r.get(0)).unwrap();
    assert_eq!(issued, 8, "always the full budget");
    drop(db);
    // The next turn sends nothing more.
    participant::tick(&o, &o.code().unwrap(), &path, &mut st, &mut c).await;
    assert_eq!(state.db.lock().unwrap().query_row("SELECT SUM(n) FROM counts", [], |r| r.get::<_, i64>(0)).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An observer's day: reported once, then "already reported".
#[tokio::test(flavor = "multi_thread")]
async fn observer_day() {
    let t = now();
    let days = EpochSpec { origin: t - t.rem_euclid(EpochSpec::DAY) - 3 * EpochSpec::WEEK, length: EpochSpec::WEEK }.days();
    let today = days.at(t).unwrap();
    let conn = db::open(":memory:").unwrap();
    let code = db::new_observer_code();
    db::add_observer_code(&conn, &code, "O01").unwrap();
    let st = Settings { epochs: EpochSpec { origin: days.origin, length: EpochSpec::WEEK }, tokens_per_epoch: 4, k_hello: 3, k_domain: 5, about_url: None };
    let (url, state) = serve(st, conn).await;
    let dir = std::env::temp_dir().join(format!("peersig-headless-day-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    log(
        &dir.join("logs"),
        days.start(today - 1) + 43200,
        &[
            hello("curl", "t13d1516h2_8daaf6152771_e5627efa2ab1"),
            serde_json::json!({"type":"hello","transport":"tcp","ja4":"t13d1516h2_8daaf6152771_000000000002","proc":"x","app":{"name":"x","kind":"unknown"}}),
            serde_json::json!({"type":"domain","app":"curl","app_kind":"cli","domain":"api.example.com","via":["sni"],"ja4":["t13d1516h2_8daaf6152771_e5627efa2ab1"],"count":1}),
        ],
    );
    let o = opts(&dir, &url, &code);
    let code = o.code().unwrap();
    assert!(matches!(observer::report(&o, &code, days, today - 1).await.unwrap(), observer::Sent::Counted(2, ref l) if l == "O01"));
    assert!(matches!(observer::report(&o, &code, days, today - 1).await.unwrap(), observer::Sent::Already));
    assert!(matches!(observer::report(&o, &code, days, today - 2).await.unwrap(), observer::Sent::Empty));
    let (_, counted) = db::observed_day(&state.db.lock().unwrap(), today - 1).unwrap();
    assert_eq!(counted.len(), 2);
    assert_eq!(observer::parse_day(days, today, "yesterday").unwrap(), today - 1);
    let _ = std::fs::remove_dir_all(&dir);
}
