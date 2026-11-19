//! Dedicated observers: one report per day with their code, counted apart
//! from participants' ballots, published day by day without threshold.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use peersig_proto::client::Client;
use peersig_proto::token;
use peersig_proto::wire::{IssueRequest, ObservedDay, ObservedDays, ObserverReport, Released, PATH_OBSERVE, PATH_OBSERVED, PATH_RELEASED};
use peersig_proto::{AppRef, EpochSpec, Item};
use peersig_server::enroll::Enrollment;
use peersig_server::{api, db, web, Settings, State};

fn app(name: &str, kind: &str) -> AppRef {
    AppRef { name: name.into(), id: Some("com.example".into()), version: Some("1.0".into()), team_id: None, kind: kind.into(), engine: None }
}

fn hello(name: &str, ja4: &str) -> Item {
    Item::Hello { os: "linux 6".into(), transport: "tcp".into(), ja4: ja4.into(), app: app(name, "cli") }
}

fn domain(name: &str, kind: &str, d: &str) -> Item {
    let mut a = app(name, kind);
    a.version = None;
    Item::Domain { os: "linux 6".into(), app: a, domain: d.into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into() }
}

const DAY: i64 = 86400;

#[tokio::test(flavor = "multi_thread")]
async fn observers_report_daily_and_are_published_without_threshold() {
    // Day 10 (UTC) of a collection whose weeks start at 0.
    let now = Arc::new(AtomicI64::new(10 * DAY + 3600));
    let clock = {
        let now = now.clone();
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    let conn = db::open(":memory:").unwrap();
    let (o1, o2, p1) = (db::new_observer_code(), db::new_observer_code(), db::new_code());
    assert!(o1.starts_with("OBS-") && peersig_proto::code::is_observer(&o1) && !peersig_proto::code::is_observer(&p1));
    db::add_observer_code(&conn, &o1, "O01").unwrap();
    db::add_observer_code(&conn, &o2, "O02").unwrap();
    db::add_code(&conn, &p1, "P01").unwrap();
    let settings = Settings { epochs: EpochSpec { origin: 0, length: EpochSpec::WEEK }, tokens_per_epoch: 4, k_hello: 3, k_domain: 5, about_url: None };
    let state = State::new(conn, settings, clock).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let site = web::Web { state: state.clone(), enroll: Enrollment::new("https://peersig.example.org", None, 3, 60), notice: None };
    let router = api::router(state.clone()).merge(web::router(Arc::new(site)));
    tokio::spawn(async move { axum::serve(listener, router).await });
    let c = Client::new(&url, None).unwrap();
    let http = reqwest::Client::new();

    let a = hello("curl", "t13d1516h2_8daaf6152771_e5627efa2ab1");
    let b = hello("wget", "t13d1516h2_8daaf6152771_000000000001");
    let x = domain("curl", "cli", "api.example.com");
    let report = |code: &str, day: u32, items: Vec<Item>| ObserverReport { code: code.into(), day, items };

    // Yesterday (day 9), with a duplicate.
    let r = c.observe(&report(&o1, 9, vec![a.clone(), x.clone(), a.clone()])).await.unwrap().expect("counted");
    assert_eq!((r.label.as_str(), r.day, r.items), ("O01", 9, 2));
    // Once per observer and day; the lowercase form of the code works too.
    assert!(c.observe(&report(&o1.to_lowercase(), 9, vec![b.clone()])).await.unwrap().is_none(), "second report of a day");
    c.observe(&report(&o2, 9, vec![a.clone(), b.clone()])).await.unwrap().expect("counted");
    // A late day, within the window.
    c.observe(&report(&o2, 3, vec![b.clone()])).await.unwrap().expect("late day counted");

    // What a code is, as `peersig configure` asks.
    let st = c.code_info(&o1.to_lowercase()).await.unwrap();
    assert_eq!((st.observer, st.label.as_deref(), st.days, st.last_day.as_deref()), (true, Some("O01"), 1, Some("1970-01-10")));
    assert_eq!(c.code_info(&o2).await.unwrap().days, 2, "day 9 and a late day 3");
    let p = c.code_info(&p1).await.unwrap();
    assert!(!p.observer && p.label.is_none(), "a participant's code says nothing more");
    assert!(c.code_info("OBS-AAAA-BBBB-CCCC").await.unwrap_err().to_string().contains("unknown"));

    // Refusals.
    let e = |r: anyhow::Result<_>| r.map(|_: Option<_>| ()).unwrap_err().to_string();
    assert!(e(c.observe(&report(&o1, 10, vec![a.clone()])).await).contains("accepted for the days"), "today is not over");
    assert!(e(c.observe(&report(&o1, 2, vec![a.clone()])).await).contains("accepted for the days"), "too late");
    assert!(e(c.observe(&report(&p1, 9, vec![a.clone()])).await).contains("not a dedicated observer"));
    assert!(e(c.observe(&report("OBS-AAAA-BBBB-CCCC", 9, vec![a.clone()])).await).contains("unknown"));
    assert!(e(c.observe(&report(&o1, 8, vec![Item::Presence { shares_domains: true }])).await).contains("presence"));
    assert!(e(c.observe(&report(&o1, 8, vec![])).await).contains("empty"));
    assert!(e(c.observe(&report(&o1, 8, vec![domain("Safari", "browser", "news.example.org")])).await).contains("browsers"));
    // A refused report does not use up the day.
    c.observe(&report(&o1, 8, vec![a.clone()])).await.unwrap().expect("day 8 still open");
    // An observer's code gets no ballot tokens: its items must never count
    // among the participants'.
    let mut cc = Client::new(&url, None).unwrap();
    let cfg = cc.config().await.unwrap();
    let blinded = token::blind(&cfg.token_key.public_key, cfg.report_epoch, 1).unwrap();
    let issue = IssueRequest { code: o1.clone(), epoch: cfg.report_epoch, blinded: vec![blinded[0].blind_message.clone()] };
    assert!(cc.issue(&issue).await.unwrap_err().to_string().contains("observer"));
    db::revoke(&state.db.lock().unwrap(), "O02").unwrap();
    assert!(e(c.observe(&report(&o2, 8, vec![a.clone()])).await).contains("withdrawn"));
    // Body over the participants' limit (512 kB) but within the observers'.
    let many: Vec<Item> = (0..3000).map(|i| hello(&format!("tool-{:05}-{}", i, "x".repeat(100)), "t13d1516h2_8daaf6152771_e5627efa2ab1")).collect();
    let body = serde_json::to_vec(&report(&o1, 7, many)).unwrap();
    assert!(body.len() > 512 * 1024);
    let resp = http.post(format!("{}{}", url, PATH_OBSERVE)).header("content-type", "application/json").body(body).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // The table: each day, every item, no threshold.
    let days: ObservedDays = http.get(format!("{}{}", url, PATH_OBSERVED)).send().await.unwrap().json().await.unwrap();
    let summary: Vec<(String, u32, u32)> = days.days.iter().map(|d| (d.day.clone(), d.observers, d.items)).collect();
    assert_eq!(
        summary,
        [("1970-01-10".into(), 2, 3), ("1970-01-09".into(), 1, 1), ("1970-01-08".into(), 1, 3000), ("1970-01-04".into(), 1, 1)]
    );
    let day: ObservedDay = http.get(format!("{}{}/1970-01-10", url, PATH_OBSERVED)).send().await.unwrap().json().await.unwrap();
    assert_eq!(day.observers, 2);
    let n = |it: &Item| day.items.iter().find(|o| o.item == *it).map(|o| o.observers);
    assert_eq!((n(&a), n(&b), n(&x)), (Some(2), Some(1), Some(1)));
    let resp = http.get(format!("{}{}/not-a-day", url, PATH_OBSERVED)).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);

    // The same on the site's data page: the last day by default, any day asked for.
    let page = |q: &str| {
        let u = format!("{}/data{}", url, q);
        let http = http.clone();
        async move { http.get(u).send().await.unwrap().text().await.unwrap() }
    };
    let p = page("").await;
    assert!(p.contains("1970-01-10: 2 observers reported 3 items") && p.contains("api.example.com") && p.contains("<b>wget</b>"), "{}", p);
    assert!(p.contains(r#"<option value="1970-01-04">"#) && p.contains("Nothing published yet"));
    let p = page("?day=1970-01-04").await;
    assert!(p.contains("1970-01-04: 1 observer reported 1 item") && !p.contains("api.example.com"));
    assert!(page("?day=1999-01-01").await.contains("1970-01-10: 2 observers"), "an unknown day shows the last");

    // Participants' table and counts: untouched.
    now.store(3 * EpochSpec::WEEK, Ordering::SeqCst);
    let released: Released = http.get(format!("{}{}", url, PATH_RELEASED)).send().await.unwrap().json().await.unwrap();
    assert!(released.items.is_empty());
    let db = state.db.lock().unwrap();
    let counts: i64 = db.query_row("SELECT COUNT(*) FROM counts", [], |r| r.get(0)).unwrap();
    assert_eq!(counts, 0);
    let codes = db::list_codes(&db).unwrap();
    let o = codes.iter().find(|c| c.label == "O01").unwrap();
    assert!(o.observer && o.epochs.keys().copied().collect::<Vec<_>>() == [7, 8, 9]);
}

/// A database made before observers existed gets the column, and its
/// codes stay participants' codes.
#[test]
fn older_databases_are_migrated() {
    let path = std::env::temp_dir().join(format!("peersig-migrate-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE codes(hash TEXT PRIMARY KEY, label TEXT NOT NULL, created TEXT NOT NULL,
                 revoked INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;",
        )
        .unwrap();
        c.execute("INSERT INTO codes(hash, label, created) VALUES(?1, 'P01', '2026-11-01')", [db::code_hash("K7QF-2M9D-XW4P")]).unwrap();
    }
    let c = db::open(path.to_str().unwrap()).unwrap();
    let s = db::code_status(&c, &db::code_hash("K7QF-2M9D-XW4P")).unwrap().unwrap();
    assert!(s.active && !s.observer && s.label == "P01");
    drop(c);
    // Opening again does not try to add it twice.
    db::open(path.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_file(&path);
}

/// Counters stored under the key of an older app's item (PeerSig up to
/// 0.1.9 sent a second, non-standard JA4) join the item's current key when
/// the server starts, for participants and observers alike.
#[test]
fn older_item_keys_join_the_current_one() {
    let path = std::env::temp_dir().join(format!("peersig-keys-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let item = hello("curl", "t13d1516h2_8daaf6152771_e5627efa2ab1");
    let old = item.key().replacen("\"ja4\":", "\"ja4_legacy\":\"t13d1516h2_8daaf6152771_02713d6af862\",\"ja4\":", 1);
    assert_ne!(old, item.key());
    let tables = [("counts", "epoch"), ("observed", "day")];
    {
        let c = db::open(path.to_str().unwrap()).unwrap();
        for (table, period) in tables {
            let add = |p: i64, key: &str, n: i64| {
                c.execute(
                    &format!("INSERT INTO {table}({period}, item, class, n) VALUES(?1, ?2, ?3, ?4)"),
                    rusqlite::params![p, key, item.class().name(), n],
                )
                .unwrap()
            };
            add(5, &old, 2);
            add(5, &item.key(), 3);
            add(6, &old, 1);
        }
    }
    let c = db::open(path.to_str().unwrap()).unwrap();
    for (table, period) in tables {
        let mut st = c.prepare(&format!("SELECT {period}, item, n FROM {table} ORDER BY {period}")).unwrap();
        let rows: Vec<(i64, String, i64)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(rows, vec![(5, item.key(), 5), (6, item.key(), 1)], "{}", table);
    }
    drop(c);
    let _ = std::fs::remove_file(&path);
}
