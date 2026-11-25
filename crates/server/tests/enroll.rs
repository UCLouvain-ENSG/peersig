//! Enrollment from the web page: a code by e-mail or with a GitHub account
//! (against a stand-in for GitHub), which then gets tokens. The database
//! keeps neither the address nor a link between it and the code.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::Form;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use peersig_proto::client::Client;
use peersig_proto::token;
use peersig_proto::wire::IssueRequest;
use peersig_proto::EpochSpec;
use peersig_server::enroll::{Enrollment, GitHub, Mail, Network};
use peersig_server::{api, db, system_clock, web, Settings, State};

async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await });
    url
}

/// As `peersig-server serve` does: handlers can see the connection's address.
async fn serve_with_peer(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await });
    url
}

fn state() -> Arc<State> {
    let now = chrono::Utc::now().timestamp();
    let settings = Settings {
        epochs: EpochSpec { origin: now - 1500, length: 1000 },
        tokens_per_epoch: 2,
        k_hello: 1,
        k_domain: 1,
        about_url: None,
    };
    State::new(db::open(":memory:").unwrap(), settings, system_clock()).unwrap()
}

/// The first `XXXX-XXXX-XXXX` in a text.
fn find_code(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .find(|w| w.len() == 14 && w.split('-').map(str::len).eq([4, 4, 4]) && w.chars().all(|c| c == '-' || c.is_ascii_digit() || c.is_ascii_uppercase()))
        .map(String::from)
}

/// The code gets the epoch's tokens.
async fn works(server: &str, code: &str) {
    let mut c = Client::new(server, None).unwrap();
    let cfg = c.config().await.unwrap();
    let blinded = token::blind(&cfg.token_key.public_key, cfg.report_epoch, 2).unwrap();
    let req = IssueRequest { code: code.into(), epoch: cfg.report_epoch, blinded: blinded.iter().map(|b| b.blind_message.clone()).collect() };
    let resp = c.issue(&req).await.unwrap();
    token::finalize(&cfg.token_key.public_key, &blinded, &resp.signatures).unwrap();
}

/// Every text value in the database.
fn dump(s: &State) -> String {
    let db = s.db.lock().unwrap();
    let mut out = String::new();
    for t in ["meta", "codes", "issuance", "identities"] {
        let mut st = db.prepare(&format!("SELECT * FROM {}", t)).unwrap();
        let n = st.column_count();
        let rows = st
            .query_map([], |r| {
                Ok((0..n).map(|i| r.get::<_, rusqlite::types::Value>(i).map(|v| format!("{:?}", v)).unwrap_or_default()).collect::<Vec<_>>().join(" "))
            })
            .unwrap();
        for r in rows {
            out.push_str(&r.unwrap());
            out.push('\n');
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn code_by_mail() {
    let state = state();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut e = Enrollment::new("https://peersig.example.org", Some("https://relay.example.net"), 3, 60);
    e.contact = Some("team@example.org".into());
    e.mail = Some(Mail::memory("PeerSig <peersig@example.org>", sent.clone()).unwrap());
    let notice = web::Notice { text: "Pilot <phase>.".into(), url: Some("/privacy#relay".into()) };
    let url = serve(api::router(state.clone()).merge(web::router(Arc::new(web::Web { state: state.clone(), enroll: e, notice: Some(notice) })))).await;
    let http = reqwest::Client::new();

    let home = http.get(format!("{}/participate", url)).send().await.unwrap().text().await.unwrap();
    assert!(home.contains(r#"action="/enroll/mail""#) && home.contains("flood"), "{}", home);
    assert!(home.contains("mailto:team@example.org"));
    // The notice is text, with its link after it.
    assert!(home.contains(r#"<p class="notice">Pilot &lt;phase&gt;. <a href="/privacy#relay">More on this</a>.</p>"#), "{}", home);

    // The home page and its assets, under a policy that allows no inline script.
    let r = http.get(&url).send().await.unwrap();
    let csp = r.headers()["content-security-policy"].to_str().unwrap().to_string();
    assert!(csp.contains("script-src 'self'") && !csp.contains("unsafe-inline"), "{}", csp);
    let index = r.text().await.unwrap();
    assert!(index.contains(r#"href="/participate""#) && !index.contains("{{"), "unfilled placeholder");
    for (a, kind) in [("site.css", "text/css"), ("site.js", "text/javascript"), ("hero.js", "text/javascript"), ("logo.svg", "image/svg+xml")] {
        let r = http.get(format!("{}/assets/{}", url, a)).send().await.unwrap();
        assert_eq!(r.status(), 200, "{}", a);
        assert!(r.headers()["content-type"].to_str().unwrap().starts_with(kind), "{}", a);
    }
    assert!(!home.contains("{{"), "unfilled placeholder");
    assert!(!home.contains("/enroll/github"), "GitHub is not configured");

    // The privacy policy (the Android app links to it), with this server's numbers.
    let r = http.get(format!("{}/privacy", url)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let policy = r.text().await.unwrap();
    assert!(policy.contains("<h1>Privacy policy</h1>") && policy.contains("mailto:team@example.org"), "{}", policy);
    assert!(policy.contains("(at most 3;") && !policy.contains("{{"), "unfilled placeholder");
    assert!(index.contains(r#"href="/privacy""#), "the footer links to the policy");

    let post = |email: &str| http.post(format!("{}/enroll/mail", url)).form(&[("email", email)]).send();
    let r = post("Alice+PeerSig@Example.org").await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("Check your mailbox"));
    let msg = {
        let v = sent.lock().unwrap();
        assert_eq!(v.len(), 1);
        String::from_utf8(v[0].formatted()).unwrap()
    };
    assert!(msg.contains("To: alice+peersig@example.org"), "{}", msg);
    assert!(msg.contains("MIME-Version: 1.0"), "{}", msg);
    let mid = msg.lines().find(|l| l.starts_with("Message-ID: <")).expect("a Message-ID");
    assert!(mid.ends_with("@example.org>"), "{}", mid);
    assert!(msg.contains("https://relay.example.net") && msg.contains("Questions: team@example.org"));
    let code = find_code(&msg).expect("a code in the message");
    works(&url, &code).await;

    // Same mailbox (the +tag does not count) a minute later: same answer,
    // no second message.
    let r = post("alice@example.org").await.unwrap();
    assert!(r.text().await.unwrap().contains("Check your mailbox"));
    assert_eq!(sent.lock().unwrap().len(), 1);

    let r = post("not an address").await.unwrap();
    assert_eq!(r.status(), 400);

    // A label and a code hash, a keyed hash and a count: no address.
    let d = dump(&state);
    assert!(d.contains("M01"));
    assert!(!d.to_lowercase().contains("alice") && !d.contains("example.org"), "{}", d);
    let n: u32 = state.db.lock().unwrap().query_row("SELECT codes FROM identities", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1);
}

#[test]
fn codes_per_identity() {
    let mut c = db::open(":memory:").unwrap();
    let t = 1_795_000_000; // a Wednesday
    assert!(db::enroll(&mut c, "h", "M", 2, t).unwrap().is_some());
    let (code, label) = db::enroll(&mut c, "h", "M", 2, t).unwrap().unwrap();
    assert_eq!(label, "M02");
    assert!(db::enroll(&mut c, "h", "M", 2, t).unwrap().is_none());
    assert!(db::enroll(&mut c, "other", "G", 2, t).unwrap().is_some());
    // A code that could not be delivered is forgotten, and counts no more.
    db::unenroll(&mut c, "h", &code).unwrap();
    assert_eq!(db::code_active(&c, &db::code_hash(&code)).unwrap(), None);
    assert!(db::enroll(&mut c, "h", "M", 2, t).unwrap().is_some());
    assert!(db::enroll(&mut c, "h", "M", 2, t).unwrap().is_none());
}

/// One more code each week once the limit is reached, and no more than the
/// limit at once after weeks without asking. Nothing per identity says when.
#[test]
fn codes_renew_each_week() {
    let mut c = db::open(":memory:").unwrap();
    let day = 86400;
    let t = 1_795_000_000; // a Wednesday
    let monday = (db::week(t) + 1) * 7 * day - 3 * day;
    assert_eq!(db::week(monday), db::week(t) + 1);
    assert_eq!(db::week(monday - 1), db::week(t));
    let n = |c: &mut rusqlite::Connection, at: i64| (0..10).take_while(|_| db::enroll(c, "h", "M", 5, at).unwrap().is_some()).count();
    assert_eq!(n(&mut c, t), 5);
    // Later the same week: none. From Monday: one.
    assert_eq!(n(&mut c, monday - 1), 0);
    assert_eq!(n(&mut c, monday), 1);
    assert_eq!(n(&mut c, monday + 6 * day), 0);
    // Three weeks without asking: three, not more.
    assert_eq!(n(&mut c, monday + 21 * day), 3);
    // Ten weeks: back to the full five, and the row went in between.
    assert!(db::enroll(&mut c, "other", "G", 5, monday + 70 * day).unwrap().is_some());
    let rows: Vec<(String, u32)> = {
        let mut st = c.prepare("SELECT hash, codes FROM identities").unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(rows, vec![("other".to_string(), 1)]);
    assert_eq!(n(&mut c, monday + 70 * day), 5);
    // The clock going back changes nothing.
    assert_eq!(n(&mut c, t), 0);
}

/// Stands in for github.com and api.github.com.
async fn fake_github() -> String {
    async fn token(Form(f): Form<Vec<(String, String)>>) -> Json<serde_json::Value> {
        let get = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or_default();
        assert_eq!((get("client_id"), get("client_secret")), ("cid", "secret"));
        assert!(get("redirect_uri").ends_with("/enroll/github/callback"));
        match get("code") {
            "old" | "young" => Json(serde_json::json!({ "access_token": format!("tok-{}", get("code")), "token_type": "bearer" })),
            _ => Json(serde_json::json!({ "error": "bad_verification_code", "error_description": "The code is incorrect or expired." })),
        }
    }
    async fn user(h: HeaderMap) -> Json<serde_json::Value> {
        let created = match h.get("authorization").and_then(|v| v.to_str().ok()) {
            Some("Bearer tok-old") => "2015-03-01T10:00:00Z".to_string(),
            Some("Bearer tok-young") => (chrono::Utc::now() - chrono::Days::new(2)).to_rfc3339(),
            other => panic!("unexpected authorization {:?}", other),
        };
        Json(serde_json::json!({ "login": "octo", "id": 4242, "created_at": created }))
    }
    serve(Router::new().route("/login/oauth/access_token", post(token)).route("/user", get(user))).await
}

/// The page sends the browser to GitHub with a state only it can make.
async fn start(http: &reqwest::Client, url: &str) -> String {
    let r = http.get(format!("{}/enroll/github", url)).send().await.unwrap();
    assert!(r.status().is_redirection());
    let to = reqwest::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    assert_eq!(to.path(), "/login/oauth/authorize");
    let q: Vec<(String, String)> = to.query_pairs().into_owned().collect();
    assert!(q.contains(&("client_id".into(), "cid".into())));
    assert!(!q.iter().any(|(k, _)| k == "scope"), "no permission is asked for");
    q.into_iter().find(|(k, _)| k == "state").unwrap().1
}

#[tokio::test(flavor = "multi_thread")]
async fn code_with_github() {
    let state = state();
    let gh = fake_github().await;
    let mut e = Enrollment::new("https://peersig.example.org", None, 3, 60);
    e.github = Some(GitHub::with_endpoints("cid", "secret", 30, &gh, &gh).unwrap());
    let url = serve(api::router(state.clone()).merge(web::router(Arc::new(web::Web { state: state.clone(), enroll: e, notice: None })))).await;
    let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();

    let home = http.get(format!("{}/participate", url)).send().await.unwrap().text().await.unwrap();
    assert!(home.contains("/enroll/github") && !home.contains("/enroll/mail"));

    let back = |code: &str, st: &str| {
        http.get(reqwest::Url::parse_with_params(&format!("{}/enroll/github/callback", url), &[("code", code), ("state", st)]).unwrap()).send()
    };

    let st = start(&http, &url).await;
    let r = back("old", &st).await.unwrap();
    assert_eq!(r.status(), 200);
    let page = r.text().await.unwrap();
    let code = find_code(&page).expect("a code on the page");
    works(&url, &code).await;

    // A state this server did not make, a refused sign-in, a new account.
    let r = back("old", &format!("{}x", st)).await.unwrap();
    assert_eq!(r.status(), 400);
    let r = back("expired", &start(&http, &url).await).await.unwrap();
    assert!(r.text().await.unwrap().contains("incorrect or expired"));
    let r = back("young", &start(&http, &url).await).await.unwrap();
    assert_eq!(r.status(), 403);

    // Three codes per account, then no more.
    for _ in 0..2 {
        let p = back("old", &start(&http, &url).await).await.unwrap().text().await.unwrap();
        assert!(find_code(&p).is_some());
    }
    let p = back("old", &start(&http, &url).await).await.unwrap().text().await.unwrap();
    assert!(find_code(&p).is_none() && p.contains("enough codes"), "{}", p);
    let d = dump(&state);
    assert!(d.contains("G01") && !d.contains("octo") && !d.contains("tok-"), "{}", d);
}

#[tokio::test(flavor = "multi_thread")]
async fn code_from_the_network() {
    let state = state();
    let campus = |header: Option<&str>| Network {
        name: "UCLouvain".into(),
        blocks: vec!["130.104.0.0/16".parse().unwrap(), "2001:6a8:3080::/44".parse().unwrap()],
        address_header: header.map(String::from),
    };
    let mut e = Enrollment::new("https://peersig.example.org", None, 3, 60);
    e.network = Some(campus(Some("x-peersig-client")));
    let url = serve_with_peer(api::router(state.clone()).merge(web::router(Arc::new(web::Web { state: state.clone(), enroll: e, notice: None })))).await;
    let http = reqwest::Client::new();

    let home = http.get(format!("{}/participate", url)).send().await.unwrap().text().await.unwrap();
    assert!(home.contains("On the UCLouvain network") && home.contains(r#"action="/enroll/network""#));

    // The proxy on this machine (the test client, from 127.0.0.1) says who
    // the visitor is; only the last entry counts.
    let from = |a: Option<&str>| {
        let r = http.post(format!("{}/enroll/network", url));
        match a {
            Some(a) => r.header("x-peersig-client", a),
            None => r,
        }
        .send()
    };
    for inside in ["130.104.229.17", "2001:6a8:3081::42", "198.51.100.9, 130.104.1.1"] {
        let r = from(Some(inside)).await.unwrap();
        assert_eq!(r.status(), 200, "{}", inside);
        let code = find_code(&r.text().await.unwrap()).expect("a code");
        works(&url, &code).await;
    }
    for outside in [Some("193.0.0.1"), Some("130.104.1.1, 198.51.100.9"), Some("2001:6a8:3180::1"), Some("garbage"), None] {
        let r = from(outside).await.unwrap();
        assert_eq!(r.status(), 403, "{:?}", outside);
        assert!(find_code(&r.text().await.unwrap()).is_none());
    }
    let d = dump(&state);
    assert!(d.contains("N01") && !d.contains("130.104") && !d.contains("2001:6a8"), "{}", d);

    // Without a proxy, the connection's own address counts: 127.0.0.1 is
    // not on campus, whatever the header says.
    let state = self::state();
    let mut e = Enrollment::new("https://peersig.example.org", None, 3, 60);
    e.network = Some(campus(None));
    let url = serve_with_peer(web::router(Arc::new(web::Web { state, enroll: e, notice: None }))).await;
    let r = http.post(format!("{}/enroll/network", url)).header("x-peersig-client", "130.104.1.1").send().await.unwrap();
    assert_eq!(r.status(), 403);
}
