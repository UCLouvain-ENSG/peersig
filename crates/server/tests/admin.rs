//! The admin page (codes and bans, behind a GitHub sign-in), and the limits
//! on enrollment it works with: bans and the per-address count.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Path};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use peersig_proto::client::Client;
use peersig_proto::token;
use peersig_proto::wire::IssueRequest;
use peersig_proto::EpochSpec;
use peersig_server::enroll::{Enrollment, GitHub, Mail, ADMIN_CALLBACK};
use peersig_server::{api, db, system_clock, web, Settings, State};

async fn serve(app: Router, with_peer: bool) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    if with_peer {
        tokio::spawn(async move { axum::serve(l, app.into_make_service_with_connect_info::<SocketAddr>()).await });
    } else {
        tokio::spawn(async move { axum::serve(l, app).await });
    }
    url
}

fn state() -> Arc<State> {
    let now = chrono::Utc::now().timestamp();
    let settings = Settings { epochs: EpochSpec { origin: now - 1500, length: 1000 }, tokens_per_epoch: 2, k_hello: 1, k_domain: 1, about_url: None };
    State::new(db::open(":memory:").unwrap(), settings, system_clock()).unwrap()
}

fn find_codes(text: &str) -> Vec<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|w| w.len() == 14 && w.split('-').map(str::len).eq([4, 4, 4]) && w.chars().all(|c| c == '-' || c.is_ascii_digit() || c.is_ascii_uppercase()))
        .map(String::from)
        .collect()
}

/// Whether the code gets the epoch's tokens.
async fn works(server: &str, code: &str) -> bool {
    let mut c = Client::new(server, None).unwrap();
    let cfg = c.config().await.unwrap();
    let blinded = token::blind(&cfg.token_key.public_key, cfg.report_epoch, 1).unwrap();
    let req = IssueRequest { code: code.into(), epoch: cfg.report_epoch, blinded: blinded.iter().map(|b| b.blind_message.clone()).collect() };
    c.issue(&req).await.is_ok()
}

/// Stands in for github.com and api.github.com: "octo" is an admin, "eve"
/// is not, "spammer" is an old account that will be banned.
async fn fake_github() -> String {
    async fn token(Form(f): Form<Vec<(String, String)>>) -> Json<serde_json::Value> {
        let get = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str()).unwrap_or_default();
        let uri = get("redirect_uri");
        assert!(uri.ends_with("/enroll/github/callback") || uri.ends_with(ADMIN_CALLBACK), "{}", uri);
        Json(serde_json::json!({ "access_token": format!("tok-{}", get("code")), "token_type": "bearer" }))
    }
    async fn user(h: HeaderMap) -> Json<serde_json::Value> {
        let (login, id) = match h.get("authorization").and_then(|v| v.to_str().ok()) {
            Some("Bearer tok-octo") => ("Octo", 4242),
            Some("Bearer tok-eve") => ("eve", 7),
            Some("Bearer tok-spammer") => ("spammer", 99),
            other => panic!("unexpected authorization {:?}", other),
        };
        Json(serde_json::json!({ "login": login, "id": id, "created_at": "2015-03-01T10:00:00Z" }))
    }
    async fn users(Path(login): Path<String>) -> axum::response::Response {
        match login.as_str() {
            "spammer" => Json(serde_json::json!({ "login": "spammer", "id": 99 })).into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        }
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let app = Router::new().route("/login/oauth/access_token", post(token)).route("/user", get(user)).route("/users/{login}", get(users));
    tokio::spawn(async move { axum::serve(l, app).await });
    url
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
}

/// Follows a sign-in from `start` (/admin/login or /enroll/github): the
/// `state` GitHub would hand back.
async fn state_from(http: &reqwest::Client, url: &str, start: &str) -> (String, String) {
    let r = http.get(format!("{}{}", url, start)).send().await.unwrap();
    assert!(r.status().is_redirection(), "{}", start);
    let to = reqwest::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
    let q: Vec<(String, String)> = to.query_pairs().into_owned().collect();
    let get = |k: &str| q.iter().find(|(n, _)| n == k).unwrap().1.clone();
    (get("state"), get("redirect_uri"))
}

async fn back(http: &reqwest::Client, url: &str, path: &str, code: &str, st: &str) -> reqwest::Response {
    http.get(reqwest::Url::parse_with_params(&format!("{}{}", url, path), &[("code", code), ("state", st)]).unwrap()).send().await.unwrap()
}

/// Signs in as `who` and returns the session cookie.
async fn sign_in(http: &reqwest::Client, url: &str, who: &str) -> Option<String> {
    let (st, uri) = state_from(http, url, "/admin/login").await;
    assert!(uri.ends_with(ADMIN_CALLBACK), "{}", uri);
    let r = back(http, url, ADMIN_CALLBACK, who, &st).await;
    let c = r.headers().get("set-cookie").map(|v| v.to_str().unwrap().to_string());
    if r.status() != StatusCode::SEE_OTHER {
        assert!(c.is_none());
        return None;
    }
    let c = c.unwrap();
    assert!(c.contains("HttpOnly") && c.contains("Secure") && c.contains("SameSite=Lax") && c.contains("Path=/admin"), "{}", c);
    Some(c.split(';').next().unwrap().to_string())
}

async fn admin_page(http: &reqwest::Client, url: &str, cookie: &str) -> String {
    http.get(format!("{}/admin", url)).header("cookie", cookie).send().await.unwrap().text().await.unwrap()
}

fn csrf(page: &str) -> String {
    let i = page.find(r#"name="csrf" value=""#).expect("a form") + r#"name="csrf" value=""#.len();
    page[i..i + page[i..].find('"').unwrap()].to_string()
}

async fn send(http: &reqwest::Client, url: &str, path: &str, cookie: &str, form: &[(&str, &str)]) -> reqwest::Response {
    http.post(format!("{}{}", url, path)).header("cookie", cookie).form(form).send().await.unwrap()
}

fn with_admin(e: &mut Enrollment, gh: &str) {
    e.github = Some(GitHub::with_endpoints("cid", "secret", 30, gh, gh).unwrap());
    e.admins = vec!["octo".into()];
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_and_codes() {
    let state = state();
    let gh = fake_github().await;
    let mut e = Enrollment::new("https://peersig.example.org", None, 3, 60);
    with_admin(&mut e, &gh);
    let url = serve(api::router(state.clone()).merge(web::router(Arc::new(web::Web { state: state.clone(), enroll: e, notice: None }))), false).await;
    let http = http();

    let p = http.get(format!("{}/admin", url)).send().await.unwrap().text().await.unwrap();
    assert!(p.contains(r#"href="/admin/login""#) && !p.contains("csrf"), "{}", p);

    // Not an admin; a state made for enrollment; a forged cookie.
    assert!(sign_in(&http, &url, "eve").await.is_none());
    let (st, _) = state_from(&http, &url, "/enroll/github").await;
    assert_eq!(back(&http, &url, ADMIN_CALLBACK, "octo", &st).await.status(), StatusCode::BAD_REQUEST);
    let cookie = sign_in(&http, &url, "octo").await.expect("octo is an admin (whatever the case of the login)");
    let forged = cookie.replacen("octo.", "eve.", 1);
    assert!(admin_page(&http, &url, &forged).await.contains("/admin/login"));

    let page = admin_page(&http, &url, &cookie).await;
    assert!(page.contains("Signed in as <b>octo</b>") && page.contains("No codes yet"), "{}", page);
    let token = csrf(&page);

    // Two codes, shown once; both work.
    let r = send(&http, &url, "/admin/codes", &cookie, &[("csrf", &token), ("count", "2"), ("prefix", "T")]).await;
    assert_eq!(r.status(), 200);
    let codes = find_codes(&r.text().await.unwrap());
    assert_eq!(codes.len(), 2);
    for c in &codes {
        assert!(works(&url, c).await);
    }
    let page = admin_page(&http, &url, &cookie).await;
    assert!(page.contains("<b>T01</b>") && page.contains("<b>T02</b>") && find_codes(&page).is_empty(), "codes are shown once");

    // Forms need the session's token.
    for bad in ["", "AAAA", "x"] {
        let r = send(&http, &url, "/admin/codes", &cookie, &[("csrf", bad), ("count", "1"), ("prefix", "X")]).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{:?}", bad);
    }
    let r = send(&http, &url, "/admin/codes", "", &[("csrf", &token), ("count", "1"), ("prefix", "X")]).await;
    assert!(r.status().is_redirection(), "no session: back to the sign-in");

    // Revoke T01 by label: no more tokens; restore it.
    let hash = db::code_hash(&codes[0]);
    let r = send(&http, &url, "/admin/codes/revoke", &cookie, &[("csrf", &token), ("label", "T01")]).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let to = r.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(db::code_active(&state.db.lock().unwrap(), &hash).unwrap(), Some(false));
    assert!(!works(&url, &codes[0]).await);
    let p = http.get(format!("{}{}", url, to)).header("cookie", &cookie).send().await.unwrap().text().await.unwrap();
    assert!(p.contains("Revoked T01.") && p.contains(r#"<tr class="revoked">"#), "{}", to);
    let r = send(&http, &url, "/admin/codes/revoke", &cookie, &[("csrf", &token), ("label", "T01"), ("restore", "1")]).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(db::code_active(&state.db.lock().unwrap(), &hash).unwrap(), Some(true));
    let r = send(&http, &url, "/admin/codes/revoke", &cookie, &[("csrf", &token), ("label", "nope")]).await;
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    let r = send(&http, &url, "/admin/logout", &cookie, &[("csrf", &token)]).await;
    assert!(r.headers()["set-cookie"].to_str().unwrap().contains("Max-Age=0"));

    // Without admins, no admin page at all.
    let mut e = Enrollment::new("https://peersig.example.org", None, 3, 60);
    e.github = Some(GitHub::with_endpoints("cid", "secret", 30, &gh, &gh).unwrap());
    let url = serve(web::router(Arc::new(web::Web { state: self::state(), enroll: e, notice: None })), false).await;
    assert_eq!(http.get(format!("{}/admin", url)).send().await.unwrap().status(), StatusCode::NOT_FOUND);
    assert_eq!(http.get(format!("{}/admin/login", url)).send().await.unwrap().status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn bans() {
    let state = state();
    let gh = fake_github().await;
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut e = Enrollment::new("https://peersig.example.org", None, 3, 60);
    with_admin(&mut e, &gh);
    e.mail = Some(Mail::memory("PeerSig <peersig@example.org>", sent.clone()).unwrap());
    let url = serve(api::router(state.clone()).merge(web::router(Arc::new(web::Web { state: state.clone(), enroll: e, notice: None }))), false).await;
    let http = http();
    let cookie = sign_in(&http, &url, "octo").await.unwrap();
    let token = csrf(&admin_page(&http, &url, &cookie).await);
    let ban = |kind: &'static str, value: &'static str| {
        let (http, url, cookie, token) = (http.clone(), url.clone(), cookie.clone(), token.clone());
        async move { send(&http, &url, "/admin/bans", &cookie, &[("csrf", &token), ("kind", kind), ("value", value), ("note", "spam run")]).await.status() }
    };
    assert_eq!(ban("mail", "Spam+x@Example.org").await, StatusCode::SEE_OTHER);
    assert_eq!(ban("domain", "@junk.example").await, StatusCode::SEE_OTHER);
    assert_eq!(ban("github", "spammer").await, StatusCode::SEE_OTHER);
    assert_eq!(ban("github", "nobody").await, StatusCode::BAD_REQUEST);
    assert_eq!(ban("domain", "example").await, StatusCode::BAD_REQUEST);
    assert_eq!(ban("mail", "not an address").await, StatusCode::BAD_REQUEST);

    // Banned: the same answer as for anyone, and no message.
    let mail = |to: &'static str| {
        let (http, url) = (http.clone(), url.clone());
        async move { http.post(format!("{}/enroll/mail", url)).form(&[("email", to)]).send().await.unwrap().text().await.unwrap() }
    };
    for to in ["spam@example.org", "someone@junk.example", "a@mx.junk.example"] {
        assert!(mail(to).await.contains("Check your mailbox"), "{}", to);
    }
    assert_eq!(sent.lock().unwrap().len(), 0);
    assert!(mail("fine@example.org").await.contains("Check your mailbox"));
    assert_eq!(sent.lock().unwrap().len(), 1);

    // A banned GitHub account is told so.
    let (st, _) = state_from(&http, &url, "/enroll/github").await;
    let r = back(&http, &url, "/enroll/github/callback", "spammer", &st).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(r.text().await.unwrap().contains("cannot get a code"));

    // The list shows the domain, and neither the address nor the login.
    let page = admin_page(&http, &url, &cookie).await;
    assert!(page.contains("<code>junk.example</code>") && page.contains("spam run"), "{}", page);
    assert!(!page.contains("spam@") && !page.contains(">spammer<"), "{}", page);
    let stored: Vec<(String, String)> = {
        let db = state.db.lock().unwrap();
        db::list_bans(&db).unwrap().into_iter().map(|b| (b.kind, b.value)).collect()
    };
    assert_eq!(stored.len(), 3);
    assert!(stored.iter().all(|(_, v)| !v.contains("spam") && !v.contains("example.org")), "{:?}", stored);

    // Lifting the domain ban.
    let r = send(&http, &url, "/admin/bans/remove", &cookie, &[("csrf", &token), ("kind", "domain"), ("value", "junk.example")]).await;
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    mail("a@mx.junk.example").await;
    assert_eq!(sent.lock().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn per_address() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let mut e = Enrollment::new("https://peersig.example.org", None, 3, 60);
    e.mail = Some(Mail::memory("PeerSig <peersig@example.org>", sent.clone()).unwrap());
    e.per_address = 2;
    e.address_header = Some("x-peersig-client".into());
    let url = serve(web::router(Arc::new(web::Web { state: state(), enroll: e, notice: None })), true).await;
    let http = http();
    let ask = |from: Option<&'static str>, to: String| {
        let (http, url) = (http.clone(), url.clone());
        async move {
            let r = http.post(format!("{}/enroll/mail", url)).form(&[("email", to)]);
            match from {
                Some(a) => r.header("x-peersig-client", a),
                None => r,
            }
            .send()
            .await
            .unwrap()
            .status()
        }
    };
    assert_eq!(ask(Some("198.51.100.7"), "a@example.org".into()).await, 200);
    assert_eq!(ask(Some("198.51.100.7"), "b@example.org".into()).await, 200);
    assert_eq!(ask(Some("198.51.100.7"), "c@example.org".into()).await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(ask(Some("203.0.113.1"), "d@example.org".into()).await, 200);
    // The proxy did not say: no count (one count for all would stop everyone).
    for i in 0..4 {
        assert_eq!(ask(None, format!("e{}@example.org", i)).await, 200);
    }
    assert_eq!(sent.lock().unwrap().len(), 7);
}
