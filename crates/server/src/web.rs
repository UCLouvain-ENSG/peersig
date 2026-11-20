//! The site: the home page (what PeerSig is, how participants stay
//! anonymous, what JA4 is), /participate (download, code, join), /privacy
//! (the privacy policy, which the apps link to), and the
//! enrollment pages (a code by e-mail, with a GitHub account, or from the
//! institution's network). Pages and assets are compiled in. Like the API,
//! no handler logs the client address. Enrollment looks at it to check the
//! institution's network and to count requests per address (in memory, see
//! `enroll`), then forgets it. The admin page is in `admin`.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Form, FromRequest, Path, Query, Request, State as AxState};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::enroll::{self, Enrollment, GitHubOutcome, MailOutcome, NetworkOutcome, Refusal};
use crate::State;

pub struct Web {
    pub state: Arc<State>,
    pub enroll: Enrollment,
    /// Shown at the top of the pages, e.g. the limits of a pilot.
    pub notice: Option<Notice>,
}

/// The note at the top of the pages: plain text, and where it says more.
pub struct Notice {
    pub text: String,
    pub url: Option<String>,
}

const LOGO: &str = include_str!("../../../assets/logo/peersig.svg");
const CSS: &str = include_str!("../site/site.css");
const SITE_JS: &str = include_str!("../site/site.js");
const HERO_JS: &str = include_str!("../site/hero.js");
const INDEX: &str = include_str!("../site/index.html");
const PARTICIPATE: &str = include_str!("../site/participate.html");
const PRIVACY: &str = include_str!("../site/privacy.html");
const SOURCE: &str = "https://github.com/UCLouvain-ENSG/peersig";

pub(crate) fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Changes whenever an asset does: links carry it, so browsers may cache.
fn assets_version() -> &'static str {
    static V: OnceLock<String> = OnceLock::new();
    V.get_or_init(|| peersig_proto::short_hash([CSS, SITE_JS, HERO_JS, LOGO].concat().as_bytes(), 4))
}

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; \
                   form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// A whole page: header, `body`, footer.
pub(crate) fn layout(title: &str, description: &str, active: &str, body: &str, scripts: &[&str]) -> String {
    let v = assets_version();
    let nav = [("/", "Home"), ("/#anonymity", "Anonymity"), ("/#ja4", "JA4"), ("/data", "Data")]
        .iter()
        .map(|(href, name)| format!(r#"<a href="{}"{}>{}</a>"#, href, if *href == active { r#" class="on""# } else { "" }, name))
        .collect::<String>();
    let scripts: String = scripts.iter().map(|s| format!(r#"<script defer src="/assets/{}?v={}"></script>"#, s, v)).collect();
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<meta name="description" content="{description}">
<link rel="icon" href="/assets/logo.svg?v={v}" type="image/svg+xml">
<link rel="stylesheet" href="/assets/site.css?v={v}">
{scripts}
</head>
<body>
<header class="top">
  <a class="brand" href="/">{LOGO}PeerSig</a>
  <nav>{nav}</nav>
  <a class="btn primary" href="/participate">Participate</a>
</header>
<main>
{body}
</main>
<footer><div class="in">
  <span>PeerSig, a study of the <a href="https://github.com/UCLouvain-ENSG">Efficiency of Networked Systems Group</a>, UCLouvain. Apache-2.0.</span>
  <span><a href="/privacy">Privacy policy</a> · <a href="{SOURCE}/blob/main/docs/privacy.md">Privacy design</a> ·<a href="/data">Published tables</a> · <a href="/data#observers">Observers' daily table</a> · <a href="{SOURCE}">Source code</a></span>
</div></footer>
</body>
</html>"#,
        title = esc(title),
        description = esc(description),
    )
}

pub(crate) fn html(status: StatusCode, doc: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CONTENT_SECURITY_POLICY, CSP),
        ],
        doc,
    )
        .into_response()
}

fn page(status: StatusCode, title: &str, body: String) -> Response {
    html(status, layout(&format!("{} · PeerSig", title), "PeerSig enrollment", "", &format!(r#"<div class="msg">{}</div>"#, body), &[]))
}

pub(crate) fn message(status: StatusCode, title: &str, text: &str) -> Response {
    page(status, title, format!(r#"<h2>{}</h2><p>{}</p>"#, esc(title), text))
}

fn refusal(r: Refusal) -> Response {
    match r {
        Refusal::Busy => message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            "This page hands out a limited number of codes per hour, so that it cannot be used to flood the collection. Please try again in an hour.",
        ),
        // Same answer as when the message went out: the page must not tell
        // whether an address asked before.
        Refusal::Recent => sent(),
        Refusal::Address => message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            "Too many requests for a code came from your connection in the last hour. Please try again in an hour.",
        ),
    }
}

/// The visitor's address, for enrollment only (see `Enrollment::client`).
fn client(w: &Web, req: &Request) -> Option<IpAddr> {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    w.enroll.client(peer, req.headers())
}

fn sent() -> Response {
    message(
        StatusCode::OK,
        "Check your mailbox",
        r#"If the address can receive mail, a message with your code is on its way (look in the spam folder too). An address gets at most one message every ten minutes. Then: <a href="/participate#join">open PeerSig and paste it</a>."#,
    )
}

fn notice(w: &Web) -> String {
    let Some(n) = &w.notice else { return String::new() };
    let more = n.url.as_deref().map(|u| format!(r#" <a href="{}">More on this</a>."#, esc(u))).unwrap_or_default();
    format!(r#"<p class="notice">{}{}</p>"#, esc(&n.text), more)
}

async fn index(AxState(w): AxState<Arc<Web>>) -> Response {
    let st = &w.state.settings;
    let body = INDEX
        .replace("{{NOTICE}}", &notice(&w))
        .replace("{{K_HELLO}}", &st.k_hello.to_string())
        .replace("{{K_DOMAIN}}", &st.k_domain.to_string());
    html(
        StatusCode::OK,
        layout(
            "PeerSig: which app sent that TLS handshake?",
            "PeerSig labels TLS fingerprints (JA4) with the applications that send them, from anonymous ballots of volunteers.",
            "/",
            &body,
            &["site.js", "hero.js"],
        ),
    )
}

/// The ways to get a code, as this server is set up.
fn methods(e: &Enrollment) -> String {
    let mut m = String::new();
    if let Some(net) = &e.network {
        m.push_str(&format!(
            r#"<div class="method"><h3>On the {name} network</h3><p>On campus or through the {name} VPN: one click, nothing to fill in. Your network address is checked, not kept.</p>
<form method="post" action="/enroll/network"><button class="btn primary" type="submit">Get my code</button></form></div>"#,
            name = esc(&net.name)
        ));
    }
    if e.mail.is_some() {
        m.push_str(&format!(
            r#"<div class="method"><h3>By e-mail</h3>
<form method="post" action="/enroll/mail"><input type="email" name="email" required maxlength="254" placeholder="you@example.org" autocomplete="email" aria-label="E-mail address"><button class="btn" type="submit">Send me a code</button></form>
<p>The address is not kept: only a keyed hash, so that it gets at most {n} codes (one per computer or phone). Nothing links it to your code.</p></div>"#,
            n = e.per_identity
        ));
    }
    if let Some(gh) = &e.github {
        m.push_str(&format!(
            r#"<div class="method"><h3>With GitHub</h3><p>No permission asked: PeerSig only reads your account's number and creation date (accounts older than {d} days). A keyed hash of the number is kept, not linked to your code.</p>
<a class="btn" href="/enroll/github"><svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0a8 8 0 0 0-2.53 15.59c.4.07.55-.17.55-.38v-1.33c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.06-.49.06-.49.8.06 1.23.83 1.23.83.72 1.22 1.87.87 2.33.67.07-.52.28-.87.5-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 8 0Z"/></svg>Sign in with GitHub</a></div>"#,
            d = gh.min_age_days
        ));
    }
    if m.is_empty() {
        m.push_str(r#"<div class="method"><h3>From the study team</h3><p>The study team gives each participant a code.</p></div>"#);
    }
    m
}

async fn participate(AxState(w): AxState<Arc<Web>>) -> Response {
    let e = &w.enroll;
    let relay = e.relay_url.as_deref().map(|r| format!(r#" and the relay <code>{}</code>"#, esc(r))).unwrap_or_default();
    let contact = e.contact.as_deref().map(|c| format!(r#"Questions: <a href="mailto:{0}">{0}</a> · "#, esc(c))).unwrap_or_default();
    let body = PARTICIPATE
        .replace("{{NOTICE}}", &notice(&w))
        .replace("{{TOKENS}}", &w.state.settings.tokens_per_epoch.to_string())
        .replace("{{METHODS}}", &methods(e))
        .replace("{{SERVER}}", &esc(&e.public_url))
        .replace("{{RELAY}}", &relay)
        .replace("{{CONTACT}}", &contact);
    html(
        StatusCode::OK,
        layout("Participate · PeerSig", "Download PeerSig, get a code, and join the study.", "/participate", &body, &["site.js"]),
    )
}

/// The privacy policy, with this server's numbers. The apps link to it.
async fn privacy(AxState(w): AxState<Arc<Web>>) -> Response {
    let e = &w.enroll;
    let st = &w.state.settings;
    let contact = match e.contact.as_deref() {
        Some(c) => format!(r#"<a href="mailto:{0}">{0}</a>"#, esc(c)),
        None => format!(r#"the study through its <a href="{SOURCE}">source repository</a>"#),
    };
    let github_days = e.github.as_ref().map(|g| g.min_age_days).unwrap_or(30);
    let body = PRIVACY
        .replace("{{NOTICE}}", &notice(&w))
        .replace("{{CONTACT}}", &contact)
        .replace("{{TOKENS}}", &st.tokens_per_epoch.to_string())
        .replace("{{K_HELLO}}", &st.k_hello.to_string())
        .replace("{{K_DOMAIN}}", &st.k_domain.to_string())
        .replace("{{PER_IDENTITY}}", &e.per_identity.to_string())
        .replace("{{GITHUB_DAYS}}", &github_days.to_string());
    html(
        StatusCode::OK,
        layout(
            "Privacy policy · PeerSig",
            "PeerSig's privacy policy: what the apps look at, what they send, who sees it, how long it is kept, and your rights.",
            "/privacy",
            &body,
            &[],
        ),
    )
}

async fn asset(Path(name): Path<String>) -> Response {
    let (body, kind) = match name.as_str() {
        "site.css" => (CSS, "text/css; charset=utf-8"),
        "site.js" => (SITE_JS, "text/javascript; charset=utf-8"),
        "hero.js" => (HERO_JS, "text/javascript; charset=utf-8"),
        "logo.svg" => (LOGO, "image/svg+xml"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, "public, max-age=86400"), (header::X_CONTENT_TYPE_OPTIONS, "nosniff")],
        body,
    )
        .into_response()
}

#[derive(Deserialize)]
struct MailForm {
    email: String,
}

async fn by_mail(AxState(w): AxState<Arc<Web>>, req: Request) -> Response {
    if w.enroll.mail.is_none() {
        return message(StatusCode::NOT_FOUND, "Not available", "This server does not hand out codes by e-mail.");
    }
    let ip = client(&w, &req);
    let Ok(Form(f)) = Form::<MailForm>::from_request(req, &()).await else {
        return message(StatusCode::BAD_REQUEST, "Not an e-mail address", r#"<a href="/participate#code">Try again</a>."#);
    };
    let Some((to, id)) = enroll::parse_address(&f.email) else {
        return message(StatusCode::BAD_REQUEST, "Not an e-mail address", r#"<a href="/participate#code">Try again</a>."#);
    };
    match enroll::by_mail(&w.state, &w.enroll, to, &id, ip).await {
        Ok(MailOutcome::Sent) => sent(),
        Ok(MailOutcome::Refused(r)) => refusal(r),
        Err(e) => {
            // The error is about the mail system, never the address.
            tracing::error!("enrollment by e-mail: {:#}", e);
            message(StatusCode::BAD_GATEWAY, "The message could not be sent", "Please try again later.")
        }
    }
}

async fn by_network(AxState(w): AxState<Arc<Web>>, req: Request) -> Response {
    let Some(net) = &w.enroll.network else {
        return message(StatusCode::NOT_FOUND, "Not available", "This server does not hand out codes by network.");
    };
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let ip = net.client(peer, req.headers());
    drop(req);
    match enroll::by_network(&w.state, &w.enroll, ip).await {
        Ok(NetworkOutcome::Code(c)) => show_code(&w, &c),
        Ok(NetworkOutcome::Outside) => message(
            StatusCode::FORBIDDEN,
            &format!("Not on the {} network", net.name),
            &format!(
                r#"This connection does not come from the {} network. Connect to it (on campus, or through its VPN) and try again, or <a href="/participate#code">use another way</a>."#,
                esc(&net.name)
            ),
        ),
        Ok(NetworkOutcome::Refused(r)) => refusal(r),
        Err(e) => {
            tracing::error!("enrollment from the network: {:#}", e);
            message(StatusCode::INTERNAL_SERVER_ERROR, "No code", "Something went wrong; please try again later.")
        }
    }
}

/// The page that shows a new code, once.
fn show_code(_w: &Web, code: &str) -> Response {
    page(
        StatusCode::OK,
        "Your PeerSig code",
        format!(
            r#"<div class="eyebrow">Your enrollment code</div>
<p class="code-box">{code}</p>
<p><b>Copy it now:</b> it is shown only once, and the server keeps a hash of it, not the code. One code per computer or phone; keep it to yourself.</p>
<p class="cta"><a class="btn primary" href="/participate#join">Next: open PeerSig and paste it</a><a class="btn" href="/participate#download">Download PeerSig</a></p>"#,
            code = esc(code),
        ),
    )
}

async fn github_start(AxState(w): AxState<Arc<Web>>) -> Response {
    match enroll::authorize_url(&w.state, &w.enroll) {
        Ok(u) => Redirect::to(&u).into_response(),
        Err(_) => message(StatusCode::NOT_FOUND, "Not available", "This server does not hand out codes with GitHub."),
    }
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
}

async fn github_callback(AxState(w): AxState<Arc<Web>>, Query(q): Query<Callback>, req: Request) -> Response {
    let ip = client(&w, &req);
    drop(req);
    let (Some(code), Some(st)) = (q.code, q.state) else {
        return message(StatusCode::BAD_REQUEST, "Sign-in cancelled", r#"No code was handed out. <a href="/participate#code">Back</a>."#);
    };
    match enroll::by_github(&w.state, &w.enroll, &code, &st, ip).await {
        Ok(GitHubOutcome::Code(c)) => show_code(&w, &c),
        Ok(GitHubOutcome::Enough) => message(
            StatusCode::OK,
            "You have enough codes",
            &format!("This GitHub account already received {} codes, the most one account can get. Use one of them (one per computer or phone).", w.enroll.per_identity),
        ),
        Ok(GitHubOutcome::TooYoung) => message(
            StatusCode::FORBIDDEN,
            "Account too recent",
            &format!(
                "GitHub accounts younger than {} days cannot get a code here, against throwaway accounts. Use the e-mail option, or come back later.",
                w.enroll.github.as_ref().map_or(0, |g| g.min_age_days)
            ),
        ),
        Ok(GitHubOutcome::Banned) => message(
            StatusCode::FORBIDDEN,
            "No code for this account",
            "This GitHub account cannot get a code here. If you think this is a mistake, write to the study team.",
        ),
        Ok(GitHubOutcome::Refused(r)) => refusal(r),
        Err(e) => {
            tracing::warn!("enrollment with GitHub: {:#}", e);
            message(StatusCode::BAD_REQUEST, "Sign-in failed", &format!(r#"{}. <a href="/participate#code">Start again</a>."#, esc(&format!("{:#}", e))))
        }
    }
}

pub fn router(web: Arc<Web>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/participate", get(participate))
        .route("/privacy", get(privacy))
        .route("/assets/{name}", get(asset))
        .route("/enroll/mail", post(by_mail))
        .route("/enroll/network", post(by_network))
        .route("/enroll/github", get(github_start))
        .route("/enroll/github/callback", get(github_callback))
        .merge(crate::admin::routes())
        .merge(crate::data::routes())
        .with_state(web)
}
