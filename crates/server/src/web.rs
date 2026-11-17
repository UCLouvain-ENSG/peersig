//! The server's web page: what the collection is, how data is protected,
//! and enrollment (a code by e-mail, with a GitHub account, or from the
//! institution's network). Like the API, no handler logs the client
//! address; only the network enrollment looks at it, and forgets it.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Form, Query, Request, State as AxState};
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
    /// Shown at the top of the page (plain text), e.g. the limits of a pilot.
    pub notice: Option<String>,
}

const LOGO: &str = include_str!("../../../assets/logo/peersig.svg");
const RELEASES: &str = "https://github.com/UCLouvain-ENSG/peersig/releases";
const SOURCE: &str = "https://github.com/UCLouvain-ENSG/peersig";

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

const STYLE: &str = r#"
:root{--fg:#1d2330;--muted:#5d6677;--bg:#f6f7f9;--card:#fff;--line:#e2e5ea;--accent:#2f6fdf;--bad:#c0392b;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--fg:#e6e9ef;--muted:#9aa3b2;--bg:#15181e;--card:#1e222a;--line:#2d333d;--accent:#6c9cff;--bad:#ff7b6b}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,sans-serif}
main{max-width:46em;margin:0 auto;padding:2em 16px 3em}
header{display:flex;align-items:center;gap:12px}
header svg{width:44px;height:44px;flex:none}
h1{font-size:1.6em;margin:0}
h2{font-size:1.15em;margin:0 0 .5em}
a{color:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1.1em 1.3em;margin:1.2em 0}
.muted{color:var(--muted)}
.small{font-size:.9em}
.why{border-left:3px solid var(--accent);padding:.2em 0 .2em 1em;margin:1em 0}
form{display:flex;gap:.5em;flex-wrap:wrap;margin:.6em 0}
input[type=email]{flex:1 1 16em;min-width:0;padding:.55em .7em;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--fg);font:inherit}
.btn{display:inline-block;padding:.55em 1em;border-radius:7px;border:1px solid var(--accent);background:var(--accent);color:#fff;font:inherit;text-decoration:none;cursor:pointer}
.code{font:600 1.6em/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;padding:.4em .6em;background:var(--bg);border:1px dashed var(--line);border-radius:8px;display:inline-block;user-select:all}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.92em;overflow-wrap:anywhere}
.error{color:var(--bad)}
.notice{border:1px solid #d9a441;background:color-mix(in srgb,#d9a441 14%,var(--card));border-radius:10px;padding:.8em 1.1em;margin:1.2em 0}
ol,ul{padding-left:1.3em}
li{margin:.25em 0}
"#;

fn page(status: StatusCode, title: &str, body: String) -> Response {
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>{STYLE}</style></head>
<body><main><header>{LOGO}<h1>PeerSig</h1></header>
{body}
<p class="muted small"><a href="/">Home</a> · <a href="/v1/released">Released fingerprints</a> · <a href="{SOURCE}">Source code</a></p>
</main></body></html>"#,
        title = esc(title),
    );
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            ),
        ],
        html,
    )
        .into_response()
}

fn message(status: StatusCode, title: &str, text: &str) -> Response {
    page(status, title, format!(r#"<div class="card"><h2>{}</h2><p>{}</p></div>"#, esc(title), text))
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
    }
}

fn sent() -> Response {
    message(
        StatusCode::OK,
        "Check your mailbox",
        "If the address can receive mail, a message with your code is on its way (look in the spam folder too). \
         An address gets at most one message every ten minutes.",
    )
}

/// Where the participant goes next, with the addresses the app needs.
fn next_steps(e: &Enrollment) -> String {
    let relay = e
        .relay_url
        .as_deref()
        .map(|r| format!(r#"<li>Relay: <span class="mono">{}</span></li>"#, esc(r)))
        .unwrap_or_default();
    format!(
        r#"<ol>
<li>Install PeerSig from the <a href="{RELEASES}">releases page</a> (macOS or Linux).</li>
<li>Open it and enter your code. The addresses are filled in already; they should be:
<ul><li>Server: <span class="mono">{server}</span></li>{relay}</ul></li>
<li>Each week, PeerSig shows you what it will send and waits a day before sending it.</li>
</ol>"#,
        server = esc(&e.public_url),
    )
}

async fn index(AxState(w): AxState<Arc<Web>>) -> Response {
    let st = &w.state.settings;
    let e = &w.enroll;
    let epoch = w.state.epochs().map(|(c, _)| c.to_string()).unwrap_or_else(|| "not started".into());
    let mut methods = String::new();
    if let Some(net) = &e.network {
        methods.push_str(&format!(
            r#"<h3>From the {name} network</h3>
<form method="post" action="/enroll/network"><button class="btn" type="submit">Get a code</button></form>
<p class="muted small">On campus or through the {name} VPN: the server checks that your connection comes from the {name} network and hands you a code, with nothing to fill in. It does not keep your network address.</p>"#,
            name = esc(&net.name)
        ));
    }
    if e.mail.is_some() {
        methods.push_str(&format!(
            r#"<h3>By e-mail</h3>
<form method="post" action="/enroll/mail"><input type="email" name="email" required maxlength="254" placeholder="you@example.org" autocomplete="email" aria-label="E-mail address"><button class="btn" type="submit">Send me a code</button></form>
<p class="muted small">The code is sent to this address. The server does not keep the address: it keeps a keyed hash of it, so that one address gets at most {n} codes (one per computer). Nothing links that hash to your code.</p>"#,
            n = e.per_identity
        ));
    }
    if let Some(gh) = &e.github {
        methods.push_str(&format!(
            r#"<h3>With a GitHub account</h3>
<p><a class="btn" href="/enroll/github">Sign in with GitHub</a></p>
<p class="muted small">PeerSig asks GitHub for no permission: it only reads your account's number and creation date. Accounts younger than {d} days are refused, against throwaway accounts. The server keeps a keyed hash of the number (at most {n} codes per account), not linked to your code, and no GitHub token.</p>"#,
            d = gh.min_age_days,
            n = e.per_identity
        ));
    }
    if methods.is_empty() {
        methods.push_str("<p>The study team gives each participant a code.</p>");
    }
    let notice = w.notice.as_deref().map(|n| format!(r#"<p class="notice">{}</p>"#, esc(n))).unwrap_or_default();
    let body = format!(
        r#"{notice}<p>PeerSig finds which applications send which TLS fingerprints (<a href="https://github.com/FoxIO-LLC/ja4">JA4</a>). Volunteers run a small app that watches the start of the encrypted connections their computer makes and, once a week, contributes which applications sent which fingerprints, as anonymous ballots. The result is a public ground-truth table for traffic classification research.</p>

<div class="card"><h2>Take part: get a code</h2>
<div class="why"><strong>Why a code?</strong> The collection only accepts ballots from enrolled participants, so that nobody can reach it uncontrolled from the internet and flood it with made-up results (spam). A code lets one computer send at most {tokens} anonymous ballots a week. It does not tell the server which ballots are yours: ballot tokens are signed blind, so a ballot cannot be traced back to the code that obtained it.</div>
{methods}
<h3>Then</h3>
{next}
{contact}</div>

<div class="card"><h2>How data is protected</h2><ul>
<li>Only application names and versions, the fingerprints of their handshakes and the OS family leave a participant's computer, and, if they allow it, the server names (SNI) non-browser applications connect to. Never addresses, visited sites, times, file paths or names.</li>
<li>Each observation is a separate anonymous ballot carrying a blind-signed token: the server knows it comes from a participant, not which one, nor which ballots come from the same person.</li>
<li>Ballots go through an Oblivious HTTP relay, which sees the sender's address but not the content; the server sees the content but not the address. This hides who sends what as long as the relay and the server are run by different parties.</li>
<li>The server stores one counter per item and week: no addresses, no arrival times, no individual ballots.</li>
<li>An item is published only once at least {kh} participants reported it in the same week ({kd} for domains).</li>
</ul>
<p class="muted small">Current week: {epoch}. <a href="/v1/config">Configuration</a>. The full design is in <a href="{SOURCE}/blob/main/docs/privacy.md">docs/privacy.md</a>.</p></div>"#,
        tokens = st.tokens_per_epoch,
        next = next_steps(e),
        contact = e
            .contact
            .as_deref()
            .map(|c| format!(r#"<p class="muted small">Questions about the study: <a href="mailto:{0}">{0}</a>.</p>"#, esc(c)))
            .unwrap_or_default(),
        kh = st.k_hello,
        kd = st.k_domain,
    );
    page(StatusCode::OK, "PeerSig", body)
}

#[derive(Deserialize)]
struct MailForm {
    email: String,
}

async fn by_mail(AxState(w): AxState<Arc<Web>>, Form(f): Form<MailForm>) -> Response {
    if w.enroll.mail.is_none() {
        return message(StatusCode::NOT_FOUND, "Not available", "This server does not hand out codes by e-mail.");
    }
    let Some((to, id)) = enroll::parse_address(&f.email) else {
        return message(StatusCode::BAD_REQUEST, "Not an e-mail address", r#"<a href="/">Try again</a>."#);
    };
    match enroll::by_mail(&w.state, &w.enroll, to, &id).await {
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
                r#"This connection does not come from the {} network. Connect to it (on campus, or through its VPN) and try again, or <a href="/">use another way</a>."#,
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
fn show_code(w: &Web, code: &str) -> Response {
    page(
        StatusCode::OK,
        "Your PeerSig code",
        format!(
            r#"<div class="card"><h2>Your enrollment code</h2>
<p class="code">{code}</p>
<p><strong>Copy it now:</strong> it is shown only once, and the server keeps a hash of it, not the code. One code per computer; keep it to yourself.</p>
<h3>Then</h3>{next}</div>"#,
            code = esc(code),
            next = next_steps(&w.enroll)
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

async fn github_callback(AxState(w): AxState<Arc<Web>>, Query(q): Query<Callback>) -> Response {
    let (Some(code), Some(st)) = (q.code, q.state) else {
        return message(StatusCode::BAD_REQUEST, "Sign-in cancelled", r#"No code was handed out. <a href="/">Back</a>."#);
    };
    match enroll::by_github(&w.state, &w.enroll, &code, &st).await {
        Ok(GitHubOutcome::Code(c)) => show_code(&w, &c),
        Ok(GitHubOutcome::Enough) => message(
            StatusCode::OK,
            "You have enough codes",
            &format!("This GitHub account already received {} codes, the most one account can get. Use one of them (one per computer).", w.enroll.per_identity),
        ),
        Ok(GitHubOutcome::TooYoung) => message(
            StatusCode::FORBIDDEN,
            "Account too recent",
            &format!(
                "GitHub accounts younger than {} days cannot get a code here, against throwaway accounts. Use the e-mail option, or come back later.",
                w.enroll.github.as_ref().map_or(0, |g| g.min_age_days)
            ),
        ),
        Ok(GitHubOutcome::Refused(r)) => refusal(r),
        Err(e) => {
            tracing::warn!("enrollment with GitHub: {:#}", e);
            message(StatusCode::BAD_REQUEST, "Sign-in failed", &format!(r#"{}. <a href="/">Start again</a>."#, esc(&format!("{:#}", e))))
        }
    }
}

pub fn router(web: Arc<Web>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/enroll/mail", post(by_mail))
        .route("/enroll/network", post(by_network))
        .route("/enroll/github", get(github_start))
        .route("/enroll/github/callback", get(github_callback))
        .with_state(web)
}
