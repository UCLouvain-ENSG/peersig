//! The admin page, /admin: enrollment codes (create, list, revoke) and
//! bans, for the GitHub accounts in `Enrollment::admins`, who sign in
//! through the server's GitHub app. Off unless both are set.
//!
//! It shows what `peersig-server codes list` and `stats` show: code labels
//! and the epochs each one took tokens in, counts per epoch. Never ballots
//! or addresses: the server has neither. Nothing about the admin is stored:
//! the session is a cookie signed with a key kept in the database, valid
//! for 12 hours, and forms carry a token derived from it.

use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Form, Query, State as AxState};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use hmac::{Hmac, Mac};
use peersig_proto::b64;
use serde::Deserialize;
use sha2::Sha256;

use crate::enroll::{self, Purpose, ADMIN_CALLBACK};
use crate::web::{esc, html, layout, message, Web};
use crate::db;

const COOKIE: &str = "peersig_admin";
const SESSION_SECONDS: i64 = 12 * 3600;
/// Codes one form can create.
const MAX_CODES: u32 = 100;

fn keyed(w: &Web, what: &str) -> Result<Hmac<Sha256>> {
    let key = db::secret(&w.state.db.lock().unwrap(), "admin-key")?;
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("any key length");
    m.update(what.as_bytes());
    Ok(m)
}

fn sign(w: &Web, what: &str) -> Result<String> {
    Ok(b64::encode(&keyed(w, what)?.finalize().into_bytes()))
}

fn verify(w: &Web, what: &str, tag: &str) -> bool {
    let Ok(tag) = b64::decode(tag) else { return false };
    keyed(w, what).is_ok_and(|m| m.verify_slice(&tag).is_ok())
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
}

/// A signed-in admin, and the token their forms carry.
struct Admin {
    login: String,
    csrf: String,
}

/// The session in the cookie: `<login>.<expiry>.<mac>`. Refused once
/// expired, or once the login is no longer in the list.
fn session(w: &Web, headers: &HeaderMap) -> Option<Admin> {
    let v = cookie(headers, COOKIE)?;
    let (body, tag) = v.rsplit_once('.')?;
    let (login, expiry) = body.split_once('.')?;
    let expiry: i64 = expiry.parse().ok()?;
    if !verify(w, &format!("session:{}", body), tag) || expiry < (w.state.clock)() || !w.enroll.admins.iter().any(|a| a == login) {
        return None;
    }
    Some(Admin { login: login.into(), csrf: sign(w, &format!("csrf:{}", v)).ok()? })
}

/// The admin behind a form, if its token matches their session.
fn checked(w: &Web, headers: &HeaderMap, csrf: &str) -> Result<Admin, Response> {
    let Some(a) = session(w, headers) else { return Err(Redirect::to("/admin").into_response()) };
    let v = cookie(headers, COOKIE).unwrap_or_default();
    if !verify(w, &format!("csrf:{}", v), csrf) {
        return Err(message(StatusCode::FORBIDDEN, "Expired form", r#"This form is no longer valid. <a href="/admin">Back to the admin page</a>."#));
    }
    Ok(a)
}

fn secure(w: &Web) -> &'static str {
    if w.enroll.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    }
}

fn redirect_with_cookie(to: &str, cookie: String) -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, to.to_string()), (header::SET_COOKIE, cookie), (header::CACHE_CONTROL, "no-store".into())])
        .into_response()
}

fn admin_page(status: StatusCode, title: &str, body: &str) -> Response {
    html(status, layout(&format!("{} · PeerSig", title), "PeerSig administration", "", &format!(r#"<div class="admin">{}</div>"#, body), &[]))
}

fn off(w: &Web) -> Option<Response> {
    (!w.enroll.admin_enabled()).then(|| StatusCode::NOT_FOUND.into_response())
}

fn failed(e: anyhow::Error) -> Response {
    tracing::error!("admin page: {:#}", e);
    message(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong", r#"<a href="/admin">Back to the admin page</a>."#)
}

#[derive(Deserialize)]
struct Done {
    done: Option<String>,
    what: Option<String>,
}

async fn home(AxState(w): AxState<Arc<Web>>, headers: HeaderMap, Query(q): Query<Done>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    let Some(a) = session(&w, &headers) else {
        return admin_page(
            StatusCode::OK,
            "Admin",
            r#"<div class="msg"><h2>PeerSig admin</h2><p>For the study team: sign in with an administrator's GitHub account.</p>
<p><a class="btn primary" href="/admin/login">Sign in with GitHub</a></p></div>"#,
        );
    };
    match dashboard(&w, &a, &q) {
        Ok(body) => admin_page(StatusCode::OK, "Admin", &body),
        Err(e) => failed(e),
    }
}

fn hidden(a: &Admin) -> String {
    format!(r#"<input type="hidden" name="csrf" value="{}">"#, esc(&a.csrf))
}

fn dashboard(w: &Web, a: &Admin, q: &Done) -> Result<String> {
    let e = &w.enroll;
    let st = &w.state;
    let (codes, bans, stats) = {
        let db = st.db.lock().unwrap();
        (db::list_codes(&db)?, db::list_bans(&db)?, db::stats(&db)?)
    };
    let what = q.what.as_deref().map(esc).unwrap_or_default();
    let done = match q.done.as_deref() {
        Some("revoked") => format!("Revoked {}.", what),
        Some("restored") => format!("Restored {}.", what),
        Some("banned") => format!("Banned {}.", what),
        Some("unbanned") => "Ban removed.".to_string(),
        _ => String::new(),
    };
    let done = if done.is_empty() { done } else { format!(r#"<p class="done">{}</p>"#, done) };
    let (used, per_hour) = e.budget_used();
    let per_address = if e.per_address == 0 {
        "no limit per client address".to_string()
    } else {
        format!("at most {} requests per client address and hour for codes by e-mail or GitHub, counted in memory only", e.per_address)
    };

    let mut rows = String::new();
    for c in codes.iter().rev() {
        let epochs: Vec<String> = if c.observer {
            // Days reported (items), most recent first.
            let days = st.settings.epochs.days();
            c.epochs
                .iter()
                .rev()
                .take(14)
                .map(|(d, n)| {
                    let day = chrono::DateTime::from_timestamp(days.start(*d), 0).map(|t| t.date_naive().to_string()).unwrap_or_default();
                    format!("{} ({})", day, n)
                })
                .collect()
        } else {
            c.epochs.iter().map(|(ep, t)| format!("{} ({})", ep, t)).collect()
        };
        let (status, button) = match (c.revoked, c.observer) {
            (true, _) => ("revoked", "Restore"),
            (false, true) => ("observer", "Revoke"),
            (false, false) => ("active", "Revoke"),
        };
        let restore = if c.revoked { r#"<input type="hidden" name="restore" value="1">"# } else { "" };
        rows.push_str(&format!(
            r#"<tr class="{status}"><td><b>{label}</b></td><td>{created}</td><td>{status}</td><td>{epochs}</td>
<td><form class="inline" method="post" action="/admin/codes/revoke">{csrf}<input type="hidden" name="label" value="{label}">{restore}<button class="btn small" type="submit">{button}</button></form></td></tr>"#,
            label = esc(&c.label),
            created = esc(&c.created),
            epochs = esc(&epochs.join(", ")),
            csrf = hidden(a),
        ));
    }
    if rows.is_empty() {
        rows = r#"<tr><td colspan="5" class="muted">No codes yet.</td></tr>"#.into();
    }

    let mut ban_rows = String::new();
    for b in &bans {
        let (kind, shown) = match b.kind.as_str() {
            "domain" => ("Mail domain", format!("<code>{}</code>", esc(&b.value))),
            "mail" => ("E-mail address", format!(r#"<span class="muted">keyed hash {}…</span>"#, esc(&b.value[..b.value.len().min(12)]))),
            _ => ("GitHub account", format!(r#"<span class="muted">keyed hash {}…</span>"#, esc(&b.value[..b.value.len().min(12)]))),
        };
        ban_rows.push_str(&format!(
            r#"<tr><td>{kind}</td><td>{shown}</td><td>{note}</td><td>{created}</td>
<td><form class="inline" method="post" action="/admin/bans/remove">{csrf}<input type="hidden" name="kind" value="{k}"><input type="hidden" name="value" value="{v}"><button class="btn small" type="submit">Remove</button></form></td></tr>"#,
            note = esc(&b.note),
            created = esc(&b.created),
            csrf = hidden(a),
            k = esc(&b.kind),
            v = esc(&b.value),
        ));
    }
    if ban_rows.is_empty() {
        ban_rows = r#"<tr><td colspan="5" class="muted">No bans.</td></tr>"#.into();
    }

    let mut stat_rows = String::new();
    for s in stats.iter().rev() {
        let start = chrono::DateTime::from_timestamp(st.settings.epochs.start(s.epoch), 0).map(|d| d.date_naive().to_string()).unwrap_or_default();
        stat_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            s.epoch, start, s.codes, s.tokens, s.presence, s.ballots, s.items
        ));
    }
    if stat_rows.is_empty() {
        stat_rows = r#"<tr><td colspan="7" class="muted">Nothing yet.</td></tr>"#.into();
    }

    Ok(format!(
        r##"<div class="muted small">Signed in as <b>{login}</b> with GitHub · <form class="inline" method="post" action="/admin/logout">{csrf}<button class="link" type="submit">Sign out</button></form></div>
<h1>PeerSig admin</h1>
{done}
<p>This hour, the page handed out {used} of its {per_hour} codes; {per_address}.</p>

<h2 id="codes">Codes</h2>
<form class="row" method="post" action="/admin/codes">{csrf}
  <label>Codes <input type="number" name="count" min="1" max="{max}" value="1" required></label>
  <label>Label prefix <input name="prefix" value="P" maxlength="12" pattern="[A-Za-z0-9]+" required></label>
  <button class="btn primary" type="submit">Create</button>
</form>
<p class="muted small">Each new code is shown once: the server keeps its hash. Labels: P (or your prefix) from here or the command line, M by e-mail, G with GitHub, N from the network, O for dedicated observers (made on the server only: <code>codes add --observer</code>; for them, the days they reported and how many items). A revoked code gets no more tokens; ballots it already sent stay counted, since nothing links them to it.</p>
<table><thead><tr><th>Label</th><th>Created</th><th>Status</th><th>Epochs (tokens)</th><th></th></tr></thead><tbody>{rows}</tbody></table>

<h2 id="bans">Bans</h2>
<form class="row" method="post" action="/admin/bans">{csrf}
  <select name="kind" aria-label="What to ban"><option value="mail">E-mail address</option><option value="domain">Mail domain</option><option value="github">GitHub account</option></select>
  <input name="value" required maxlength="254" placeholder="someone@example.org, example.org, or a GitHub login" aria-label="Address, domain or login">
  <input name="note" maxlength="200" placeholder="Note (optional)" aria-label="Note">
  <button class="btn" type="submit">Ban</button>
</form>
<p class="muted small">A banned address or domain (and its subdomains) gets the usual "check your mailbox" answer and no message; a banned GitHub account is told it cannot get a code. Addresses and accounts are stored as the keyed hash enrollment uses, so this list cannot show them: write a note. Codes they got before are not linked to them: revoke those by label if you know them. Network addresses cannot be banned: the server does not keep them.</p>
<table><thead><tr><th>Kind</th><th>Banned</th><th>Note</th><th>Since</th><th></th></tr></thead><tbody>{ban_rows}</tbody></table>

<h2 id="epochs">Epochs</h2>
<table><thead><tr><th>Epoch</th><th>Start</th><th>Codes</th><th>Tokens</th><th>Reporters</th><th>Ballots</th><th>Distinct items</th></tr></thead><tbody>{stat_rows}</tbody></table>"##,
        login = esc(&a.login),
        csrf = hidden(a),
        max = MAX_CODES,
    ))
}

async fn login(AxState(w): AxState<Arc<Web>>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    match enroll::sign_in_url(&w.state, &w.enroll, Purpose::Admin) {
        Ok(u) => Redirect::to(&u).into_response(),
        Err(e) => failed(e),
    }
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
}

async fn callback(AxState(w): AxState<Arc<Web>>, Query(q): Query<Callback>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    let (Some(code), Some(st)) = (q.code, q.state) else {
        return message(StatusCode::BAD_REQUEST, "Sign-in cancelled", r#"<a href="/admin">Back</a>."#);
    };
    match enroll::admin_sign_in(&w.state, &w.enroll, &code, &st).await {
        Ok(Some(login)) => {
            let body = format!("{}.{}", login, (w.state.clock)() + SESSION_SECONDS);
            match sign(&w, &format!("session:{}", body)) {
                Ok(tag) => redirect_with_cookie(
                    "/admin",
                    format!("{}={}.{}; Path=/admin; Max-Age={}; HttpOnly; SameSite=Lax{}", COOKIE, body, tag, SESSION_SECONDS, secure(&w)),
                ),
                Err(e) => failed(e),
            }
        }
        Ok(None) => message(StatusCode::FORBIDDEN, "Not an administrator", "This GitHub account cannot sign in to this server's admin page."),
        Err(e) => message(StatusCode::BAD_REQUEST, "Sign-in failed", &format!(r#"{}. <a href="/admin">Start again</a>."#, esc(&format!("{:#}", e)))),
    }
}

#[derive(Deserialize)]
struct Plain {
    csrf: String,
}

async fn logout(AxState(w): AxState<Arc<Web>>, headers: HeaderMap, Form(f): Form<Plain>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    if let Err(r) = checked(&w, &headers, &f.csrf) {
        return r;
    }
    redirect_with_cookie("/", format!("{}=; Path=/admin; Max-Age=0; HttpOnly; SameSite=Lax{}", COOKIE, secure(&w)))
}

#[derive(Deserialize)]
struct NewCodes {
    csrf: String,
    count: u32,
    prefix: String,
}

async fn create_codes(AxState(w): AxState<Arc<Web>>, headers: HeaderMap, Form(f): Form<NewCodes>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    if let Err(r) = checked(&w, &headers, &f.csrf) {
        return r;
    }
    let prefix = f.prefix.trim();
    if !(1..=MAX_CODES).contains(&f.count) || prefix.is_empty() || prefix.len() > 12 || !prefix.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return message(StatusCode::BAD_REQUEST, "Not created", r#"From 1 to 100 codes, with a prefix of letters and digits. <a href="/admin#codes">Back</a>."#);
    }
    let made = db::add_codes(&mut w.state.db.lock().unwrap(), f.count, prefix);
    match made {
        Ok(codes) => {
            let rows: String =
                codes.iter().map(|(l, c)| format!(r#"<tr><td><b>{}</b></td><td><code>{}</code></td></tr>"#, esc(l), esc(c))).collect();
            admin_page(
                StatusCode::OK,
                "New codes",
                &format!(
                    r#"<h1>{n} new code{s}</h1>
<p><b>Copy them now:</b> they are shown only once, and the server keeps only their hash. Give each participant one, with its label if you need to pay them.</p>
<table><thead><tr><th>Label</th><th>Code</th></tr></thead><tbody>{rows}</tbody></table>
<p class="cta"><a class="btn" href="/admin#codes">Back to the admin page</a></p>"#,
                    n = codes.len(),
                    s = if codes.len() == 1 { "" } else { "s" },
                ),
            )
        }
        Err(e) => failed(e),
    }
}

#[derive(Deserialize)]
struct Revoke {
    csrf: String,
    label: String,
    restore: Option<String>,
}

fn back(done: &str, what: &str, anchor: &str) -> Response {
    let q = reqwest::Url::parse_with_params("http://x/admin", &[("done", done), ("what", what)]).map(|u| u.query().unwrap_or_default().to_string()).unwrap_or_default();
    (StatusCode::SEE_OTHER, [(header::LOCATION, format!("/admin?{}#{}", q, anchor))]).into_response()
}

async fn revoke(AxState(w): AxState<Arc<Web>>, headers: HeaderMap, Form(f): Form<Revoke>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    if let Err(r) = checked(&w, &headers, &f.csrf) {
        return r;
    }
    let revoked = f.restore.is_none();
    // By label only: a code typed here would end up in the browser's history.
    let n = {
        let db = w.state.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM codes WHERE label = ?1", [&f.label], |r| r.get::<_, i64>(0))
            .map_err(anyhow::Error::from)
            .and_then(|n| if n > 0 { db::set_revoked(&db, &f.label, revoked) } else { Ok(0) })
    };
    match n {
        Ok(0) => message(StatusCode::NOT_FOUND, "No such label", r#"<a href="/admin#codes">Back</a>."#),
        Ok(_) => back(if revoked { "revoked" } else { "restored" }, &f.label, "codes"),
        Err(e) => failed(e),
    }
}

#[derive(Deserialize)]
struct Ban {
    csrf: String,
    kind: String,
    value: String,
    note: Option<String>,
}

async fn ban(AxState(w): AxState<Arc<Web>>, headers: HeaderMap, Form(f): Form<Ban>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    if let Err(r) = checked(&w, &headers, &f.csrf) {
        return r;
    }
    let invalid = |what: &str| message(StatusCode::BAD_REQUEST, "Not banned", &format!(r#"{}. <a href="/admin#bans">Back</a>."#, what));
    let (value, shown) = match f.kind.as_str() {
        "mail" => match enroll::parse_address(&f.value) {
            Some((_, id)) => match enroll::identity(&w.state, "mail", &id) {
                Ok(h) => (h, "an e-mail address".to_string()),
                Err(e) => return failed(e),
            },
            None => return invalid("Not an e-mail address"),
        },
        "domain" => match enroll::ban_domain(&f.value) {
            Some(d) => (d.clone(), d),
            None => return invalid("Not a mail domain (example.org)"),
        },
        "github" => match enroll::github_id(&w.enroll, &f.value).await {
            Ok(Some(id)) => match enroll::identity(&w.state, "github", &id.to_string()) {
                Ok(h) => (h, "a GitHub account".to_string()),
                Err(e) => return failed(e),
            },
            Ok(None) => return invalid("No such GitHub account"),
            Err(e) => return failed(e),
        },
        _ => return invalid("Unknown kind"),
    };
    let note: String = f.note.as_deref().unwrap_or_default().trim().chars().take(200).collect();
    match db::add_ban(&w.state.db.lock().unwrap(), &f.kind, &value, &note) {
        Ok(()) => back("banned", &shown, "bans"),
        Err(e) => failed(e),
    }
}

#[derive(Deserialize)]
struct Unban {
    csrf: String,
    kind: String,
    value: String,
}

async fn unban(AxState(w): AxState<Arc<Web>>, headers: HeaderMap, Form(f): Form<Unban>) -> Response {
    if let Some(r) = off(&w) {
        return r;
    }
    if let Err(r) = checked(&w, &headers, &f.csrf) {
        return r;
    }
    match db::remove_ban(&w.state.db.lock().unwrap(), &f.kind, &f.value) {
        Ok(_) => back("unbanned", "", "bans"),
        Err(e) => failed(e),
    }
}

pub fn routes() -> Router<Arc<Web>> {
    Router::new()
        .route("/admin", get(home))
        .route("/admin/login", get(login))
        .route("/admin/logout", post(logout))
        .route("/admin/codes", post(create_codes))
        .route("/admin/codes/revoke", post(revoke))
        .route("/admin/bans", post(ban))
        .route("/admin/bans/remove", post(unban))
        .route(ADMIN_CALLBACK, get(callback))
}
