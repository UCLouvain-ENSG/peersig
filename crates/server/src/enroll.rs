//! Enrollment from the server's web page: a participant gets a code by
//! e-mail, with a GitHub account, or from the institution's network,
//! without asking the study team.
//!
//! Enrollment keeps the collection closed to people who are not
//! participants: without it, anyone on the internet could get tokens and
//! flood the study with made-up ballots. It does not tell the server who
//! sends what: tokens are signed blind, so a ballot cannot be traced back to
//! the code that obtained it.
//!
//! What the server keeps: the code's hash and a label, as for codes made by
//! hand, and in `identities` a keyed hash of the address or GitHub account
//! with the number of codes it got (at most `per_identity`, one per
//! computer). Nothing links the two. The address is used to send one
//! message; GitHub's access token, for one request. Neither is stored or
//! logged. From the institution's network, the connection's address is
//! checked against the network's blocks and forgotten: nothing is kept.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Deserialize;
use sha2::Sha256;

use crate::{db, State};

type HmacSha256 = Hmac<Sha256>;

/// How long a GitHub sign-in may take.
const STATE_TTL: i64 = 600;
/// One message per address in this interval, whatever is asked.
const MAIL_INTERVAL: Duration = Duration::from_secs(600);

pub struct Enrollment {
    /// The server's public address: links, and GitHub's callback.
    pub public_url: String,
    /// The relay participants should use (shown, and put in the message).
    pub relay_url: Option<String>,
    /// The study team's e-mail address, shown on the page and in messages.
    pub contact: Option<String>,
    /// Codes one address or account can get.
    pub per_identity: u32,
    /// Codes the web page hands out per hour, all methods together.
    pub per_hour: u32,
    pub mail: Option<Mail>,
    pub github: Option<GitHub>,
    pub network: Option<Network>,
    budget: Mutex<Budget>,
}

/// In memory only, and without addresses: how many codes this hour, and
/// which identity hashes got a message recently.
struct Budget {
    hour: Instant,
    used: u32,
    recent: HashMap<String, Instant>,
}

pub enum Refusal {
    /// The hourly budget is spent.
    Busy,
    /// This address got a message a few minutes ago.
    Recent,
}

impl Enrollment {
    pub fn new(public_url: &str, relay_url: Option<&str>, per_identity: u32, per_hour: u32) -> Self {
        Enrollment {
            public_url: public_url.trim_end_matches('/').to_string(),
            relay_url: relay_url.map(|r| r.trim_end_matches('/').to_string()),
            contact: None,
            per_identity,
            per_hour,
            mail: None,
            github: None,
            network: None,
            budget: Mutex::new(Budget { hour: Instant::now(), used: 0, recent: HashMap::new() }),
        }
    }

    pub fn enabled(&self) -> bool {
        self.mail.is_some() || self.github.is_some() || self.network.is_some()
    }

    /// Takes one unit of the hourly budget; for e-mail, also checks the
    /// address did not get a message in the last minutes.
    fn take(&self, mail_identity: Option<&str>) -> Result<(), Refusal> {
        let now = Instant::now();
        let mut b = self.budget.lock().unwrap();
        if now.duration_since(b.hour) >= Duration::from_secs(3600) {
            b.hour = now;
            b.used = 0;
        }
        b.recent.retain(|_, t| now.duration_since(*t) < MAIL_INTERVAL);
        if let Some(id) = mail_identity {
            if b.recent.contains_key(id) {
                return Err(Refusal::Recent);
            }
        }
        if b.used >= self.per_hour {
            return Err(Refusal::Busy);
        }
        b.used += 1;
        if let Some(id) = mail_identity {
            b.recent.insert(id.to_string(), now);
        }
        Ok(())
    }
}

/// Keyed hash of an identity: the key never leaves the database, so the
/// hash cannot be checked against a list of addresses without it.
pub fn identity(state: &State, kind: &str, id: &str) -> Result<String> {
    let key = db::secret(&state.db.lock().unwrap(), "enroll-key")?;
    let mut m = <HmacSha256 as Mac>::new_from_slice(&key).expect("any key length");
    m.update(format!("{}:{}", kind, id).as_bytes());
    Ok(m.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect())
}

async fn new_code(state: &Arc<State>, identity: &str, prefix: &'static str, cap: u32) -> Result<Option<(String, String)>> {
    let (s, id) = (state.clone(), identity.to_string());
    tokio::task::spawn_blocking(move || db::enroll(&mut s.db.lock().unwrap(), &id, prefix, cap)).await?
}

// ---------------------------------------------------------------- e-mail

pub struct Mail {
    pub from: Mailbox,
    transport: Transport,
}

pub enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    /// Keeps the messages in memory (tests).
    Memory(Arc<Mutex<Vec<Message>>>),
}

impl Mail {
    /// `url`: `smtp://host:25` (no TLS: a local MTA), `smtp://user:pass@host:587?tls=required`
    /// (STARTTLS) or `smtps://user:pass@host:465`.
    pub fn smtp(url: &str, from: &str) -> Result<Self> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::from_url(url)
            .context("--smtp-url")?
            .timeout(Some(Duration::from_secs(30)))
            .build();
        Ok(Mail { from: from.parse().context("--mail-from")?, transport: Transport::Smtp(transport) })
    }

    pub fn memory(from: &str, sent: Arc<Mutex<Vec<Message>>>) -> Result<Self> {
        Ok(Mail { from: from.parse()?, transport: Transport::Memory(sent) })
    }

    async fn send(&self, to: Mailbox, subject: &str, body: String) -> Result<()> {
        // Spam filters want both; lettre adds neither to a single part, and
        // its Message-ID would end in this machine's short host name.
        let mut id = [0u8; 16];
        rand::fill(&mut id[..]);
        let id: String = id.iter().map(|b| format!("{:02x}", b)).collect();
        let m = Message::builder()
            .header(lettre::message::header::MIME_VERSION_1_0)
            .message_id(Some(format!("<{}@{}>", id, self.from.email.domain())))
            .from(self.from.clone())
            .to(to)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)?;
        match &self.transport {
            Transport::Smtp(t) => {
                t.send(m).await?;
            }
            Transport::Memory(v) => v.lock().unwrap().push(m),
        }
        Ok(())
    }
}

/// The address to write to, and the identity it counts as: lower case,
/// without a `+tag` (one mailbox, one identity).
pub fn parse_address(s: &str) -> Option<(Mailbox, String)> {
    let s = s.trim().to_lowercase();
    if s.len() > 254 {
        return None;
    }
    let addr: lettre::Address = s.parse().ok()?;
    let user = addr.user().split('+').next().unwrap_or_default();
    if user.is_empty() || !addr.domain().contains('.') {
        return None;
    }
    let id = format!("{}@{}", user, addr.domain());
    Some((Mailbox::new(None, addr), id))
}

pub enum MailOutcome {
    /// A message went out (a code, or "you have enough codes").
    Sent,
    Refused(Refusal),
}

/// Sends a code to `address`. The answer does not say whether the address
/// had codes already, so the page cannot be used to test addresses.
pub async fn by_mail(state: &Arc<State>, e: &Enrollment, to: Mailbox, id: &str) -> Result<MailOutcome> {
    let mail = e.mail.as_ref().context("e-mail enrollment is off")?;
    let identity = identity(state, "mail", id)?;
    if let Err(r) = e.take(Some(&identity)) {
        return Ok(MailOutcome::Refused(r));
    }
    match new_code(state, &identity, "M", e.per_identity).await? {
        Some((code, _label)) => {
            let sent = mail.send(to, "Your PeerSig enrollment code", code_message(e, &code)).await;
            if let Err(err) = sent {
                let (s, i, c) = (state.clone(), identity.clone(), code.clone());
                tokio::task::spawn_blocking(move || db::unenroll(&mut s.db.lock().unwrap(), &i, &c)).await??;
                return Err(err);
            }
        }
        None => mail.send(to, "Your PeerSig enrollment codes", enough_message(e)).await?,
    }
    Ok(MailOutcome::Sent)
}

fn code_message(e: &Enrollment, code: &str) -> String {
    let relay = e.relay_url.as_deref().map(|r| format!("\n    Relay:  {}", r)).unwrap_or_default();
    format!(
        "Hello,

Here is your PeerSig enrollment code:

    {code}

Install PeerSig (https://github.com/UCLouvain-ENSG/peersig/releases), open
it and enter this code. The addresses are already filled in:

    Server: {server}{relay}

One code per computer. Keep it to yourself: whoever has it can send
ballots in your place.

The server keeps a hash of this code, not the code, and does not keep your
address. If you did not ask for a code, ignore this message.
{contact}
--
PeerSig, {server}
",
        server = e.public_url,
        contact = contact_line(e),
    )
}

fn enough_message(e: &Enrollment) -> String {
    format!(
        "Hello,

Someone asked for a PeerSig enrollment code for this address, which
already received {n}, the most one address can get. Use one of the codes
you received (one per computer).

If you did not ask for a code, ignore this message.
{contact}
--
PeerSig, {server}
",
        n = e.per_identity,
        server = e.public_url,
        contact = contact_line(e),
    )
}

fn contact_line(e: &Enrollment) -> String {
    e.contact.as_deref().map(|c| format!("\nQuestions: {}\n", c)).unwrap_or_default()
}

// ---------------------------------------------------------------- GitHub

pub struct GitHub {
    pub client_id: String,
    client_secret: String,
    pub min_age_days: u32,
    /// https://github.com and https://api.github.com, or a test server.
    web: String,
    api: String,
    http: reqwest::Client,
}

impl GitHub {
    pub fn new(client_id: &str, client_secret: &str, min_age_days: u32) -> Result<Self> {
        Self::with_endpoints(client_id, client_secret, min_age_days, "https://github.com", "https://api.github.com")
    }

    pub fn with_endpoints(client_id: &str, client_secret: &str, min_age_days: u32, web: &str, api: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("peersig-server/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(20))
            .build()?;
        Ok(GitHub {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            min_age_days,
            web: web.trim_end_matches('/').into(),
            api: api.trim_end_matches('/').into(),
            http,
        })
    }
}

fn callback(e: &Enrollment) -> String {
    format!("{}/enroll/github/callback", e.public_url)
}

/// The MAC of a sign-in's `state`: GitHub hands it back, and only this
/// server could have made it.
fn state_mac(state: &State, payload: &str) -> Result<HmacSha256> {
    let key = db::secret(&state.db.lock().unwrap(), "enroll-key")?;
    let mut m = <HmacSha256 as Mac>::new_from_slice(&key).expect("any key length");
    m.update(b"github-state:");
    m.update(payload.as_bytes());
    Ok(m)
}

/// Where to send the browser: GitHub's authorization page. No scope is
/// asked for: the token can only read public profile data.
pub fn authorize_url(state: &State, e: &Enrollment) -> Result<String> {
    let gh = e.github.as_ref().context("GitHub enrollment is off")?;
    let mut nonce = [0u8; 16];
    rand::fill(&mut nonce[..]);
    let payload = format!("{}.{}", (state.clock)(), peersig_proto::b64::encode(&nonce));
    let token = format!("{}.{}", payload, peersig_proto::b64::encode(&state_mac(state, &payload)?.finalize().into_bytes()));
    let u = reqwest::Url::parse_with_params(
        &format!("{}/login/oauth/authorize", gh.web),
        &[("client_id", gh.client_id.as_str()), ("redirect_uri", &callback(e)), ("state", &token), ("allow_signup", "false")],
    )?;
    Ok(u.to_string())
}

fn check_state(state: &State, token: &str) -> Result<()> {
    let (payload, mac) = token.rsplit_once('.').context("malformed state")?;
    let ts: i64 = payload.split('.').next().unwrap_or_default().parse().context("malformed state")?;
    let mac = peersig_proto::b64::decode(mac).ok().context("malformed state")?;
    state_mac(state, payload)?.verify_slice(&mac).ok().context("this sign-in did not start here")?;
    let age = (state.clock)() - ts;
    if !(0..=STATE_TTL).contains(&age) {
        bail!("this sign-in took too long; start again");
    }
    Ok(())
}

pub enum GitHubOutcome {
    Code(String),
    /// The account has `per_identity` codes already.
    Enough,
    TooYoung,
    Refused(Refusal),
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct User {
    id: u64,
    created_at: String,
}

/// GitHub sent the browser back with `code`: ask who it is, then hand out a
/// code. The access token is dropped at the end of this function.
pub async fn by_github(state: &Arc<State>, e: &Enrollment, code: &str, st: &str) -> Result<GitHubOutcome> {
    let gh = e.github.as_ref().context("GitHub enrollment is off")?;
    check_state(state, st)?;
    let tok: TokenResponse = gh
        .http
        .post(format!("{}/login/oauth/access_token", gh.web))
        .header("accept", "application/json")
        .form(&[
            ("client_id", gh.client_id.as_str()),
            ("client_secret", gh.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", &callback(e)),
        ])
        .send()
        .await
        .context("GitHub")?
        .error_for_status()
        .context("GitHub")?
        .json()
        .await
        .context("GitHub")?;
    let Some(access) = tok.access_token else {
        bail!("GitHub refused the sign-in: {}", tok.error_description.unwrap_or_default());
    };
    let user: User = gh
        .http
        .get(format!("{}/user", gh.api))
        .bearer_auth(&access)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28")
        .send()
        .await
        .context("GitHub")?
        .error_for_status()
        .context("GitHub")?
        .json()
        .await
        .context("GitHub")?;
    drop(access);
    let created = chrono::DateTime::parse_from_rfc3339(&user.created_at).context("GitHub account date")?;
    if (state.clock)() - created.timestamp() < gh.min_age_days as i64 * 86400 {
        return Ok(GitHubOutcome::TooYoung);
    }
    let identity = identity(state, "github", &user.id.to_string())?;
    if let Err(r) = e.take(None) {
        return Ok(GitHubOutcome::Refused(r));
    }
    Ok(match new_code(state, &identity, "G", e.per_identity).await? {
        Some((code, _)) => GitHubOutcome::Code(code),
        None => GitHubOutcome::Enough,
    })
}

// ---------------------------------------------------------------- network

/// An address block: `130.104.0.0/16`, `2001:6a8:3080::/44`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block {
    addr: IpAddr,
    len: u8,
}

impl std::str::FromStr for Block {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let (a, l) = s.trim().split_once('/').ok_or_else(|| anyhow!("{}: expected address/length", s))?;
        let addr: IpAddr = a.parse().with_context(|| s.to_string())?;
        let len: u8 = l.parse().with_context(|| s.to_string())?;
        if len > if addr.is_ipv4() { 32 } else { 128 } {
            bail!("{}: prefix too long", s);
        }
        Ok(Block { addr, len })
    }
}

impl Block {
    pub fn contains(&self, ip: IpAddr) -> bool {
        fn prefix(a: u128, b: u128, len: u8, bits: u8) -> bool {
            len == 0 || (a ^ b) >> (bits - len) == 0
        }
        match (self.addr, ip.to_canonical()) {
            (IpAddr::V4(n), IpAddr::V4(i)) => prefix(u32::from(n) as u128, u32::from(i) as u128, self.len, 32),
            (IpAddr::V6(n), IpAddr::V6(i)) => prefix(u128::from(n), u128::from(i), self.len, 128),
            _ => false,
        }
    }
}

/// Visitors from these blocks (a university's, say) get a code with one
/// click.
pub struct Network {
    /// As shown on the page: "UCLouvain".
    pub name: String,
    pub blocks: Vec<Block>,
    /// Header in which a reverse proxy on this machine puts the client's
    /// address (it must overwrite what the client sent). None: the
    /// connection's own address.
    pub address_header: Option<String>,
}

impl Network {
    /// The visitor's address: the connection's, or, from a proxy on this
    /// machine, the last entry of `address_header`.
    pub fn client(&self, peer: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        let peer = peer?;
        let Some(h) = &self.address_header else { return Some(peer) };
        if !peer.is_loopback() {
            return Some(peer);
        }
        let v = headers.get_all(h.as_str()).iter().last();
        if v.is_none() {
            tracing::warn!("no {} header from the proxy: check that it sets it on /enroll/network", h);
        }
        v?.to_str().ok()?.rsplit(',').next()?.trim().parse().ok()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.blocks.iter().any(|b| b.contains(ip))
    }
}

pub enum NetworkOutcome {
    Code(String),
    Outside,
    Refused(Refusal),
}

/// A code for a visitor from the network. `ip` is checked, then dropped.
pub async fn by_network(state: &Arc<State>, e: &Enrollment, ip: Option<IpAddr>) -> Result<NetworkOutcome> {
    let net = e.network.as_ref().context("enrollment from the network is off")?;
    if !ip.is_some_and(|ip| net.contains(ip)) {
        return Ok(NetworkOutcome::Outside);
    }
    if let Err(r) = e.take(None) {
        return Ok(NetworkOutcome::Refused(r));
    }
    let s = state.clone();
    let (code, _) = tokio::task::spawn_blocking(move || db::add_labelled_code(&s.db.lock().unwrap(), "N")).await??;
    Ok(NetworkOutcome::Code(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks() {
        let b: Block = "130.104.0.0/16".parse().unwrap();
        assert!(b.contains("130.104.229.17".parse().unwrap()));
        assert!(b.contains("::ffff:130.104.1.2".parse().unwrap()));
        assert!(!b.contains("130.105.0.1".parse().unwrap()));
        assert!(!b.contains("2001:6a8:3080::1".parse().unwrap()));
        let b6: Block = "2001:6a8:3080::/44".parse().unwrap();
        assert!(b6.contains("2001:6a8:308f:ffff::1".parse().unwrap()));
        assert!(!b6.contains("2001:6a8:3090::1".parse().unwrap()));
        assert!("0.0.0.0/0".parse::<Block>().unwrap().contains("8.8.8.8".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Block>().is_err() && "10.0.0.0".parse::<Block>().is_err());
    }
}
