//! HTTP client for the app: oblivious requests through the relay (or the
//! server's own gateway), and the one direct request, token issuance.

use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;

use crate::oblivious;
use crate::wire::*;

pub struct Client {
    http: reqwest::Client,
    server: String,
    relay: Option<String>,
    keys: Option<Vec<u8>>,
}

fn base(u: &str) -> String {
    u.trim().trim_end_matches('/').to_string()
}

fn error_text(status: u16, body: &[u8]) -> String {
    match serde_json::from_slice::<ErrorBody>(body) {
        Ok(e) => format!("{} ({})", e.error, status),
        Err(_) => format!("HTTP {}: {}", status, String::from_utf8_lossy(&body[..body.len().min(200)])),
    }
}

impl Client {
    pub fn new(server: &str, relay: Option<&str>) -> Result<Self> {
        let http = reqwest::Client::builder()
            // The same for every participant.
            .user_agent(concat!("peersig/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()?;
        Ok(Client { http, server: base(server), relay: relay.map(base).filter(|r| !r.is_empty()), keys: None })
    }

    pub fn server(&self) -> &str {
        &self.server
    }

    pub fn relay(&self) -> Option<&str> {
        self.relay.as_deref()
    }

    async fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let r = self.http.get(url).send().await.with_context(|| url.to_string())?;
        let status = r.status().as_u16();
        let body = r.bytes().await?.to_vec();
        if !(200..300).contains(&status) {
            bail!("{}: {}", url, error_text(status, &body));
        }
        Ok(body)
    }

    /// The gateway's key, fetched from the server and through the relay:
    /// they must agree. A relay cannot substitute its own key, and the
    /// server cannot give one participant a key of its own.
    pub async fn ohttp_keys(&mut self) -> Result<Vec<u8>> {
        if let Some(k) = &self.keys {
            return Ok(k.clone());
        }
        let direct = self.get_bytes(&format!("{}{}", self.server, PATH_OHTTP_KEYS)).await?;
        if let Some(relay) = &self.relay {
            let relayed = self.get_bytes(&format!("{}{}", relay, PATH_OHTTP_KEYS)).await?;
            if relayed != direct {
                bail!("the relay and the server publish different gateway keys");
            }
        }
        self.keys = Some(direct.clone());
        Ok(direct)
    }

    /// One request through Oblivious HTTP.
    pub async fn oblivious(&mut self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let keys = self.ohttp_keys().await?;
        let (enc, pending) = oblivious::encapsulate(&keys, method, path, body)?;
        let url = format!("{}{}", self.relay.as_deref().unwrap_or(&self.server), PATH_OHTTP);
        let r = self
            .http
            .post(&url)
            .header("content-type", oblivious::REQUEST_TYPE)
            .body(enc)
            .send()
            .await
            .with_context(|| url.clone())?;
        let status = r.status().as_u16();
        let body = r.bytes().await?.to_vec();
        if status != 200 {
            // The key may have changed: fetch it again next time.
            self.keys = None;
            bail!("{}: {}", url, error_text(status, &body));
        }
        oblivious::decapsulate_response(pending, &body)
    }

    async fn oblivious_json<T: DeserializeOwned>(&mut self, method: &str, path: &str, body: &[u8]) -> Result<T> {
        let (status, body) = self.oblivious(method, path, body).await?;
        if !(200..300).contains(&status) {
            bail!("{}: {}", path, error_text(status, &body));
        }
        serde_json::from_slice(&body).with_context(|| path.to_string())
    }

    pub async fn config(&mut self) -> Result<Config> {
        self.oblivious_json("GET", PATH_CONFIG, b"").await
    }

    /// Direct: the server knows who asks, but tokens are blinded.
    pub async fn issue(&self, req: &IssueRequest) -> Result<IssueResponse> {
        let url = format!("{}{}", self.server, PATH_ISSUE);
        let r = self.http.post(&url).json(req).send().await.with_context(|| url.clone())?;
        let status = r.status().as_u16();
        let body = r.bytes().await?.to_vec();
        if !(200..300).contains(&status) {
            bail!("{}", error_text(status, &body));
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Sends one ballot. A token already spent (409) counts as sent: it is a
    /// retry whose first answer was lost.
    pub async fn ballot(&mut self, b: &Ballot) -> Result<()> {
        let (status, body) = self.oblivious("POST", PATH_BALLOT, &serde_json::to_vec(b)?).await?;
        match status {
            200..=299 | 409 => Ok(()),
            _ => bail!("ballot: {}", error_text(status, &body)),
        }
    }
}
