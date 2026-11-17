//! PeerSig Oblivious HTTP relay (RFC 9458).
//!
//! Meant to be run by someone other than the server's operator. It sees
//! who sends requests, and opaque encrypted blobs; it forwards the blobs to
//! the server's gateway from its own address. The server sees the content
//! but only the relay's address. Neither can link a ballot to a person
//! unless they collude.
//!
//! The relay keeps no logs. It holds the addresses of recent clients in
//! memory only, to rate-limit them, and forgets them within two minutes.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

pub const REQUEST_TYPE: &str = "message/ohttp-req";
pub const RESPONSE_TYPE: &str = "message/ohttp-res";
pub const KEYS_TYPE: &str = "application/ohttp-keys";

pub struct Relay {
    gateway: String,
    http: reqwest::Client,
    per_minute: u32,
    forwarded: bool,
    seen: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl Relay {
    /// `gateway`: the server's base URL (it serves `/ohttp` and `/ohttp-keys`).
    pub fn new(gateway: &str, per_minute: u32) -> anyhow::Result<Arc<Self>> {
        Self::with_options(gateway, per_minute, false)
    }

    /// `forwarded`: behind a reverse proxy on this machine, rate-limit by
    /// the address the proxy puts last in `X-Forwarded-For`.
    pub fn with_options(gateway: &str, per_minute: u32, forwarded: bool) -> anyhow::Result<Arc<Self>> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("peersig-relay/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Arc::new(Relay {
            gateway: gateway.trim_end_matches('/').to_string(),
            http,
            per_minute,
            forwarded,
            seen: Mutex::new(HashMap::new()),
        }))
    }

    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap();
        if seen.len() > 10_000 {
            seen.retain(|_, (t, _)| now.duration_since(*t) < Duration::from_secs(120));
        }
        let e = seen.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= Duration::from_secs(60) {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= self.per_minute
    }

    /// The client's address, for rate limiting only. A proxy on this
    /// machine appends the address it saw to `X-Forwarded-For`; what comes
    /// before was written by the client and is ignored.
    fn client(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        if !self.forwarded || !peer.is_loopback() {
            return peer;
        }
        headers
            .get_all("x-forwarded-for")
            .iter()
            .last()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|a| a.trim().parse().ok())
            .unwrap_or(peer)
    }
}

/// Forwards the body only: no client header, address or cookie goes on
/// (`X-Forwarded-For` included).
async fn forward(relay: &Relay, req: reqwest::RequestBuilder, response_type: &str) -> Response {
    match req.send().await {
        Ok(r) => {
            let status = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            match r.bytes().await {
                Ok(b) => (status, [(header::CONTENT_TYPE, response_type)], b).into_response(),
                Err(_) => StatusCode::BAD_GATEWAY.into_response(),
            }
        }
        Err(e) => {
            // The error names the gateway, never the client.
            tracing::warn!("gateway {}: {}", relay.gateway, e.without_url());
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn ohttp(
    State(relay): State<Arc<Relay>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) != Some(REQUEST_TYPE) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "expected message/ohttp-req").into_response();
    }
    if !relay.allow(relay.client(peer.ip(), &headers)) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let req = relay.http.post(format!("{}/ohttp", relay.gateway)).header(header::CONTENT_TYPE, REQUEST_TYPE).body(body);
    forward(&relay, req, RESPONSE_TYPE).await
}

async fn keys(State(relay): State<Arc<Relay>>) -> Response {
    let req = relay.http.get(format!("{}/ohttp-keys", relay.gateway));
    forward(&relay, req, KEYS_TYPE).await
}

async fn index(State(relay): State<Arc<Relay>>) -> String {
    format!(
        "PeerSig Oblivious HTTP relay (https://github.com/UCLouvain-ENSG/peersig).\n\
         Forwards encrypted requests to {} without the sender's address. Keeps no logs.\n",
        relay.gateway
    )
}

pub fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ohttp", post(ohttp))
        .route("/ohttp-keys", get(keys))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(relay)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_behind_a_proxy() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut h = HeaderMap::new();
        // The client wrote the first entry; the local proxy appended the second.
        h.insert("x-forwarded-for", "203.0.113.66, 192.0.2.7".parse().unwrap());
        let r = Relay::with_options("http://gateway", 1, true).unwrap();
        assert_eq!(r.client(ip("127.0.0.1"), &h), ip("192.0.2.7"));
        // Someone connecting directly cannot choose the address it is counted as.
        assert_eq!(r.client(ip("198.51.100.1"), &h), ip("198.51.100.1"));
        let off = Relay::new("http://gateway", 1).unwrap();
        assert_eq!(off.client(ip("127.0.0.1"), &h), ip("127.0.0.1"));
    }
}
