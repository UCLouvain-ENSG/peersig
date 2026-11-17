//! HTTP API. Every handler is a plain function from a request body to a
//! (status, JSON) pair, so the same code serves direct requests and the
//! requests decrypted by the Oblivious HTTP gateway. Ballots are only
//! accepted through the gateway. No handler sees or logs the client
//! address. The web page for people is in [`crate::web`].

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State as AxState};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Serialize;

use peersig_proto::oblivious;
use peersig_proto::token::{key_id, KEY_BITS};
use peersig_proto::wire::*;

use crate::db::{self, Spend};
use crate::State;

type Reply = (u16, Vec<u8>);

fn json<T: Serialize>(status: u16, v: &T) -> Reply {
    (status, serde_json::to_vec(v).unwrap_or_default())
}

fn err(status: u16, msg: impl Into<String>) -> Reply {
    json(status, &ErrorBody { error: msg.into() })
}

fn internal(e: anyhow::Error) -> Reply {
    tracing::error!("{:#}", e);
    err(500, "internal error")
}

pub fn config(s: &State) -> Reply {
    let Some((current, report)) = s.epochs() else { return err(503, "the collection has not started") };
    let issuer = match s.issuer(report) {
        Ok(i) => i,
        Err(e) => return internal(e),
    };
    let st = &s.settings;
    json(
        200,
        &Config {
            server_version: env!("CARGO_PKG_VERSION").into(),
            epochs: st.epochs,
            current_epoch: current,
            report_epoch: report,
            token_key: TokenKey { epoch: report, public_key: issuer.public_der().to_vec(), key_id: key_id(issuer.public_der()) },
            tokens_per_epoch: st.tokens_per_epoch,
            k_hello: st.k_hello,
            k_domain: st.k_domain,
            about_url: st.about_url.clone(),
        },
    )
}

pub fn released(s: &State) -> Reply {
    let Some((_, report)) = s.epochs() else { return err(503, "the collection has not started") };
    match s.released_json(report) {
        Ok(j) => (200, j),
        Err(e) => internal(e),
    }
}

pub fn issue(s: &State, body: &[u8]) -> Reply {
    let Ok(req) = serde_json::from_slice::<IssueRequest>(body) else { return err(400, "malformed request") };
    let Some((current, report)) = s.epochs() else { return err(503, "the collection has not started") };
    if req.epoch != report || report >= current {
        return err(400, format!("tokens are issued for epoch {} only", report));
    }
    let hash = db::code_hash(&req.code);
    match db::code_active(&s.db.lock().unwrap(), &hash) {
        Ok(Some(true)) => {}
        Ok(Some(false)) => return err(403, "this enrollment code was withdrawn"),
        Ok(None) => return err(403, "unknown enrollment code"),
        Err(e) => return internal(e),
    }
    let len = KEY_BITS / 8;
    if req.blinded.iter().any(|b| b.len() != len) {
        return err(400, "malformed blinded token");
    }
    let n = req.blinded.len() as u32;
    let issuer = match s.issuer(req.epoch) {
        Ok(i) => i,
        Err(e) => return internal(e),
    };
    {
        let db = s.db.lock().unwrap();
        let used = match db::issued(&db, &hash, req.epoch) {
            Ok(u) => u,
            Err(e) => return internal(e),
        };
        if used + n > s.settings.tokens_per_epoch {
            return err(429, format!("{} of {} tokens already issued for this epoch", used, s.settings.tokens_per_epoch));
        }
        if let Err(e) = db::add_issued(&db, &hash, req.epoch, n) {
            return internal(e);
        }
    }
    let signatures: Result<Vec<Vec<u8>>, _> = req.blinded.iter().map(|b| issuer.sign(b)).collect();
    match signatures {
        Ok(signatures) => json(200, &IssueResponse { key_id: key_id(issuer.public_der()), signatures }),
        Err(e) => internal(e),
    }
}

pub fn ballot(s: &State, body: &[u8]) -> Reply {
    let Ok(b) = serde_json::from_slice::<Ballot>(body) else { return err(400, "malformed ballot") };
    let Some((current, report)) = s.epochs() else { return err(503, "the collection has not started") };
    if b.token.epoch != report || report >= current {
        return err(400, format!("ballots are accepted for epoch {} only", report));
    }
    if let Err(e) = b.item.validate() {
        return err(400, format!("invalid item: {}", e));
    }
    match s.issuer(report) {
        Ok(i) if i.verify(&b.token) => {}
        Ok(_) => return err(403, "invalid token"),
        Err(e) => return internal(e),
    }
    match db::count_ballot(&mut s.db.lock().unwrap(), report, &b.token.nonce, &b.item) {
        Ok(Spend::Counted) => (204, vec![]),
        Ok(Spend::AlreadySpent) => err(409, "token already spent"),
        Err(e) => internal(e),
    }
}

/// Requests a participant may make through the gateway.
fn dispatch(s: &State, method: &str, path: &str, body: &[u8]) -> Reply {
    match (method, path) {
        ("GET", PATH_CONFIG) => config(s),
        ("GET", PATH_RELEASED) => released(s),
        ("POST", PATH_BALLOT) => ballot(s, body),
        _ => err(404, "not found"),
    }
}

fn reply(r: Reply) -> Response {
    let status = StatusCode::from_u16(r.0).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if r.1.is_empty() {
        return status.into_response();
    }
    (status, [(header::CONTENT_TYPE, "application/json")], r.1).into_response()
}

async fn blocking(f: impl FnOnce() -> Reply + Send + 'static) -> Response {
    reply(tokio::task::spawn_blocking(f).await.unwrap_or_else(|_| err(500, "internal error")))
}

async fn ohttp_h(AxState(s): AxState<Arc<State>>, body: Bytes) -> Response {
    let enc = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, StatusCode> {
        let (plain, pending) = s.gateway.decapsulate(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
        let r = match oblivious::decode_request(&plain) {
            Ok(req) => dispatch(&s, &req.method, &req.path, &req.body),
            Err(_) => err(400, "malformed request"),
        };
        let msg = oblivious::encode_response(r.0, &r.1).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        pending.encapsulate(&msg).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    })
    .await;
    match enc {
        Ok(Ok(b)) => ([(header::CONTENT_TYPE, oblivious::RESPONSE_TYPE)], b).into_response(),
        Ok(Err(code)) => code.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub fn router(state: Arc<State>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(PATH_CONFIG, get(|AxState(s): AxState<Arc<State>>| blocking(move || config(&s))))
        .route(PATH_RELEASED, get(|AxState(s): AxState<Arc<State>>| blocking(move || released(&s))))
        .route(PATH_ISSUE, post(|AxState(s): AxState<Arc<State>>, body: Bytes| blocking(move || issue(&s, &body))))
        .route(
            PATH_OHTTP_KEYS,
            get(|AxState(s): AxState<Arc<State>>| async move {
                ([(header::CONTENT_TYPE, oblivious::KEYS_TYPE)], s.key_config.clone())
            }),
        )
        .route(PATH_OHTTP, post(ohttp_h))
        // Issuance of 512 tokens is about 180 kB of JSON.
        .layer(DefaultBodyLimit::max(512 * 1024))
        .with_state(state)
}
