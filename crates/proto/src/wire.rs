//! API messages. `GET /v1/config` and `POST /v1/ballot` go through
//! Oblivious HTTP (`POST /ohttp`); only
//! `POST /v1/issue`, which is authenticated by the enrollment code anyway,
//! goes directly to the server.

use serde::{Deserialize, Serialize};

use crate::{EpochSpec, Item, Token};

pub const PATH_CONFIG: &str = "/v1/config";
pub const PATH_ISSUE: &str = "/v1/issue";
pub const PATH_BALLOT: &str = "/v1/ballot";
pub const PATH_RELEASED: &str = "/v1/released";
pub const PATH_OHTTP: &str = "/ohttp";
pub const PATH_OHTTP_KEYS: &str = "/ohttp-keys";

/// The key that signs the tokens of one epoch.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenKey {
    pub epoch: u32,
    #[serde(with = "crate::b64")]
    pub public_key: Vec<u8>,
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub server_version: String,
    pub epochs: EpochSpec,
    pub current_epoch: u32,
    /// The epoch being reported now: the one before `current_epoch`.
    pub report_epoch: u32,
    pub token_key: TokenKey,
    /// Tokens every participant gets per epoch, whatever it will send.
    pub tokens_per_epoch: u32,
    /// Participants an item needs before it is released.
    pub k_hello: u32,
    pub k_domain: u32,
    /// Web page describing this collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about_url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IssueRequest {
    pub code: String,
    pub epoch: u32,
    #[serde(with = "crate::b64::vec")]
    pub blinded: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IssueResponse {
    pub key_id: String,
    #[serde(with = "crate::b64::vec")]
    pub signatures: Vec<Vec<u8>>,
}

/// One anonymous ballot: one item, one token.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Ballot {
    pub item: Item,
    pub token: Token,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ErrorBody {
    pub error: String,
}

/// The public result: items reported by enough participants, with their
/// support (the most participants that reported it in one epoch).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Released {
    /// Counts up to this epoch, excluded.
    pub until_epoch: u32,
    pub k_hello: u32,
    pub k_domain: u32,
    pub items: Vec<ReleasedItem>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReleasedItem {
    pub item: Item,
    /// Largest per-epoch count.
    pub support: i64,
}
