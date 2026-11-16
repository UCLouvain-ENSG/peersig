//! API messages. `GET /v1/config`, `GET /v1/catalogue/{epoch}` and
//! `POST /v1/ballot` go through Oblivious HTTP (`POST /ohttp`); only
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

pub fn path_catalogue(epoch: u32) -> String {
    format!("/v1/catalogue/{}", epoch)
}

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
    /// Randomized response: probability of reporting the truth for a
    /// catalogue item. Epsilon = ln(p / (1 - p)).
    pub rr_p: f64,
    /// Participants an item needs before it is released.
    pub k_hello: u32,
    pub k_domain: u32,
    /// Epsilon of the Laplace noise on released counts.
    pub epsilon_central: f64,
    /// Web page describing this collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about_url: Option<String>,
}

/// Released items as of the start of `epoch`, frozen: every participant
/// randomizes against the same list.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Catalogue {
    pub epoch: u32,
    pub items: Vec<Item>,
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

/// The public result: items reported by enough participants, with a noisy
/// support (participants per epoch, at most).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Released {
    /// Counts up to this epoch, excluded.
    pub until_epoch: u32,
    pub k_hello: u32,
    pub k_domain: u32,
    pub epsilon_central: f64,
    pub items: Vec<ReleasedItem>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReleasedItem {
    pub item: Item,
    /// Noisy estimate, rounded.
    pub support: i64,
}
