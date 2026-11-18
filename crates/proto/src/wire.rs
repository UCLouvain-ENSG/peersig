//! API messages. `GET /v1/config` and `POST /v1/ballot` go through
//! Oblivious HTTP (`POST /ohttp`); only
//! `POST /v1/issue`, which is authenticated by the enrollment code anyway,
//! goes directly to the server. So does `POST /v1/observe`: a dedicated
//! observer's daily report, which is not anonymous.

use serde::{Deserialize, Serialize};

use crate::{EpochSpec, Item, Token};

pub const PATH_CONFIG: &str = "/v1/config";
pub const PATH_ISSUE: &str = "/v1/issue";
pub const PATH_BALLOT: &str = "/v1/ballot";
pub const PATH_RELEASED: &str = "/v1/released";
pub const PATH_OHTTP: &str = "/ohttp";
pub const PATH_OHTTP_KEYS: &str = "/ohttp-keys";
pub const PATH_OBSERVE: &str = "/v1/observe";
/// What a code is: a participant's or an observer's (`CodeCheck`).
pub const PATH_CODE: &str = "/v1/code";
/// The observers' daily table: the list of days, and `/<YYYY-MM-DD>` for one.
pub const PATH_OBSERVED: &str = "/v1/released/observers";

/// Days back an observer may still report (its logs are kept 14 days).
pub const OBSERVER_LATE_DAYS: u32 = 7;
/// Items in one observer report, at most.
pub const OBSERVER_MAX_ITEMS: usize = 10_000;

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

/// A dedicated observer's report: every item it saw on one day (UTC), in
/// one request authenticated by its code. Not a ballot: the server knows
/// which observer sends it, and publishes the day's items without
/// threshold.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObserverReport {
    pub code: String,
    /// Day number from the collection's origin (`EpochSpec::days`).
    pub day: u32,
    pub items: Vec<Item>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObserverReceipt {
    /// The observer's label on the server (`O01`).
    pub label: String,
    pub day: u32,
    /// Distinct items counted.
    pub items: usize,
}

/// Asks the server what a code is (`peersig configure` and `status`),
/// directly, as token issuance does. 403 for an unknown or withdrawn code.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CodeCheck {
    pub code: String,
}

/// A participant's code: `observer` false, nothing else (its ballots are
/// anonymous). An observer's: its label and its reports.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CodeInfo {
    pub observer: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Days reported so far (observers).
    #[serde(default)]
    pub days: u32,
    /// The last day reported, YYYY-MM-DD (UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_day: Option<String>,
}

/// One day of the observers' table: every item any observer reported,
/// with how many reported it. No threshold.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObservedDay {
    /// YYYY-MM-DD, UTC.
    pub day: String,
    /// Observers that reported this day.
    pub observers: u32,
    pub items: Vec<ObservedItem>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObservedItem {
    pub item: Item,
    pub observers: u32,
}

/// The days of the observers' table, most recent first.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObservedDays {
    pub days: Vec<ObservedDaySummary>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ObservedDaySummary {
    pub day: String,
    pub observers: u32,
    pub items: u32,
}
