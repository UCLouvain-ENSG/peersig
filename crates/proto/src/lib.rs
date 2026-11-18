//! PeerSig's shared protocol: what a participant's computer may send, how it
//! is made anonymous, and the wire format between the app and the server.
//!
//! - [`item`]: the only things a ballot can carry, and how the app derives
//!   them from the probe's local logs (no addresses, paths, times or ports).
//! - [`token`]: RSA blind-signature tokens (RFC 9474). The server signs
//!   tokens for an enrolled participant without seeing them, so a ballot
//!   proves its sender is enrolled but not who it is.
//! - [`oblivious`]: Oblivious HTTP (RFC 9458) framing. Ballots go through a
//!   relay that sees the sender's address but not the content; the server
//!   sees the content but not the address.
//! - [`plan`]: turns a week's items into the shuffled list of ballots.
//! - [`wire`]: API messages.
//! - [`code`]: enrollment codes, and how to tell an observer's.
//! - [`logs`]: reads the probe's daily logs into one period's items.
//! - `client` (feature `client`): the HTTP client used by the app.
//! - `participant` (feature `client`): a week's ballots and their tokens,
//!   for the app and the headless `peersig`.

pub mod b64;
pub mod code;
pub mod epoch;
pub mod item;
pub mod logs;
pub mod merge;
pub mod oblivious;
pub mod plan;
pub mod token;
pub mod wire;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub mod participant;

pub use epoch::EpochSpec;
pub use item::{AppRef, Class, Item};
pub use token::Token;

/// Hex of the first `n` bytes of SHA-256: short identifiers shown to people.
pub fn short_hash(data: &[u8], n: usize) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)[..n].iter().map(|b| format!("{:02x}", b)).collect()
}
