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
//! - [`rr`]: randomized response over the public catalogue (local
//!   differential privacy) and the server-side debiasing.
//! - [`plan`]: turns a week's items into the shuffled list of ballots.
//! - [`wire`]: API messages.
//! - `client` (feature `client`): the HTTP client used by the app.

pub mod b64;
pub mod epoch;
pub mod item;
pub mod oblivious;
pub mod plan;
pub mod rr;
pub mod token;
pub mod wire;

#[cfg(feature = "client")]
pub mod client;

pub use epoch::EpochSpec;
pub use item::{AppRef, Class, Item};
pub use token::Token;

/// Hex of the first `n` bytes of SHA-256: short identifiers shown to people.
pub fn short_hash(data: &[u8], n: usize) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)[..n].iter().map(|b| format!("{:02x}", b)).collect()
}
