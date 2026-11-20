//! peersig-probe as a library: the packet pipeline (ClientHellos, JA4,
//! attribution, names) and the daily logs, for the `peersig-probe`
//! command (src/main.rs) and for the Android app, which feeds the same
//! pipeline with the packets of its VPN interface (crates/android). See
//! README.md.

pub mod attrib;
pub mod binary;
pub mod bundle;
/// Live capture and capture files. Android has neither: its packets come
/// from the app's VPN interface.
#[cfg(not(target_os = "android"))]
pub mod capture;
pub mod dns;
pub mod domains;
pub mod fingerprint;
pub mod flow;
pub mod logdir;
pub mod net;
pub mod pipeline;
pub mod platform;
pub mod quic;
pub mod summary;
pub mod tls;
