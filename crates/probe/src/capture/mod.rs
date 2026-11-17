//! Where packets come from: libpcap on macOS and Linux; on Windows the
//! packet capture built into the system (NDIS, read through ETW), so that
//! nothing needs installing beside PeerSig, and a reader for capture files.

/// Time (Unix seconds), link type, frame.
pub type Packet = (f64, i32, Vec<u8>);

/// Capture counters, as libpcap's `pcap_stat`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub received: u64,
    pub dropped: u64,
    pub if_dropped: u64,
}

#[cfg(any(windows, test))]
pub mod file;

#[cfg(not(windows))]
mod libpcap;
#[cfg(not(windows))]
pub use libpcap::{Live, Offline};

#[cfg(windows)]
mod etw;
#[cfg(windows)]
pub use etw::Live;
#[cfg(windows)]
pub use file::Reader as Offline;
