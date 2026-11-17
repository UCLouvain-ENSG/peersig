//! macOS and Linux: libpcap (PKTAP on macOS, "any" on Linux).

use anyhow::{Context, Result};

use super::{Packet, Stats};
use crate::net;
#[cfg(target_os = "macos")]
use crate::platform;

fn ts_of(h: &pcap::PacketHeader) -> f64 {
    h.ts.tv_sec as f64 + h.ts.tv_usec as f64 / 1e6
}

pub struct Live {
    cap: pcap::Capture<pcap::Active>,
    dlt: i32,
    filter: String,
}

pub type Saver = pcap::Savefile;

impl Live {
    /// Opens the capture device with its kernel filter (the one asked for,
    /// or the default for its link type).
    pub fn open(device: &str, snaplen: i32, bpf: &Option<String>, names: bool) -> Result<Live> {
        let inactive = pcap::Capture::from_device(device)?.snaplen(snaplen).buffer_size(16 << 20).promisc(false).timeout(100);
        #[cfg(target_os = "macos")]
        if device.starts_with("pktap") && !platform::want_pktap(inactive.as_ptr().cast()) {
            eprintln!("warning: this libpcap has no pcap_set_want_pktap: no per-packet process metadata");
        }
        let mut cap = inactive.open().with_context(|| format!("opening {}", device))?;
        let dlt = cap.get_datalink().0;
        let filter = match bpf {
            Some(f) => f.clone(),
            None if net::is_pktap(dlt) => net::pktap_filter(names),
            None => String::new(),
        };
        let mut used = filter.clone();
        if !filter.is_empty() {
            if let Err(e) = cap.filter(&filter, true) {
                eprintln!("warning: kernel filter rejected ({}); filtering in user space only", e);
                used = String::new();
            }
        }
        Ok(Live { cap, dlt, filter: used })
    }

    pub fn dlt(&self) -> i32 {
        self.dlt
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// A file for `--save-pcap` (pcap, with this capture's link type).
    pub fn saver(&self, path: &str, _snaplen: i32) -> Result<Saver> {
        Ok(self.cap.savefile(path)?)
    }

    /// The next packet, also written to `save`; None when the read timeout
    /// expires.
    pub fn next(&mut self, save: Option<&mut Saver>) -> Result<Option<Packet>> {
        match self.cap.next_packet() {
            Ok(pkt) => {
                if let Some(s) = save {
                    s.write(&pkt);
                }
                Ok(Some((ts_of(pkt.header), self.dlt, pkt.data.to_vec())))
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn stats(&mut self) -> Option<Stats> {
        self.cap.stats().ok().map(|s| Stats { received: s.received as u64, dropped: s.dropped as u64, if_dropped: s.if_dropped as u64 })
    }
}

pub struct Offline {
    cap: pcap::Capture<pcap::Offline>,
    dlt: i32,
}

impl Offline {
    pub fn open(path: &str) -> Result<Offline> {
        let cap = pcap::Capture::from_file(path).with_context(|| path.to_string())?;
        let dlt = cap.get_datalink().0;
        Ok(Offline { cap, dlt })
    }

    pub fn dlt(&self) -> i32 {
        self.dlt
    }

    /// The next packet; None at the end of the file.
    pub fn next(&mut self) -> Result<Option<Packet>> {
        match self.cap.next_packet() {
            Ok(p) => Ok(Some((ts_of(p.header), self.dlt, p.data.to_vec()))),
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
