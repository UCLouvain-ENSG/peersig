//! Link layers, Apple's PKTAP header, IPv4/IPv6, TCP and UDP.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DLT_NULL: i32 = 0;
pub const DLT_EN10MB: i32 = 1;
pub const DLT_RAW: i32 = 12;
pub const DLT_RAW_BSD: i32 = 14;
pub const DLT_LINKTYPE_RAW: i32 = 101;
pub const DLT_LOOP: i32 = 108;
pub const DLT_LINUX_SLL: i32 = 113;
/// Apple's DLT_PKTAP is DLT_USER2; LINKTYPE_PKTAP in files elsewhere.
pub const DLT_PKTAP_APPLE: i32 = 149;
pub const DLT_PKTAP: i32 = 258;
pub const DLT_IPV4: i32 = 228;
pub const DLT_IPV6: i32 = 229;
pub const DLT_LINUX_SLL2: i32 = 276;

pub fn is_pktap(dlt: i32) -> bool {
    dlt == DLT_PKTAP_APPLE || dlt == DLT_PKTAP
}

/// Per-packet metadata of a PKTAP capture (xnu bsd/net/pktap.h).
#[derive(Debug, Clone, Default)]
pub struct PktapMeta {
    pub ifname: String,
    pub flags: u32,
    pub pid: i32,
    pub comm: String,
    /// Effective process: the one a delegated socket works for
    /// (nsurlsessiond downloading for softwareupdated, for instance).
    pub epid: i32,
    pub ecomm: String,
    pub svc: u32,
    pub uuid: Option<[u8; 16]>,
    pub euuid: Option<[u8; 16]>,
}

pub const PTH_FLAG_DIR_IN: u32 = 0x1;
pub const PTH_FLAG_PROC_DELEGATED: u32 = 0x4;

impl PktapMeta {
    /// mbuf service class (xnu kpi_mbuf.h): BK_SYS and BK are background
    /// traffic (software updates, backups), VO/VI/AV interactive media.
    pub fn svc_name(&self) -> String {
        match self.svc {
            0x0008_0090 => "BK_SYS".into(),
            0x0010_0080 => "BK".into(),
            0x0000_0000 => "BE".into(),
            0x0018_0010 => "RD".into(),
            0x0020_0020 => "OAM".into(),
            0x0028_0120 => "AV".into(),
            0x0030_0110 => "RV".into(),
            0x0038_0100 => "VI".into(),
            0x0038_0130 => "SIG".into(),
            0x0040_0180 => "VO".into(),
            0x0048_0190 => "CTL".into(),
            v => format!("0x{:08x}", v),
        }
    }
    pub fn delegated(&self) -> bool {
        self.flags & PTH_FLAG_PROC_DELEGATED != 0 || (self.epid > 0 && self.epid != self.pid)
    }
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// The header is in host byte order; every Mac is little-endian.
/// Returns (meta, inner DLT, offset of the inner frame).
pub fn parse_pktap(d: &[u8]) -> Option<(PktapMeta, i32, usize)> {
    // v1 `struct pktap_header`: pth_length (u32), pth_type_next (u32, 1 = packet)...
    let len = le32(d, 0)? as usize;
    if le32(d, 4)? == 1 && (108..=1024).contains(&len) && len <= d.len() {
        let mut m = PktapMeta {
            ifname: cstr(&d[12..36]),
            flags: le32(d, 36)?,
            pid: le32(d, 52)? as i32,
            comm: cstr(&d[56..73]),
            svc: le32(d, 76)?,
            epid: le32(d, 84)? as i32,
            ecomm: cstr(&d[88..105]),
            ..Default::default()
        };
        if len >= 156 {
            m.uuid = d[124..140].try_into().ok();
            m.euuid = d[140..156].try_into().ok();
        }
        return Some((m, le32(d, 8)? as i32, len));
    }
    // v2 `struct pktap_v2_hdr`: u8 length and offsets of the variable fields.
    let len = d[0] as usize;
    if len >= 40 && len <= d.len() {
        let off = |i: usize| d[i] as usize;
        let s = |o: usize, max: usize| -> String {
            if o == 0 || o >= len {
                String::new()
            } else {
                cstr(&d[o..(o + max).min(len)])
            }
        };
        let uuid = |o: usize| -> Option<[u8; 16]> {
            if o == 0 || o + 16 > len {
                None
            } else {
                d[o..o + 16].try_into().ok()
            }
        };
        let m = PktapMeta {
            ifname: s(off(3), 24),
            comm: s(off(4), 32),
            ecomm: s(off(5), 32),
            uuid: uuid(off(1)),
            euuid: uuid(off(2)),
            svc: le32(d, 20)?,
            pid: le32(d, 28)? as i32,
            epid: le32(d, 32)? as i32,
            flags: le32(d, 36)?,
        };
        return Some((m, le16(d, 6)? as i32, len));
    }
    None
}

/// Kernel filter for a PKTAP capture. libpcap cannot compile protocol
/// filters for DLT_PKTAP, so this reads the header with `link[]`:
/// - outbound packets, from the flag word at offset 36 (the same offset in
///   the v1 and v2 headers). ClientHellos are always sent, so downloads
///   (macOS updates, video) stay in the kernel;
/// - with `dns`, inbound UDP from port 53, for the answers that name
///   connections. The IP header is found from the inner link type at offset
///   8 (Ethernet, loopback/utun, raw IP) and the header length at offset 0.
#[cfg_attr(windows, allow(dead_code))]
pub fn pktap_filter(dns: bool) -> String {
    let out = "link[36] & 2 != 0".to_string();
    if !dns {
        return out;
    }
    let ip = |off: usize| {
        let h = if off == 0 { "link[0]".to_string() } else { format!("link[0]+{}", off) };
        format!(
            "(((link[{h}] & 0xf0) = 0x40 and link[{h}+9] = 17 and link[{h}+((link[{h}] & 0x0f) << 2):2] = 53) or \
             ((link[{h}] & 0xf0) = 0x60 and link[{h}+6] = 17 and link[{h}+40:2] = 53))"
        )
    };
    let parts: Vec<String> = [(DLT_EN10MB, 14), (DLT_NULL, 4), (DLT_RAW, 0)]
        .iter()
        .map(|(dlt, off)| format!("(link[8] = {} and {})", dlt, ip(*off)))
        .collect();
    format!("{} or {}", out, parts.join(" or "))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    pub proto: u8,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

pub struct L4<'a> {
    pub key: FlowKey,
    pub payload: &'a [u8],
    pub tcp_seq: u32,
    pub tcp_flags: u8,
}

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

/// Finds the IP header behind a link-layer header.
pub fn ip_offset(dlt: i32, d: &[u8]) -> Option<usize> {
    match dlt {
        DLT_EN10MB => {
            let mut off = 12;
            let mut et = u16::from_be_bytes(d.get(off..off + 2)?.try_into().ok()?);
            while et == 0x8100 || et == 0x88a8 {
                off += 4;
                et = u16::from_be_bytes(d.get(off..off + 2)?.try_into().ok()?);
            }
            matches!(et, 0x0800 | 0x86dd).then_some(off + 2)
        }
        DLT_NULL | DLT_LOOP => Some(4),
        DLT_RAW | DLT_RAW_BSD | DLT_LINKTYPE_RAW | DLT_IPV4 | DLT_IPV6 => Some(0),
        DLT_LINUX_SLL => Some(16),
        DLT_LINUX_SLL2 => Some(20),
        _ => None,
    }
}

pub fn parse_ip(d: &[u8]) -> Option<L4<'_>> {
    let v = d.first()? >> 4;
    let (src, dst, proto, l4) = match v {
        4 => {
            if d.len() < 20 {
                return None;
            }
            let ihl = ((d[0] & 0x0f) as usize) * 4;
            let total = u16::from_be_bytes([d[2], d[3]]) as usize;
            let frag = u16::from_be_bytes([d[6], d[7]]);
            if frag & 0x1fff != 0 || frag & 0x2000 != 0 {
                return None; // fragments: never a whole ClientHello datagram
            }
            // Outbound packets seen before TSO may carry total length 0.
            let end = if total >= ihl && total <= d.len() { total } else { d.len() };
            if ihl < 20 || end < ihl {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(d[12], d[13], d[14], d[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(d[16], d[17], d[18], d[19]));
            (src, dst, d[9], &d[ihl..end])
        }
        6 => {
            if d.len() < 40 {
                return None;
            }
            let plen = u16::from_be_bytes([d[4], d[5]]) as usize;
            let end = if plen > 0 && 40 + plen <= d.len() { 40 + plen } else { d.len() };
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&d[8..24]).ok()?));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&d[24..40]).ok()?));
            let mut nh = d[6];
            let mut off = 40;
            // Hop-by-hop, routing, destination options; fragments are skipped.
            loop {
                match nh {
                    0 | 43 | 60 => {
                        let h = d.get(off..off + 2)?;
                        nh = h[0];
                        off += (h[1] as usize + 1) * 8;
                    }
                    44 => return None,
                    _ => break,
                }
                if off > end {
                    return None;
                }
            }
            (src, dst, nh, &d[off..end])
        }
        _ => return None,
    };
    match proto {
        TCP => {
            if l4.len() < 20 {
                return None;
            }
            let doff = ((l4[12] >> 4) as usize) * 4;
            if doff < 20 || doff > l4.len() {
                return None;
            }
            Some(L4 {
                key: FlowKey {
                    proto,
                    src,
                    sport: u16::from_be_bytes([l4[0], l4[1]]),
                    dst,
                    dport: u16::from_be_bytes([l4[2], l4[3]]),
                },
                payload: &l4[doff..],
                tcp_seq: u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]),
                tcp_flags: l4[13],
            })
        }
        UDP => {
            if l4.len() < 8 {
                return None;
            }
            let ulen = u16::from_be_bytes([l4[4], l4[5]]) as usize;
            let end = if ulen >= 8 && ulen <= l4.len() { ulen } else { l4.len() };
            Some(L4 {
                key: FlowKey {
                    proto,
                    src,
                    sport: u16::from_be_bytes([l4[0], l4[1]]),
                    dst,
                    dport: u16::from_be_bytes([l4[2], l4[3]]),
                },
                payload: &l4[8..end],
                tcp_seq: 0,
                tcp_flags: 0,
            })
        }
        _ => None,
    }
}

/// A frame decoded down to L4, with the PKTAP metadata when there is some.
pub fn decode(dlt: i32, data: &[u8]) -> Option<(Option<PktapMeta>, L4<'_>)> {
    if is_pktap(dlt) {
        let (meta, inner, off) = parse_pktap(data)?;
        let frame = &data[off..];
        let ip = match ip_offset(inner, frame) {
            Some(o) => o,
            // Unknown inner link type: look for an IP header where it would
            // be on the common ones.
            None => [0usize, 4, 14].into_iter().find(|&o| {
                frame.get(o).map_or(false, |b| b >> 4 == 4 || b >> 4 == 6)
            })?,
        };
        let l4 = parse_ip(frame.get(ip..)?)?;
        return Some((Some(meta), l4));
    }
    let off = ip_offset(dlt, data)?;
    Some((None, parse_ip(data.get(off..)?)?))
}
