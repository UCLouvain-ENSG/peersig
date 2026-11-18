//! JA4 (FoxIO spec, technical_details/JA4.md), its raw and original-order
//! variants, JA3, and `ja4_legacy`: an earlier, non-standard value (the
//! extension hash without the signature algorithms), to join with TAP
//! records archived with it before 2026-11-16.

use crate::tls::{is_grease, ClientHello, EXT_ALPN, EXT_SNI};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct Fingerprints {
    pub ja4: String,
    pub ja4_r: String,
    pub ja4_o: String,
    pub ja4_ro: String,
    /// The earlier value, archived until 2026-11-16: its extension hash
    /// left out the signature algorithms. None for DTLS (never archived).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4_legacy: Option<String>,
    pub ja3: String,
    pub ja3_r: String,
}

/// Transport letter of JA4_a.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Quic,
    Dtls,
}

impl Transport {
    pub fn letter(self) -> char {
        match self {
            Transport::Tcp => 't',
            Transport::Quic => 'q',
            Transport::Dtls => 'd',
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Quic => "quic",
            Transport::Dtls => "dtls",
        }
    }
}

fn version_code(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        0x0100 => "s1",
        0xfeff => "d1",
        0xfefd => "d2",
        0xfefc => "d3",
        _ => "00",
    }
}

/// Highest version offered: supported_versions if present, else the legacy
/// field. DTLS numbers count down (0xfefc is DTLS 1.3), so the newest one is
/// the smallest there.
pub fn offered_version(ch: &ClientHello) -> u16 {
    let sv = ch.supported_versions.iter().copied().filter(|v| !is_grease(*v));
    let best = if ch.dtls { sv.min() } else { sv.max() };
    best.unwrap_or(ch.legacy_version)
}

fn alpn_code(ch: &ClientHello) -> String {
    let Some(first) = ch.alpn.first() else { return "00".into() };
    if first.is_empty() {
        return "00".into();
    }
    let (a, b) = (first[0], first[first.len() - 1]);
    if a.is_ascii_alphanumeric() && b.is_ascii_alphanumeric() {
        format!("{}{}", a as char, b as char)
    } else {
        let hex = hex(first);
        let c = hex.as_bytes();
        format!("{}{}", c[0] as char, c[c.len() - 1] as char)
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_list(v: &[u16]) -> String {
    v.iter().map(|x| format!("{:04x}", x)).collect::<Vec<_>>().join(",")
}

fn hash12(s: &str) -> String {
    if s.is_empty() {
        return "000000000000".into();
    }
    hex(&Sha256::digest(s.as_bytes())[..6])
}

fn no_grease(v: &[u16]) -> Vec<u16> {
    v.iter().copied().filter(|x| !is_grease(*x)).collect()
}

pub fn compute(ch: &ClientHello, transport: Transport) -> Fingerprints {
    let ciphers = no_grease(&ch.ciphers);
    let exts = no_grease(&ch.extensions);
    let sigs = no_grease(&ch.sig_algs);
    let sni = if ch.has_ext(EXT_SNI) { 'd' } else { 'i' };
    let a = format!(
        "{}{}{}{:02}{:02}{}",
        transport.letter(),
        version_code(offered_version(ch)),
        sni,
        ciphers.len().min(99),
        exts.len().min(99),
        alpn_code(ch)
    );

    let mut ciphers_sorted = ciphers.clone();
    ciphers_sorted.sort_unstable();
    let mut exts_sorted: Vec<u16> =
        exts.iter().copied().filter(|e| *e != EXT_SNI && *e != EXT_ALPN).collect();
    exts_sorted.sort_unstable();

    let sig_part = if sigs.is_empty() { String::new() } else { format!("_{}", hex_list(&sigs)) };
    let c_sorted = if exts_sorted.is_empty() {
        String::new()
    } else {
        format!("{}{}", hex_list(&exts_sorted), sig_part)
    };
    let c_orig = if exts.is_empty() { String::new() } else { format!("{}{}", hex_list(&exts), sig_part) };

    let ja4 = format!("{}_{}_{}", a, hash12(&hex_list(&ciphers_sorted)), hash12(&c_sorted));
    let ja4_o = format!("{}_{}_{}", a, hash12(&hex_list(&ciphers)), hash12(&c_orig));
    let ja4_r = format!("{}_{}_{}{}", a, hex_list(&ciphers_sorted), hex_list(&exts_sorted), sig_part);
    let ja4_ro = format!("{}_{}_{}{}", a, hex_list(&ciphers), hex_list(&exts), sig_part);

    let ja4_legacy = (transport != Transport::Dtls).then(|| legacy_ja4(ch, transport, &ciphers_sorted, &exts_sorted));

    let dec = |v: &[u16]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-");
    let ja3_r = format!(
        "{},{},{},{},{}",
        ch.legacy_version,
        dec(&ciphers),
        dec(&exts),
        dec(&no_grease(&ch.groups)),
        ch.ec_point_formats.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-")
    );
    let ja3 = format!("{:x}", md5::compute(ja3_r.as_bytes()));

    Fingerprints { ja4, ja4_r, ja4_o, ja4_ro, ja4_legacy, ja3, ja3_r }
}

/// Mirror of `traffic_classifier::ja4::compute_ja4` before 2026-11-16: same JA4_a and JA4_b,
/// JA4_c over the sorted extensions only, ALPN as its first and last bytes
/// whatever they are. SNI flag from a non-empty parsed name.
fn legacy_ja4(ch: &ClientHello, transport: Transport, ciphers_sorted: &[u16], exts_sorted: &[u16]) -> String {
    let ver = match offered_version(ch) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let sni = if ch.sni.as_deref().map_or(true, str::is_empty) { 'i' } else { 'd' };
    let alpn = match ch.alpn.first() {
        Some(p) if p.len() >= 2 => format!("{}{}", p[0] as char, p[p.len() - 1] as char),
        Some(p) if p.len() == 1 => format!("{}{}", p[0] as char, p[0] as char),
        _ => "00".into(),
    };
    format!(
        "{}{}{}{:02}{:02}{}_{}_{}",
        transport.letter(),
        ver,
        sni,
        no_grease(&ch.ciphers).len().min(99),
        no_grease(&ch.extensions).len().min(99),
        alpn,
        hash12(&hex_list(ciphers_sorted)),
        hash12(&hex_list(exts_sorted))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JA4.md's worked example (Chrome, t13d1516h2_8daaf6152771_e5627efa2ab1).
    #[test]
    fn foxio_example() {
        let ch = ClientHello {
            legacy_version: 0x0303,
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: vec![
                0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023,
                0x0012, 0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
            ],
            sni: Some("example.com".into()),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            sig_algs: vec![0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
            supported_versions: vec![0x0a0a, 0x0304, 0x0303],
            ..Default::default()
        };
        let f = compute(&ch, Transport::Tcp);
        assert_eq!(f.ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(
            f.ja4_r,
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"
        );
        assert_eq!(f.ja4_o, "t13d1516h2_acb858a92679_18f69afefd3d");
    }

    #[test]
    fn alpn_non_alnum() {
        let mut ch = ClientHello { alpn: vec![vec![0xab]], ..Default::default() };
        assert_eq!(alpn_code(&ch), "ab");
        ch.alpn = vec![vec![0x20, 0x61]];
        assert_eq!(alpn_code(&ch), "21");
        ch.alpn = vec![vec![0x30, 0xab]];
        assert_eq!(alpn_code(&ch), "3b");
        ch.alpn = vec![b"h".to_vec()];
        assert_eq!(alpn_code(&ch), "hh");
        ch.alpn = vec![];
        assert_eq!(alpn_code(&ch), "00");
    }
}
