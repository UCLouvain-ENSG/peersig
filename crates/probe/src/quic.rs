//! QUIC client Initial packets: header protection removal and decryption
//! (RFC 9001 §5, RFC 9369 for v2), and the CRYPTO frames they carry.
//!
//! A ClientHello with a post-quantum key share spans two or more Initial
//! packets, often in separate datagrams, and Chromium scatters CRYPTO frames
//! out of order between PING and PADDING frames: `flow::Tracker` puts the
//! pieces back together by stream offset.

use aes::cipher::BlockEncrypt;
use aes::Aes128;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::tls::Reader;

pub const V1: u32 = 0x0000_0001;
pub const V2: u32 = 0x6b33_43cf;

const SALT_V1: [u8; 20] = hex20("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
const SALT_V2: [u8; 20] = hex20("0dede3def700a6db819381be6e269dcbf9bd2ed9");
const SALT_D29: [u8; 20] = hex20("afbfec289993d24c9e9786f19c6111e04390a899");
const SALT_D23: [u8; 20] = hex20("c3eef712c72ebb5a11a7d2432bb46365bef9f502");

const fn hex20(s: &str) -> [u8; 20] {
    let b = s.as_bytes();
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex"),
    }
}

fn salt(version: u32) -> Option<&'static [u8; 20]> {
    match version {
        V1 | 0xff00_0021 | 0xff00_0022 => Some(&SALT_V1),
        V2 => Some(&SALT_V2),
        0xff00_001d..=0xff00_0020 => Some(&SALT_D29),
        0xff00_0017..=0xff00_001c => Some(&SALT_D23),
        _ => None,
    }
}

pub fn version_name(v: u32) -> String {
    match v {
        V1 => "v1".into(),
        V2 => "v2".into(),
        0xff00_0000..=0xff00_00ff => format!("draft-{}", v & 0xff),
        _ => format!("0x{:08x}", v),
    }
}

/// Long-header packet types are numbered differently in v2.
fn is_initial(version: u32, first: u8) -> bool {
    let t = (first >> 4) & 0x03;
    if version == V2 {
        t == 1
    } else {
        t == 0
    }
}

fn is_retry(version: u32, first: u8) -> bool {
    let t = (first >> 4) & 0x03;
    if version == V2 {
        t == 0
    } else {
        t == 3
    }
}

#[derive(Clone)]
pub struct Keys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

fn expand_label(prk: &Hkdf<Sha256>, label: &str, out: &mut [u8]) {
    let full = format!("tls13 {}", label);
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    prk.expand(&info, out).expect("HKDF output length");
}

/// Client Initial keys for a destination connection id.
pub fn client_keys(dcid: &[u8], version: u32) -> Option<Keys> {
    let salt = salt(version)?;
    let (_, initial) = Hkdf::<Sha256>::extract(Some(salt), dcid);
    let mut secret = [0u8; 32];
    expand_label(&initial, "client in", &mut secret);
    let hk = Hkdf::<Sha256>::from_prk(&secret).ok()?;
    let p = if version == V2 { "quicv2 " } else { "quic " };
    let mut k = Keys { key: [0; 16], iv: [0; 12], hp: [0; 16] };
    expand_label(&hk, &format!("{}key", p), &mut k.key);
    expand_label(&hk, &format!("{}iv", p), &mut k.iv);
    expand_label(&hk, &format!("{}hp", p), &mut k.hp);
    Some(k)
}

/// One long-header packet found in a datagram.
pub struct LongHeader<'a> {
    pub version: u32,
    pub dcid: &'a [u8],
    /// Whole packet (header + protected payload).
    pub packet: &'a [u8],
    /// Offset of the packet number inside `packet`.
    pub pn_offset: usize,
    pub initial: bool,
}

pub enum Datagram<'a> {
    /// Not a QUIC long header (short header, other protocol).
    NotLong,
    /// Version negotiation or a version with unknown Initial salt.
    Unsupported(u32),
    Packets(Vec<LongHeader<'a>>),
}

/// Splits a UDP payload into its coalesced long-header packets.
pub fn split(payload: &[u8]) -> Datagram<'_> {
    if payload.len() < 7 || payload[0] & 0x80 == 0 {
        return Datagram::NotLong;
    }
    let mut out = Vec::new();
    let mut rest = payload;
    while rest.len() >= 7 && rest[0] & 0x80 != 0 {
        let first = rest[0];
        let mut r = Reader::new(rest);
        r.u8();
        let Some(version) = r.u32() else { break };
        if version == 0 || salt(version).is_none() {
            if out.is_empty() {
                return Datagram::Unsupported(version);
            }
            break;
        }
        let Some(dl) = r.u8() else { break };
        if dl > 20 {
            break;
        }
        let Some(dcid) = r.bytes(dl as usize) else { break };
        let Some(sl) = r.u8() else { break };
        if sl > 20 {
            break;
        }
        if r.bytes(sl as usize).is_none() {
            break;
        }
        if is_retry(version, first) {
            break;
        }
        let initial = is_initial(version, first);
        if initial {
            let Some(tl) = r.varint() else { break };
            if r.bytes(tl as usize).is_none() {
                break;
            }
        }
        let Some(len) = r.varint() else { break };
        let pn_offset = r.pos();
        let end = pn_offset + len as usize;
        if end > rest.len() || len < 20 {
            break;
        }
        out.push(LongHeader { version, dcid, packet: &rest[..end], pn_offset, initial });
        rest = &rest[end..];
    }
    if out.is_empty() {
        Datagram::NotLong
    } else {
        Datagram::Packets(out)
    }
}

/// Removes header protection and decrypts an Initial packet; returns the
/// plaintext frames. None when the AEAD tag does not verify (wrong keys).
pub fn decrypt(lh: &LongHeader, keys: &Keys) -> Option<Vec<u8>> {
    let p = lh.packet;
    let sample_at = lh.pn_offset + 4;
    if p.len() < sample_at + 16 {
        return None;
    }
    let hp = Aes128::new_from_slice(&keys.hp).ok()?;
    let mut block = aes::Block::clone_from_slice(&p[sample_at..sample_at + 16]);
    hp.encrypt_block(&mut block);
    let mask = block;
    let first = p[0] ^ (mask[0] & 0x0f);
    let pn_len = (first & 0x03) as usize + 1;
    if p.len() < lh.pn_offset + pn_len + 16 {
        return None;
    }
    let mut header = p[..lh.pn_offset + pn_len].to_vec();
    header[0] = first;
    let mut pn: u64 = 0;
    for i in 0..pn_len {
        header[lh.pn_offset + i] ^= mask[1 + i];
        pn = (pn << 8) | header[lh.pn_offset + i] as u64;
    }
    let mut nonce = keys.iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let body = &p[lh.pn_offset + pn_len..];
    let (ct, tag) = body.split_at(body.len() - 16);
    let mut buf = ct.to_vec();
    let aead = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    aead.decrypt_in_place_detached(Nonce::from_slice(&nonce), &header, &mut buf, Tag::from_slice(tag))
        .ok()?;
    Some(buf)
}

/// CRYPTO frames of a decrypted Initial payload, as (stream offset, data).
pub fn crypto_frames(plain: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut out = Vec::new();
    let mut r = Reader::new(plain);
    while r.remaining() > 0 {
        let Some(t) = r.varint() else { break };
        match t {
            0x00 | 0x01 => {} // PADDING, PING
            0x02 | 0x03 => {
                // ACK: largest, delay, range count, first range, ranges, [ECN]
                let ok = (|| {
                    r.varint()?;
                    r.varint()?;
                    let n = r.varint()?;
                    r.varint()?;
                    for _ in 0..n {
                        r.varint()?;
                        r.varint()?;
                    }
                    if t == 0x03 {
                        r.varint()?;
                        r.varint()?;
                        r.varint()?;
                    }
                    Some(())
                })();
                if ok.is_none() {
                    break;
                }
            }
            0x06 => {
                let (Some(off), Some(len)) = (r.varint(), r.varint()) else { break };
                let Some(data) = r.bytes(len as usize) else { break };
                out.push((off, data.to_vec()));
            }
            0x1c | 0x1d => break, // CONNECTION_CLOSE: nothing after it matters
            _ => break,           // not allowed in Initial packets
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9001 Appendix A.1 and RFC 9369 Appendix A.1 key derivation.
    #[test]
    fn rfc_keys() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let k = client_keys(&dcid, V1).unwrap();
        assert_eq!(hex(&k.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&k.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&k.hp), "9f50449e04a0e810283a1e9933adedd2");
        let k2 = client_keys(&dcid, V2).unwrap();
        assert_eq!(hex(&k2.key), "8b1a0bc121284290a29e0971b5cd045d");
        assert_eq!(hex(&k2.iv), "91f73e2351d8fa91660e909f");
        assert_eq!(hex(&k2.hp), "45b95e15235d6f45a6b19cbcb0294ba9");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }
}
