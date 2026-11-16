//! ClientHello parsing, shared by TLS over TCP, QUIC and DTLS.
//!
//! Only what fingerprints and the record need is kept. A malformed extension
//! body is skipped, not fatal: the extension type list (what JA4 hashes) is
//! still exact.

pub const EXT_SNI: u16 = 0x0000;
pub const EXT_GROUPS: u16 = 0x000a;
pub const EXT_EC_POINT_FORMATS: u16 = 0x000b;
pub const EXT_SIG_ALGS: u16 = 0x000d;
pub const EXT_ALPN: u16 = 0x0010;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
pub const EXT_QUIC_TP: u16 = 0x0039;
pub const EXT_QUIC_TP_DRAFT: u16 = 0xffa5;
pub const EXT_ECH: u16 = 0xfe0d;

/// GREASE values (RFC 8701): 0x?a?a with both bytes equal.
pub fn is_grease(v: u16) -> bool {
    (v & 0x0f0f) == 0x0a0a && (v >> 8) == (v & 0xff)
}

#[derive(Debug, Clone, Default)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    /// Extension types in wire order, GREASE included.
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    pub sig_algs: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    /// QUIC transport parameter 0x3129 (Chromium's user agent id), when sent.
    pub quic_user_agent: Option<String>,
    pub dtls: bool,
}

impl ClientHello {
    pub fn has_ext(&self, t: u16) -> bool {
        self.extensions.contains(&t)
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn pos(&self) -> usize {
        self.pos
    }
    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    pub fn u16(&mut self) -> Option<u16> {
        let b = self.bytes(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u24(&mut self) -> Option<u32> {
        let b = self.bytes(3)?;
        Some(((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32)
    }
    pub fn u32(&mut self) -> Option<u32> {
        let b = self.bytes(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    /// QUIC variable-length integer (RFC 9000 §16).
    pub fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let len = 1usize << (first >> 6);
        let mut v = (first & 0x3f) as u64;
        for _ in 1..len {
            v = (v << 8) | self.u8()? as u64;
        }
        Some(v)
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
}

fn u16_list(b: &[u8]) -> Vec<u16> {
    b.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

/// Parses a ClientHello handshake body (after the 4-byte handshake header;
/// for DTLS after the 12-byte one). DTLS adds the cookie after the session id.
pub fn parse_client_hello(body: &[u8], dtls: bool) -> Option<ClientHello> {
    let mut r = Reader::new(body);
    let mut ch = ClientHello {
        dtls,
        ..Default::default()
    };
    ch.legacy_version = r.u16()?;
    r.bytes(32)?; // random
    r.vec8()?; // session id
    if dtls {
        r.vec8()?; // cookie
    }
    ch.ciphers = u16_list(r.vec16()?);
    r.vec8()?; // compression methods
    if r.remaining() < 2 {
        return Some(ch); // no extensions (SSLv3-era clients)
    }
    let exts = r.vec16()?;
    let mut er = Reader::new(exts);
    while er.remaining() >= 4 {
        let t = er.u16()?;
        let data = er.vec16()?;
        ch.extensions.push(t);
        parse_extension(&mut ch, t, data);
    }
    Some(ch)
}

fn parse_extension(ch: &mut ClientHello, t: u16, data: &[u8]) {
    let mut r = Reader::new(data);
    match t {
        EXT_SNI => {
            let Some(list) = r.vec16() else { return };
            let mut lr = Reader::new(list);
            while lr.remaining() >= 3 {
                let (Some(kind), Some(name)) = (lr.u8(), lr.vec16()) else { break };
                if kind == 0 {
                    ch.sni = Some(printable(name));
                    break;
                }
            }
        }
        EXT_ALPN => {
            let Some(list) = r.vec16() else { return };
            let mut lr = Reader::new(list);
            while lr.remaining() >= 1 {
                let Some(p) = lr.vec8() else { break };
                ch.alpn.push(p.to_vec());
            }
        }
        EXT_SIG_ALGS => {
            if let Some(l) = r.vec16() {
                ch.sig_algs = u16_list(l);
            }
        }
        EXT_SUPPORTED_VERSIONS => {
            if let Some(l) = r.vec8() {
                ch.supported_versions = u16_list(l);
            }
        }
        EXT_GROUPS => {
            if let Some(l) = r.vec16() {
                ch.groups = u16_list(l);
            }
        }
        EXT_EC_POINT_FORMATS => {
            if let Some(l) = r.vec8() {
                ch.ec_point_formats = l.to_vec();
            }
        }
        EXT_QUIC_TP | EXT_QUIC_TP_DRAFT => {
            while r.remaining() > 0 {
                let (Some(id), Some(len)) = (r.varint(), r.varint()) else { break };
                let Some(v) = r.bytes(len as usize) else { break };
                if id == 0x3129 && !v.is_empty() && v.iter().all(|b| (0x20..0x7f).contains(b)) {
                    ch.quic_user_agent = Some(String::from_utf8_lossy(v).into_owned());
                }
            }
        }
        _ => {}
    }
}

/// Server names are ASCII; anything else is escaped so the log stays one
/// valid line.
fn printable(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (0x21..0x7f).contains(&c) {
                (c as char).to_string()
            } else {
                format!("\\x{:02x}", c)
            }
        })
        .collect()
}

/// Result of scanning the start of a client byte stream for a ClientHello
/// carried in TLS records.
pub enum StreamHello {
    /// The stream does not start with a TLS handshake record.
    NotTls,
    /// A ClientHello starts here but more bytes are needed.
    NeedMore,
    /// Complete ClientHello.
    Done(ClientHello),
    /// Starts like TLS but is not a parseable ClientHello.
    Malformed,
}

/// Collects the handshake bytes from consecutive TLS records (a ClientHello
/// may span several records) and parses the first handshake message.
pub fn client_hello_from_stream(stream: &[u8]) -> StreamHello {
    if !looks_like_tls_hello(stream) {
        return StreamHello::NotTls;
    }
    let mut hs: Vec<u8> = Vec::new();
    let mut pos = 0;
    loop {
        if hs.len() >= 4 {
            let need = 4 + (((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize);
            if hs.len() >= need {
                return match parse_client_hello(&hs[4..need], false) {
                    Some(ch) => StreamHello::Done(ch),
                    None => StreamHello::Malformed,
                };
            }
        }
        if stream.len() < pos + 5 {
            return StreamHello::NeedMore;
        }
        let rec = &stream[pos..];
        if rec[0] != 0x16 || rec[1] != 0x03 {
            return StreamHello::Malformed;
        }
        let rlen = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        if rlen == 0 || rlen > 18432 {
            return StreamHello::Malformed;
        }
        if rec.len() < 5 + rlen {
            // Use what is there: the ClientHello may end inside this record.
            hs.extend_from_slice(&rec[5..]);
            if hs.len() >= 4 {
                let need = 4 + (((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize);
                if hs.len() >= need {
                    continue;
                }
            }
            return StreamHello::NeedMore;
        }
        hs.extend_from_slice(&rec[5..5 + rlen]);
        pos += 5 + rlen;
    }
}

/// First bytes of a TLS record carrying a ClientHello: handshake (22),
/// version 3.x, handshake type 1.
pub fn looks_like_tls_hello(p: &[u8]) -> bool {
    p.len() >= 6 && p[0] == 0x16 && p[1] == 0x03 && p[2] <= 0x04 && p[5] == 0x01
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease() {
        assert!(is_grease(0x0a0a));
        assert!(is_grease(0xfafa));
        assert!(!is_grease(0x0a1a));
        assert!(!is_grease(0x1301));
    }

    #[test]
    fn varint() {
        let mut r = Reader::new(&[0x25, 0x7b, 0xbd, 0x9d, 0x7f, 0x3e, 0x7d]);
        assert_eq!(r.varint(), Some(37));
        assert_eq!(r.varint(), Some(15293));
        assert_eq!(r.varint(), Some(494878333));
    }
}
