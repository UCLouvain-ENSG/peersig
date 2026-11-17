//! Capture files without libpcap (Windows): pcap (microsecond and
//! nanosecond, either byte order) and pcapng (enhanced, simple and
//! obsolete packet blocks; several interfaces, each with its link type and
//! time resolution). Written files are pcapng, one interface per link type.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use anyhow::{bail, Context, Result};

use super::Packet;

enum Format {
    /// Big-endian, nanoseconds, link type.
    Pcap { be: bool, nanos: bool, dlt: i32 },
    Pcapng { be: bool, ifaces: Vec<(i32, f64)> },
}

pub struct Reader {
    r: BufReader<File>,
    f: Format,
    /// Link type of the first interface, for the `start` record.
    first_dlt: Option<i32>,
}

fn u16_of(b: &[u8], be: bool) -> u16 {
    let a = [b[0], b[1]];
    if be {
        u16::from_be_bytes(a)
    } else {
        u16::from_le_bytes(a)
    }
}

fn u32_of(b: &[u8], be: bool) -> u32 {
    let a = [b[0], b[1], b[2], b[3]];
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

/// pcapng `if_tsresol`: 10^-n, or 2^-n with the top bit set.
fn tsresol(v: u8) -> f64 {
    if v & 0x80 == 0 {
        10f64.powi(-(v as i32))
    } else {
        2f64.powi(-((v & 0x7f) as i32))
    }
}

impl Reader {
    pub fn open(path: &str) -> Result<Reader> {
        let mut r = BufReader::new(File::open(path).with_context(|| path.to_string())?);
        let mut m = [0u8; 4];
        r.read_exact(&mut m).with_context(|| format!("{}: empty file", path))?;
        let f = match m {
            [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4] | [0x4d, 0x3c, 0xb2, 0xa1] | [0xa1, 0xb2, 0x3c, 0x4d] => {
                let be = m[0] == 0xa1;
                let nanos = m == [0x4d, 0x3c, 0xb2, 0xa1] || m == [0xa1, 0xb2, 0x3c, 0x4d];
                let mut h = [0u8; 20];
                r.read_exact(&mut h)?;
                Format::Pcap { be, nanos, dlt: (u32_of(&h[16..], be) & 0xffff) as i32 }
            }
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                // The section header is read as the first block.
                r.seek(SeekFrom::Start(0))?;
                Format::Pcapng { be: false, ifaces: Vec::new() }
            }
            _ => bail!("{}: not a pcap or pcapng file", path),
        };
        let mut rd = Reader { r, f, first_dlt: None };
        match rd.f {
            Format::Pcap { dlt, .. } => rd.first_dlt = Some(dlt),
            // Up to the first interface, which gives the link type (no
            // packet can come before it).
            Format::Pcapng { .. } => while rd.first_dlt.is_none() && rd.ng_block()?.is_some() {},
        }
        Ok(rd)
    }

    pub fn dlt(&self) -> i32 {
        self.first_dlt.unwrap_or(1)
    }

    /// The next packet; None at the end of the file.
    pub fn next(&mut self) -> Result<Option<Packet>> {
        match self.f {
            Format::Pcap { be, nanos, dlt } => {
                let mut h = [0u8; 16];
                if !read_full(&mut self.r, &mut h)? {
                    return Ok(None);
                }
                let (sec, frac, len) = (u32_of(&h, be), u32_of(&h[4..], be), u32_of(&h[8..], be) as usize);
                if len > 1 << 24 {
                    bail!("corrupt pcap record ({} bytes)", len);
                }
                let mut data = vec![0u8; len];
                self.r.read_exact(&mut data)?;
                let ts = sec as f64 + frac as f64 / if nanos { 1e9 } else { 1e6 };
                Ok(Some((ts, dlt, data)))
            }
            Format::Pcapng { .. } => loop {
                match self.ng_block()? {
                    Some(Some(p)) => return Ok(Some(p)),
                    Some(None) => continue,
                    None => return Ok(None),
                }
            },
        }
    }

    /// One pcapng block: Some(Some(packet)), Some(None) for any other
    /// block, None at the end.
    fn ng_block(&mut self) -> Result<Option<Option<Packet>>> {
        let be = match &self.f {
            Format::Pcapng { be, .. } => *be,
            _ => unreachable!(),
        };
        let mut h = [0u8; 8];
        if !read_full(&mut self.r, &mut h)? {
            return Ok(None);
        }
        let (ty, len_raw) = (u32_of(&h, be), &h[4..]);
        // A section header (its type reads the same in both byte orders).
        if ty == 0x0a0d0d0a {
            // A new section: its byte-order magic says the endianness.
            let mut bom = [0u8; 4];
            self.r.read_exact(&mut bom)?;
            let be = match bom {
                [0x1a, 0x2b, 0x3c, 0x4d] => true,
                [0x4d, 0x3c, 0x2b, 0x1a] => false,
                _ => bail!("corrupt pcapng section header"),
            };
            let len = u32_of(len_raw, be) as usize;
            if !(28..=1 << 24).contains(&len) {
                bail!("corrupt pcapng section header");
            }
            let mut rest = vec![0u8; len - 12];
            self.r.read_exact(&mut rest)?;
            self.f = Format::Pcapng { be, ifaces: Vec::new() };
            return Ok(Some(None));
        }
        let len = u32_of(len_raw, be) as usize;
        if !(12..=1 << 26).contains(&len) || len % 4 != 0 {
            bail!("corrupt pcapng block ({} bytes)", len);
        }
        let mut body = vec![0u8; len - 12];
        self.r.read_exact(&mut body)?;
        let mut trailer = [0u8; 4];
        self.r.read_exact(&mut trailer)?;
        let Format::Pcapng { ifaces, .. } = &mut self.f else { unreachable!() };
        let iface = |ifaces: &Vec<(i32, f64)>, i: usize| ifaces.get(i).copied().unwrap_or((1, 1e-6));
        let ts_of = |hi: u32, lo: u32, res: f64| (((hi as u64) << 32) | lo as u64) as f64 * res;
        match ty {
            // Interface description: link type, then options (if_tsresol).
            1 if body.len() >= 8 => {
                let dlt = u16_of(&body, be) as i32;
                let mut res = 1e-6;
                let mut o = 8;
                while o + 4 <= body.len() {
                    let (code, olen) = (u16_of(&body[o..], be), u16_of(&body[o + 2..], be) as usize);
                    if code == 0 {
                        break;
                    }
                    if code == 9 && olen >= 1 && o + 4 < body.len() {
                        res = tsresol(body[o + 4]);
                    }
                    o += 4 + ((olen + 3) & !3);
                }
                ifaces.push((dlt, res));
                if self.first_dlt.is_none() {
                    self.first_dlt = Some(dlt);
                }
                Ok(Some(None))
            }
            // Enhanced packet.
            6 if body.len() >= 20 => {
                let (dlt, res) = iface(ifaces, u32_of(&body, be) as usize);
                let ts = ts_of(u32_of(&body[4..], be), u32_of(&body[8..], be), res);
                let cap = (u32_of(&body[12..], be) as usize).min(body.len() - 20);
                Ok(Some(Some((ts, dlt, body[20..20 + cap].to_vec()))))
            }
            // Simple packet: interface 0, no time.
            3 if body.len() >= 4 => {
                let (dlt, _) = iface(ifaces, 0);
                let orig = u32_of(&body, be) as usize;
                let cap = orig.min(body.len() - 4);
                Ok(Some(Some((0.0, dlt, body[4..4 + cap].to_vec()))))
            }
            // Obsolete packet block.
            2 if body.len() >= 20 => {
                let (dlt, res) = iface(ifaces, u16_of(&body, be) as usize);
                let ts = ts_of(u32_of(&body[4..], be), u32_of(&body[8..], be), res);
                let cap = (u32_of(&body[12..], be) as usize).min(body.len() - 20);
                Ok(Some(Some((ts, dlt, body[20..20 + cap].to_vec()))))
            }
            _ => Ok(Some(None)),
        }
    }
}

/// Fills `buf`; false at a clean end of file.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<bool> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..])? {
            0 if got == 0 => return Ok(false),
            0 => bail!("truncated capture file"),
            n => got += n,
        }
    }
    Ok(true)
}

/// A pcapng file: an interface per link type, microsecond times.
pub struct Writer {
    w: BufWriter<File>,
    ifaces: Vec<i32>,
    snaplen: u32,
}

fn block(ty: u32, body: &[u8]) -> Vec<u8> {
    let pad = (4 - body.len() % 4) % 4;
    let len = (12 + body.len() + pad) as u32;
    let mut b = Vec::with_capacity(len as usize);
    b.extend_from_slice(&ty.to_le_bytes());
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(body);
    b.extend(std::iter::repeat_n(0u8, pad));
    b.extend_from_slice(&len.to_le_bytes());
    b
}

impl Writer {
    pub fn create(path: &str, snaplen: u32) -> Result<Writer> {
        let mut w = BufWriter::new(File::create(path).with_context(|| path.to_string())?);
        let mut shb = Vec::new();
        shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
        shb.extend_from_slice(&1u16.to_le_bytes());
        shb.extend_from_slice(&0u16.to_le_bytes());
        shb.extend_from_slice(&(-1i64).to_le_bytes());
        w.write_all(&block(0x0a0d_0d0a, &shb))?;
        Ok(Writer { w, ifaces: Vec::new(), snaplen })
    }

    pub fn write(&mut self, ts: f64, dlt: i32, data: &[u8]) -> Result<()> {
        let id = match self.ifaces.iter().position(|d| *d == dlt) {
            Some(i) => i,
            None => {
                let mut idb = Vec::new();
                idb.extend_from_slice(&(dlt as u16).to_le_bytes());
                idb.extend_from_slice(&0u16.to_le_bytes());
                idb.extend_from_slice(&self.snaplen.to_le_bytes());
                self.w.write_all(&block(1, &idb))?;
                self.ifaces.push(dlt);
                self.ifaces.len() - 1
            }
        };
        let us = (ts.max(0.0) * 1e6).round() as u64;
        let mut epb = Vec::with_capacity(20 + data.len());
        epb.extend_from_slice(&(id as u32).to_le_bytes());
        epb.extend_from_slice(&((us >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(us as u32).to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(data);
        self.w.write_all(&block(6, &epb))?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.w.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let path = std::env::temp_dir().join(format!("peersig-file-{}.pcapng", std::process::id()));
        let p = path.to_str().unwrap();
        let mut w = Writer::create(p, 65535).unwrap();
        w.write(1_700_000_000.25, 1, b"ethernet frame").unwrap();
        w.write(1_700_000_001.5, 101, b"raw ip").unwrap();
        w.write(1_700_000_002.0, 1, b"x").unwrap();
        w.flush().unwrap();
        drop(w);
        let mut r = Reader::open(p).unwrap();
        assert_eq!(r.dlt(), 1);
        let mut got = Vec::new();
        while let Some(pk) = r.next().unwrap() {
            got.push(pk);
        }
        let _ = std::fs::remove_file(&path);
        assert_eq!(got.len(), 3);
        assert_eq!((got[1].1, got[1].2.as_slice()), (101, &b"raw ip"[..]));
        assert!((got[0].0 - 1_700_000_000.25).abs() < 1e-6);
        assert_eq!(got[2].2, b"x");
    }

    /// The repository's captures, pcap and pcapng, as libpcap reads them.
    #[test]
    fn test_captures() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
        for f in ["tcp_split.pcap", "dtls.pcap", "pktap.pcap", "traces/quic_kyber.pcapng", "traces/quic_retry.pcapng"] {
            let p = dir.join(f);
            if !p.exists() {
                continue;
            }
            let mut r = Reader::open(p.to_str().unwrap()).unwrap();
            let mut count = 0;
            while let Some((ts, _, data)) = r.next().unwrap() {
                assert!(!data.is_empty() && ts > 1e9, "{}", f);
                count += 1;
            }
            assert!(count > 0, "{}", f);
        }
    }
}
