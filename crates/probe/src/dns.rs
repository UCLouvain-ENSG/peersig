//! Plain DNS messages: questions, and the addresses answers bind to the name
//! that was asked (A, AAAA, and the ipv4hint/ipv6hint of HTTPS/SVCB
//! records, which Apple's resolver asks for every web name).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::tls::Reader;

pub struct Message {
    pub response: bool,
    pub rcode: u8,
    pub questions: Vec<(String, u16)>,
    /// (owner name, address)
    pub addrs: Vec<(String, IpAddr)>,
    /// (alias, target)
    pub cnames: Vec<(String, String)>,
}

pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        5 => "CNAME".into(),
        12 => "PTR".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        _ => t.to_string(),
    }
}

/// A possibly compressed name at `pos`; returns it and the position after it
/// in the original stream.
fn name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            if ptr >= pos {
                return None; // forward pointers loop
            }
            pos = ptr;
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let l = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(
            l.iter()
                .map(|&c| if (0x21..0x7f).contains(&c) { (c as char).to_ascii_lowercase().to_string() } else { format!("\\{:03}", c) })
                .collect(),
        );
        pos += 1 + len;
    }
    Some((labels.join("."), end.unwrap_or(pos)))
}

pub fn parse(msg: &[u8]) -> Option<Message> {
    let mut r = Reader::new(msg);
    let _id = r.u16()?;
    let flags = r.u16()?;
    if flags & 0x7800 != 0 {
        return None; // opcode other than QUERY
    }
    let (qd, an) = (r.u16()?, r.u16()?);
    if qd == 0 || qd > 4 {
        return None;
    }
    let mut pos = 12;
    let mut m = Message {
        response: flags & 0x8000 != 0,
        rcode: (flags & 0x0f) as u8,
        questions: Vec::new(),
        addrs: Vec::new(),
        cnames: Vec::new(),
    };
    for _ in 0..qd {
        let (n, p) = name(msg, pos)?;
        let t = u16::from_be_bytes(msg.get(p..p + 2)?.try_into().ok()?);
        m.questions.push((n, t));
        pos = p + 4;
    }
    if !m.response {
        return Some(m);
    }
    for _ in 0..an.min(256) {
        let Some((owner, p)) = name(msg, pos) else { break };
        let Some(h) = msg.get(p..p + 10) else { break };
        let t = u16::from_be_bytes([h[0], h[1]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let rd_at = p + 10;
        let Some(rd) = msg.get(rd_at..rd_at + rdlen) else { break };
        match t {
            1 if rdlen == 4 => m.addrs.push((owner, IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])))),
            28 if rdlen == 16 => m.addrs.push((owner, IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(rd).unwrap())))),
            5 => {
                if let Some((target, _)) = name(msg, rd_at) {
                    m.cnames.push((owner, target));
                }
            }
            64 | 65 => svc_hints(rd, &owner, &mut m.addrs),
            _ => {}
        }
        pos = rd_at + rdlen;
    }
    Some(m)
}

/// SvcParams of an HTTPS/SVCB record (RFC 9460): ipv4hint (4), ipv6hint (6).
fn svc_hints(rd: &[u8], owner: &str, out: &mut Vec<(String, IpAddr)>) {
    // priority, then an uncompressed target name
    let mut pos = 2;
    loop {
        let Some(&l) = rd.get(pos) else { return };
        pos += 1 + l as usize;
        if l == 0 {
            break;
        }
    }
    while pos + 4 <= rd.len() {
        let key = u16::from_be_bytes([rd[pos], rd[pos + 1]]);
        let len = u16::from_be_bytes([rd[pos + 2], rd[pos + 3]]) as usize;
        let Some(v) = rd.get(pos + 4..pos + 4 + len) else { return };
        match key {
            4 => out.extend(v.chunks_exact(4).map(|c| (owner.to_string(), IpAddr::V4(Ipv4Addr::new(c[0], c[1], c[2], c[3]))))),
            6 => out.extend(
                v.chunks_exact(16).map(|c| (owner.to_string(), IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(c).unwrap())))),
            ),
            _ => {}
        }
        pos += 4 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_with_cname() {
        // www.example.com CNAME e.cdn.net, e.cdn.net A 192.0.2.1
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(b"\x03www\x07example\x03com\x00\x00\x01\x00\x01");
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 11]);
        m.extend_from_slice(b"\x01e\x03cdn\x03net\x00");
        let target_at = (m.len() - 11) as u8;
        m.extend_from_slice(&[0xc0, target_at, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
        let r = parse(&m).unwrap();
        assert!(r.response);
        assert_eq!(r.questions, vec![("www.example.com".to_string(), 1)]);
        assert_eq!(r.cnames, vec![("www.example.com".to_string(), "e.cdn.net".to_string())]);
        assert_eq!(r.addrs, vec![("e.cdn.net".to_string(), "192.0.2.1".parse().unwrap())]);
    }
}
