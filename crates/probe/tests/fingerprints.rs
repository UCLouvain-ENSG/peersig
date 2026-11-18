//! End-to-end: `peersig-probe read` on captures, against values from tshark 4.6
//! (tls.handshake.ja4 / dtls.handshake.ja4). `tests/compare_tshark.py`
//! redoes the comparison flow by flow on any capture.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn records(capture: &PathBuf) -> Vec<Value> {
    let out = Command::new(env!("CARGO_BIN_EXE_peersig-probe")).arg("read").arg(capture).output().expect("run peersig-probe");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

/// source port -> JA4 of the ClientHellos in a capture.
fn hellos(capture: &PathBuf) -> BTreeMap<u16, BTreeSet<String>> {
    let mut m: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for r in records(capture).iter().filter(|r| r["type"] == "hello") {
        let port = r["src"].as_str().unwrap().rsplit(':').next().unwrap().parse().unwrap();
        m.entry(port).or_default().insert(r["ja4"].as_str().unwrap().to_string());
    }
    m
}

fn expect(capture: PathBuf, want: &[(u16, &str)]) {
    if !capture.exists() {
        eprintln!("skipping {}: not found", capture.display());
        return;
    }
    let got = hellos(&capture);
    let mut exp: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for (p, j) in want {
        exp.entry(*p).or_default().insert(j.to_string());
    }
    assert_eq!(got, exp, "{}", capture.display());
}

#[test]
fn tcp_out_of_order_and_ipv6() {
    // OpenSSL 4.1 with ML-KEM in 3 segments (2nd first, 1st retransmitted),
    // Python over IPv6, macOS curl without SNI.
    expect(
        crate_dir().join("tests/data/tcp_split.pcap"),
        &[
            (50001, "t13d3012h2_1d37bd780c83_e44827223d20"),
            (50002, "t13d171100_ab0a1bf427ad_8e6e362c5eac"),
            (50003, "t13i4906h2_0d8feac7bc37_7395dae3b2f3"),
        ],
    );
}

/// A little-endian Ethernet pcap rewritten as 802.11 data frames (link type
/// 105), as Windows logs a Wi-Fi adapter's packets: plain and QoS data
/// headers in turn, an LLC/SNAP header in front of the EtherType.
fn as_dot11(eth: &PathBuf) -> PathBuf {
    let b = std::fs::read(eth).unwrap();
    let le32 = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    assert_eq!((&b[..4], le32(20)), (&[0xd4, 0xc3, 0xb2, 0xa1][..], 1), "little-endian Ethernet pcap");
    let mut out = b[..20].to_vec();
    out.extend_from_slice(&105u32.to_le_bytes());
    let (mut o, mut qos) = (24, false);
    while o + 16 <= b.len() {
        let (cap, orig) = (le32(o + 8), le32(o + 12));
        let f = &b[o + 16..o + 16 + cap];
        // To DS: addr1 the access point, addr2 the source, addr3 the destination.
        let mut d = vec![if qos { 0x88 } else { 0x08 }, 0x01, 0, 0, 0x02, 0, 0, 0, 0, 0xaa];
        d.extend_from_slice(&f[6..12]);
        d.extend_from_slice(&f[..6]);
        d.extend_from_slice(&[0, 0]);
        if qos {
            d.extend_from_slice(&[0, 0]);
        }
        d.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0]);
        d.extend_from_slice(&f[12..]);
        out.extend_from_slice(&b[o..o + 8]);
        out.extend_from_slice(&(d.len() as u32).to_le_bytes());
        out.extend_from_slice(&((orig + d.len() - cap) as u32).to_le_bytes());
        out.extend_from_slice(&d);
        o += 16 + cap;
        qos = !qos;
    }
    let p = std::env::temp_dir().join(format!("peersig-dot11-{}.pcap", std::process::id()));
    std::fs::write(&p, out).unwrap();
    p
}

#[test]
fn wifi_frames() {
    // Windows logs a Wi-Fi adapter's packets as 802.11 frames: the same
    // ClientHellos must come out as over Ethernet.
    let eth = crate_dir().join("tests/data/tcp_split.pcap");
    let dot11 = as_dot11(&eth);
    let (got, want) = (hellos(&dot11), hellos(&eth));
    let _ = std::fs::remove_file(&dot11);
    assert_eq!(want.len(), 3);
    assert_eq!(got, want);
}

#[test]
fn dtls_fragments() {
    // DTLS 1.2 in 2 fragments sent twice; DTLS 1.3 in 8 fragments out of order.
    expect(
        crate_dir().join("tests/data/dtls.pcap"),
        &[(50020, "dd2d270800_a2460661a67a_36cef8aed422"), (50021, "dd3d030900_55b375c5d22e_6bcdba30a371")],
    );
}

#[test]
fn quic_traces() {
    let t = crate_dir().join("tests/data/traces");
    expect(t.join("quic_kyber.pcapng"), &[(46069, "q13d0311h3_55b375c5d22e_5a1f323ef56d")]);
    expect(t.join("quic_xargs.pcap"), &[(60220, "q13d0308p0_55b375c5d22e_f0736a66fa6b")]);
}

#[test]
fn tls_trace_counts() {
    let t = crate_dir().join("tests/data/traces");
    for (f, n) in [("tls_ciphers.pcap", 70), ("small_flows.pcap", 53)] {
        let p = t.join(f);
        if p.exists() {
            let c = records(&p).iter().filter(|r| r["type"] == "hello").count();
            assert_eq!(c, n, "{}", f);
        }
    }
}

#[test]
fn pktap_names_and_delegation() {
    let recs = records(&crate_dir().join("tests/data/pktap.pcap"));
    let hello: Vec<&Value> = recs.iter().filter(|r| r["type"] == "hello").collect();
    // The inbound ClientHello is skipped; the delegated one goes to softwareupdated.
    assert_eq!(hello.len(), 1);
    assert_eq!(hello[0]["proc"], "nsurlsessiond");
    assert_eq!(hello[0]["eproc"], "softwareupdated");
    assert_eq!(hello[0]["app"]["name"], "softwareupdated");
    assert_eq!(hello[0]["app"]["via"], "delegated");
    let domains: BTreeSet<(String, String, String)> = recs
        .iter()
        .filter(|r| r["type"] == "domain")
        .map(|r| (r["proc"].as_str().unwrap().into(), r["domain"].as_str().unwrap().into(), r["via"].to_string()))
        .collect();
    let want: BTreeSet<(String, String, String)> = [
        ("curl", "example.org", r#"["dns","http"]"#),
        ("dig", "dig.example.net", r#"["dns-query"]"#),
    ]
    .iter()
    .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
    .collect();
    // mDNSResponder's own query is not credited to it.
    assert_eq!(domains, want);
}
