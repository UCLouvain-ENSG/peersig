<p align="center"><img src="assets/logo/peersig.svg" width="128" alt="PeerSig logo: a fingerprint drawn with dots"></p>

# PeerSig

PeerSig tells which applications send which TLS fingerprints. Volunteers run
a small app that watches the start of every encrypted connection their
computer makes (the TLS or QUIC ClientHello), computes its
[JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
fingerprint, and finds the application behind it: name, version, browser
engine, TLS library. Once a week, the app contributes these
*(fingerprint, application)* pairs to a study, as anonymous ballots.

The result is a ground-truth table for traffic classification: a JA4 seen on
a network can be labelled "Microsoft Teams 26289 (Chromium 156)" or "macOS
softwareupdated" because volunteers' machines said so.

The name stands for *peered JA4 signatures*. The logo is a fingerprint made
of dots: each dot is one participant's anonymous ballot.

## Privacy

What leaves a participant's computer, and only after they could review it:

- per week, each *(application name and version, kind, engine, OS family,
  transport, JA4)* seen;
- if they opt in, the domain names that **non-browser** applications
  contacted (Teams contacting `teams.microsoft.com`). Browsing history is
  never collected.

Never: IP addresses, times, how often, file paths, command lines, user or
host names. On top of that, the system has several layers of protection:

| Layer | What it does |
| --- | --- |
| Review | Each week's list waits 24 h in the app; the participant can untick anything. Nothing is sent while the app is not running. |
| Anonymous ballots | Every item is a separate ballot with a blind-signed token ([RFC 9474](https://www.rfc-editor.org/rfc/rfc9474)), as in anonymous e-voting: the server knows a ballot comes from an enrolled participant, not which one, nor which ballots come from the same person. |
| Oblivious HTTP | Ballots go through a relay run by another party ([RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)): the relay sees addresses, not content; the server sees content, not addresses. |
| Local differential privacy | Items the server already knows are sent with randomized response (ε = ln 9 per item and week by default): some real items are left out, some decoys are added. |
| Counts only | The server stores one counter per item and week. No ballots, no arrival times. |
| Thresholds and central DP | An item is published only once *k* participants reported it (3, or 5 for domains), with Laplace noise on the published counts. |

[docs/privacy.md](docs/privacy.md) explains what each party learns and the
limits. [docs/protocol.md](docs/protocol.md) is the wire protocol.

## For participants

Download the app from the [releases](https://github.com/UCLouvain-ENSG/peersig/releases)
page (macOS `.dmg`, Linux `.deb`), open it, and enter the server address,
relay and enrollment code given by the study. On macOS, the app installs its
capture service once; the system asks for an administrator password.

The PeerSig icon in the menu bar shows what is happening: a fingerprint while
it captures, a faded one when paused or not running, an arrow while a report
is being sent. The window shows what was seen this week, what will be sent,
and what was sent before.

The release builds are not signed by Apple yet: the first time, macOS refuses
to open the app. Open *System Settings → Privacy & Security* and choose
*Open Anyway*.

## For researchers: running a collection

```sh
cargo build --release -p peersig-server -p peersig-relay

# Collection server (behind TLS, with access logs off):
peersig-server --db peersig.db serve --listen 127.0.0.1:8080
peersig-server --db peersig.db codes add --count 20      # one code per participant
peersig-server --db peersig.db stats
peersig-server --db peersig.db export --format classifier > ja4_peersig.json

# Relay, on a machine you do not control (another lab, the DPO's office):
peersig-relay --listen 127.0.0.1:8081 --gateway https://peersig.example.org
```

The `classifier` export is the `ja4_fingerprints.json` format of the Iris
traffic classifier. [docs/deploy.md](docs/deploy.md) covers TLS, Docker,
enrollment, parameters and releases.

## Building from source

Rust (stable), and libpcap (`libpcap-dev` on Debian/Ubuntu). The app also
needs [Tauri's prerequisites](https://v2.tauri.app/start/prerequisites/).

```sh
cargo test                       # probe, protocol, server, relay
cargo build --release -p peersig-probe
cp target/release/peersig-probe crates/app/binaries/peersig-probe-$(rustc -vV | sed -n 's/host: //p')
cargo test -p peersig-app
(cd crates/app && npx @tauri-apps/cli@2 build)                    # .app/.dmg or .deb/.AppImage
```

Use `--locked`: `Cargo.lock` pins `derive_more` to 2.0.1, the last release
`blind-rsa-signatures` 0.15 builds with.

| Crate | What |
| --- | --- |
| [`crates/probe`](crates/probe) | Capture daemon: JA4 of every ClientHello (TCP, QUIC, DTLS), and the process and application behind it. Writes local logs; never uses the network. See its [README](crates/probe/README.md). |
| [`crates/app`](crates/app) | Tray app (Tauri): shows the logs, lets the participant remove items, sends the weekly ballots. |
| [`crates/proto`](crates/proto) | What a ballot may contain, tokens, OHTTP, randomized response, wire format, client. |
| [`crates/server`](crates/server) | Collection server: token issuance, OHTTP gateway, counters, release. |
| [`crates/relay`](crates/relay) | OHTTP relay. |
| [`assets/logo`](assets/logo) | The logo, generated by `make_logo.py`; `render.sh` makes the app icons. |

## Status

macOS is supported: per-packet process attribution (PKTAP), bundle versions,
Chromium, Electron, Gecko and WebKit engines, XPC services credited to their
app, background downloads credited to the app they work for. Linux captures
and finds processes through procfs, but has not been tested in the field.
Windows computes fingerprints only.

## License

Apache-2.0 or MIT, at your option.
