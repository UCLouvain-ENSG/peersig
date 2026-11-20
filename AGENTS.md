# Working on PeerSig

Read README.md and docs/privacy.md first. The privacy properties are the
product: a change that weakens one is a bug even if every test passes.

## Invariants

- Only `peersig-proto::Item` crosses the network, one item per ballot. Adding
  a field to `Item` or `AppRef` changes what participants disclose: update
  docs/privacy.md, docs/protocol.md, the app's Privacy tab and its join
  screen in the same change (the Android app shows the same window,
  `crates/app/ui`: check its `android()` wording too). `deny_unknown_fields`
  stays.
- The probe never uses the network. The app is the only part that sends.
  On Android the capture is the app's own VPN (docs/android.md): it
  forwards the phone's connections unchanged, to where they were going,
  and never sends, redirects or keeps traffic beyond the probe's local
  logs; the app stays outside its VPN (`addDisallowedApplication`). Only
  DNS to the VPN's own server goes elsewhere: to the network's DNS
  servers, never another resolver.
- The server never logs or stores request addresses or arrival times, and
  stores counters, not ballots. Keep tables `WITHOUT ROWID` and the journal
  out of WAL mode.
- Every participant asks for `tokens_per_epoch` tokens, whatever it sends.
- The app and the headless `peersig` (crates/headless, docs/headless.md)
  build and send a participant's ballots with the same code
  (`peersig_proto::participant`): keep it shared. Both review a week
  before sending it and send nothing while not running. The desktop and
  Android apps share the rest of the participant's side
  (`crates/client`: report cycle, worker, window commands, tray text);
  each brings only a `Host` (its capture, its notifications).
- Dedicated observers (`OBS-` codes, docs/observers.md) are published
  without threshold, so they stay apart from participants: no tokens for
  observer codes, no observer reports from participants' codes, and
  observer counts (`observed`) never mix with `counts`. Observer codes
  are made only on the server, never by the web page.
- Web enrollment (`crates/server/src/enroll.rs`) keeps a keyed hash of the
  e-mail address or GitHub id and a count, never the identity itself, and
  nothing that links it to the code. Its pages answer alike whether or not
  an address enrolled before. Network enrollment looks at the client's
  address for that request only and keeps nothing about it. The
  per-address limit on codes by e-mail or GitHub keeps, in memory only, a
  count under a hash of the address's /32 or /64 keyed with a random key
  replaced every hour; nothing about addresses is written or logged, so
  there are no IP bans. Bans (the admin page) hold the same keyed hash as
  `identities`, or a mail domain.
- The admin page (`crates/server/src/admin.rs`) shows what the CLI shows
  (code labels, epochs, counts), to the GitHub logins in `--admin-github`.
  It must not show or keep more: no ballots, no addresses, no identities.
- The app fetches the config and the gateway key anonymously,
  and checks the token key and the gateway key as described in
  docs/privacy.md. Do not shortcut these checks.
- The JA4 code (`crates/probe/src/fingerprint.rs`) follows FoxIO's spec and
  matches tshark 4.6. PeerSig stands alone: do not name
  the lab's other projects anywhere (site, app, docs, help, comments);
  FoxIO's spec and tshark are the references.

## Building and testing

- `cargo test --locked` covers probe, proto, server, relay and headless. The
  server and relay tests run full enroll → issue → OHTTP ballot → release
  cycles; `crates/server/tests/observers.rs` the observers' daily reports.
- The app (`-p peersig-app`) needs the probe binary in `crates/app/binaries/`
  (see the README there) and Tauri's system libraries; its test runs a
  weekly report against an in-process server.
- `python3 crates/probe/tests/compare_tshark.py crates/probe/tests/data/traces/*`
  compares fingerprints with tshark after any change to them.
- `Cargo.lock` pins `derive_more` 2.0.1 for `blind-rsa-signatures` 0.15; do
  not `cargo update` it away. Its 0.18 does not build with `rsa` 0.10.0.
- Live capture needs root on macOS; it cannot run in CI.
- Windows: no libpcap. The probe captures through ETW (the system's NDIS
  packet capture, `src/capture/etw.rs`) and reads capture files itself
  (`src/capture/file.rs`), so the release needs nothing installed beside
  it. Its `build.rs` links the Visual C++ runtime statically for the same
  reason (no `VCRUNTIME140.dll`, which Windows does not have); a test
  checks the probe's imports. Keep `pcap` out of the Windows build: pcap
  2.5 depends on windows-sys 0.36, whose import library maps
  `WaitOnAddress` to vertdll.dll (the enclave DLL) and would crash std's
  first futex wait. Live capture needs an administrator; it cannot run in
  CI.
- `data/apps.toml`'s browser list decides which apps' server names are
  never collected: a browser missing there (by bundle id or, on Windows
  and Linux, executable name) has its names treated like any app's. On
  Android it lists package names; an app that opens any web address is a
  browser too (`crates/android/src/apps.rs`).
- The probe is a library as well (`crates/probe/src/lib.rs`): the Android
  app feeds its pipeline the packets of its VPN and writes the same logs.
  Keep pcap out of the Android build.
- Android (docs/android.md): `cargo test -p peersig-android` runs the
  native side's tests on the computer; the APK needs the SDK, NDK
  27.3.13750724, JDK 17 and cargo-ndk (`cd android && ./gradlew
  assembleDebug`). The native side calls Kotlin methods by name
  (`Host`, `Native`): rename them on both sides, and do not turn on
  shrinking. `rustls-platform-verifier` (TLS against Android's trust
  store) needs its Android half: its version in Cargo.lock is the Maven
  artifact's.

## Branches

Work on `main` only, on every machine: commit there and push it, without
feature or release branches (release tags are cut from `main`). Pull
before starting, since the Mac and the Windows PC both commit. Commits use
tom.barbette@uclouvain.be.

## Logo

`assets/logo/make_logo.py` draws it; `assets/logo/render.sh` regenerates the
app, window and menu-bar icons. Do not edit the PNGs by hand.
