# Working on PeerSig

Read README.md and docs/privacy.md first. The privacy properties are the
product: a change that weakens one is a bug even if every test passes.

## Invariants

- Only `peersig-proto::Item` crosses the network, one item per ballot. Adding
  a field to `Item` or `AppRef` changes what participants disclose: update
  docs/privacy.md, docs/protocol.md, the app's Privacy tab and its join
  screen in the same change. `deny_unknown_fields` stays.
- The probe never uses the network. The app is the only part that sends.
- The server never logs or stores request addresses or arrival times, and
  stores counters, not ballots. Keep tables `WITHOUT ROWID` and the journal
  out of WAL mode.
- Every participant asks for `tokens_per_epoch` tokens, whatever it sends.
- The app fetches the config, the catalogue and the gateway key anonymously,
  and checks the token key and the gateway key as described in
  docs/privacy.md. Do not shortcut these checks.
- The JA4 code (`crates/probe/src/fingerprint.rs`) follows FoxIO's spec and
  matches tshark 4.6. The Iris classifier (`examples/traffic_classifier/src/ja4.rs`
  in the lab's Iris fork) computes the same value: change both together.
  `ja4_legacy` reproduces what Iris stored before 2026-11-16.

## Building and testing

- `cargo test --locked` covers probe, proto, server and relay. The server and
  relay tests run full enroll → issue → OHTTP ballot → release cycles.
- The app (`-p peersig-app`) needs the probe binary in `crates/app/binaries/`
  (see the README there) and Tauri's system libraries; its test runs a
  weekly report against an in-process server.
- `python3 crates/probe/tests/compare_tshark.py crates/probe/tests/data/traces/*`
  compares fingerprints with tshark after any change to them.
- `Cargo.lock` pins `derive_more` 2.0.1 for `blind-rsa-signatures` 0.15; do
  not `cargo update` it away. Its 0.18 does not build with `rsa` 0.10.0.
- Live capture needs root on macOS; it cannot run in CI.

## Logo

`assets/logo/make_logo.py` draws it; `assets/logo/render.sh` regenerates the
app, window and menu-bar icons. Do not edit the PNGs by hand.
