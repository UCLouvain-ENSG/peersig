## Install

First get an enrollment code at https://peersig.org (in one click from the UCLouvain network, by e-mail, or with a GitHub account). The app fills in the server and relay addresses; you enter the code.

- **macOS** (12 or newer): `PeerSig_<version>_aarch64.dmg` for Apple Silicon, `_x64.dmg` for Intel. Drag PeerSig to Applications and open it. The builds are not signed yet: the first time, open *System Settings → Privacy & Security* and choose *Open Anyway*. PeerSig then installs its capture service (it asks for an administrator password).
- **Linux** (x86_64): install the `.deb` (Debian, Ubuntu) or the `.rpm` (Fedora, RHEL, openSUSE): the package gives the probe its capture rights. The AppImage runs the app but cannot give the probe those rights.
- **Windows** (10 and 11, x64; preview): install the `.msi`. PeerSig installs its capture service (Windows asks for an administrator's consent); it uses the packet capture built into Windows, so nothing else is needed. The builds are not signed yet: SmartScreen asks before running them.
- **Android** (10 or newer; preview): install `PeerSig_<version>_android.apk`; it is not on Google Play, so Android first asks whether your browser may install apps. PeerSig captures through a VPN of its own that stays on the phone: Android asks once whether it may set it up. Android runs one VPN at a time. See `docs/android.md`.
- **Linux server** (x86_64, systemd; no desktop needed): install `peersig-headless_<version>_amd64.deb` or `peersig-headless-<version>-1.x86_64.rpm`, then run `sudo peersig configure` with your code. Each week's list is reviewed with `sudo peersig items`. See `docs/headless.md`.
- **Collection server, relay, probe, `peersig`** (Linux x86_64): `peersig-<version>-linux-x86_64.tar.gz`. See `docs/deploy.md`.

To update, install the new version over the old one (on Android, open the new `.apk`). On macOS and Windows, PeerSig then offers to update its capture service (*Update capture service*), which asks for an administrator's password or consent again: until then, the service keeps capturing with the old version.

Check downloads against `SHA256SUMS`.

## What PeerSig sends

Once a week, after a day for you to review it: which applications (name, bundle id, version, signing team or publisher, kind, engine) sent which TLS fingerprint (JA4) on which system and major version, and, if you allow it, the server names (SNI) non-browser applications connected to, as anonymous ballots. Builds of one version line go as one (`2.1.*`). Never addresses, sites visited, times, paths or names. See `docs/privacy.md`.

Dedicated observers (machines run for the study, on any system, with an `OBS-` code from the study team) report daily instead, not anonymously, and are published without threshold: see `docs/observers.md`.
