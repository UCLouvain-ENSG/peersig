## Install

- **macOS** (12 or newer): `PeerSig_<version>_aarch64.dmg` for Apple Silicon, `_x64.dmg` for Intel. Drag PeerSig to Applications and open it. The builds are not signed yet: the first time, open *System Settings → Privacy & Security* and choose *Open Anyway*. PeerSig then installs its capture service (it asks for an administrator password).
- **Linux** (x86_64): install the `.deb` (it gives the probe its capture rights). The AppImage runs the app but cannot give the probe those rights.
- **Collection server, relay, probe** (Linux x86_64): `peersig-<version>-linux-x86_64.tar.gz`. See `docs/deploy.md`.

Check downloads against `SHA256SUMS`.

## What PeerSig sends

Once a week, after a day for you to review it: which applications (name, version, kind) sent which TLS fingerprint (JA4), as anonymous ballots. Never addresses, sites visited, times, paths or names. See `docs/privacy.md`.
