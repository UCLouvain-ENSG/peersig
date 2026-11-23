# PeerSig on Android

The Android app does what the desktop app does (it shows what was seen,
lets the participant remove items, and sends each week's report as
anonymous ballots) and captures on the phone itself. Its items are the
desktop's, with the system `android <major>` (`android 15`).

Android 10 or later (API 29), on a phone or an emulator: arm64-v8a and
x86_64.

## For participants

Install the `.apk` (from <https://peersig.org/participate> or the
releases; it is not on Google Play, so Android first asks whether the
browser may install apps), open PeerSig, enter the study's server, relay
and enrollment code, as on a computer. Then **Allow and
start** on the Overview: Android asks once whether PeerSig may set up a
VPN. A key icon shows in the status bar while it captures, and a
notification says what PeerSig is doing (capturing, paused, sending a
report), with *Pause*, *Send now* and *Quit*. *Settings → Start PeerSig
when the phone starts* brings it back after a restart; nothing is sent
while it is not running, as on a computer.

Android lets one VPN run at a time. While PeerSig captures, another VPN
app (including the university's) cannot run; starting one turns
PeerSig's off, and the window says so. To enroll in one click from the
UCLouvain network, use its Wi-Fi rather than its VPN.

## How it captures

Android shows an app other apps' traffic only through a VPN
(`VpnService`). PeerSig's VPN goes nowhere:

- Every packet the phone's apps send into it is read by the native side
  (`crates/android/src/forward.rs`). A userspace TCP/IP stack
  ([ipstack](https://crates.io/crates/ipstack) 1.0.1, with fixes to its
  TCP in `vendor/ipstack`, see its `PATCHES.md`) ends each TCP connection
  and UDP flow there, opens the same one from PeerSig to where it was
  going, and copies the bytes both ways, unchanged. Before 0.1.16 an app's
  last bytes before closing could be lost, a request sent after a
  half-close went unanswered, and uploads were up to 6 times slower.
  PeerSig is left out of
  its own VPN (`addDisallowedApplication`), so these connections, like its
  ballots, use the phone's network directly. No VPN server is involved.
- An app's TCP connection opens only once PeerSig's to the destination
  has: its SYN waits until then, and when the destination cannot be
  reached the app gets a reset, as from the destination itself. ipstack
  alone answers every SYN at once, so before 0.1.13 every connection
  seemed to open: apps racing IPv6 against IPv4 (Happy Eyeballs) kept a
  dead IPv6 path instead of falling back, and sent their ClientHello into
  a connection that ended 20 s later. While the phone changes networks
  (Wi-Fi to mobile data, one access point to another), a connection that
  fails at once (no route yet, no IPv6 address yet on the new network) is
  tried again for up to 15 s, the app's SYN held meanwhile. Before 0.1.18
  the app got a reset at once: Play services counted each one as a
  failure of the VPN's network, and on a commute stopped trying through
  it for hours, so notifications came only once the VPN was off.
- A copy of each packet the apps send (except bare TCP ACKs) goes to the
  probe's own pipeline (`crates/probe`, as a library), which finds the
  ClientHellos (TCP, QUIC, DTLS), computes their JA4 with the same code as
  on a computer, and writes the same daily logs
  (`peersig-<date>.jsonl`, 14 days) and `status.json`, in the app's
  private storage (`files/logs`).
- Android does not let an app look at other apps' processes. For each
  ClientHello, the system names the app that owns the connection, by uid
  (`ConnectivityManager.getConnectionOwnerUid`, which only the active VPN
  may call), and the package manager names that uid
  (`crates/android/src/apps.rs`):
  - `name`: the app's label in English, whatever the phone's language, so
    that the same app gives the same item on every phone; its package name
    when it has none. A uid that several packages share is named after
    Google Play services when it is one of them, after the shared uid
    otherwise (`android.uid.phone`). The system's own uids (below 10000)
    are named after the package `android` (Android System) or their role
    (`dns`, `root`, `media`).
  - `id`: the package name; `version`: its `versionName`.
  - `kind`: `browser` when `data/apps.toml` lists the package, or when the
    app opens any web address (Android's own test for a browser);
    `system` for the system's uids and for apps signed with the platform's
    key; `cli` for the shell (adb); `app` otherwise.
  - No `engine` and no `team_id`: another app's libraries and signature
    are not inspected.
  - Processes of the probe's logs are apps: `uid:10123`, named after the
    package.
- The VPN's DNS server (10.88.0.2, `fd50:ee5:91c::2`) stands for the
  network's own: queries are forwarded to the DNS servers of the Wi-Fi or
  mobile network, updated when it changes. No other resolver is used.
  Private DNS keeps working (its ClientHellos are credited to `dns`).
  The app follows the best network that is not a VPN
  (`registerBestMatchingNetworkCallback`; a network request on Android 10
  and 11), not its default network: Android gives a VPN's own app its VPN
  as default network. Before 0.1.19 the servers therefore stayed those of
  the network the VPN started on, and after a move every lookup failed
  (eduroam's servers refuse queries from elsewhere, a home router's cannot
  be reached from outside) until the capture was paused and resumed.
- IPv6 goes through the VPN only on networks that have it (a default
  route and a global address, not only a site-local or unique local one);
  the VPN starts again when that changes for 10 s (a new network often
  gets its IPv6 address a few seconds after its IPv4 one). Multicast and
  broadcast stay outside.
- ICMP (ping) is not forwarded.

## Privacy

Everything in [privacy.md](privacy.md) holds; on a phone:

- **The VPN stays on the phone.** It forwards every connection unchanged
  and keeps the start of encrypted connections only, for the local logs,
  as the desktop probe does with the computer's packets. It sends nothing
  of PeerSig's: only the app's own client does, outside the VPN, as on a
  computer. The window's Privacy tab and join screen say so.
- **Local logs** are in the app's private storage, which other apps cannot
  read (as root can on a computer, anyone with root on the phone can).
  *Export local logs* saves them, in a zip, where the participant chooses.
  Leaving the study can delete them; uninstalling the app does.
- **Seeing every app.** The app asks for `QUERY_ALL_PACKAGES`: without it,
  Android hides most apps from PeerSig and it could not name them. It reads
  their labels, versions, and whether they are browsers or signed by the
  platform; nothing of this leaves the phone except in the items, as
  shown in review.
- **Browsers.** An app is a browser when `apps.toml` lists it or when it
  opens any web address. Apps that show web pages inside themselves
  (in-app browsers) are not: the names they contact are collected like any
  app's, when sharing is on. The participant can untick them in review.

## Limits

- Little tested so far: on one phone, and on an Android 15 emulator
  (arm64), where PeerSig captured Chrome's TCP and the Google app's QUIC handshakes, Play
  services' and the DNS resolver's, credited to them, and sent a report
  through a relay to a test server.
- A VPN costs battery: every packet crosses user space twice.
- Android runs one VPN at a time (see above), and apps can tell that a VPN
  is on; a few (some banking apps) refuse to work then. Pausing the
  capture turns the VPN off.
- Work profiles have their own VPN: their apps are not captured.
- Android may stop the app; the notification and *Start PeerSig when the
  phone starts* keep it running. *Always-on VPN* (Settings → Network → VPN)
  also works; do not turn on *Block connections without VPN*, which cuts
  the phone off while PeerSig is paused.

## Building

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
# Android SDK (platform 35, build-tools), NDK 27.3.13750724, JDK 17:
sdkmanager "platforms;android-35" "build-tools;35.0.0" "ndk;27.3.13750724"
cd android
echo "sdk.dir=$ANDROID_HOME" > local.properties
./gradlew assembleDebug                 # app/build/outputs/apk/debug/app-debug.apk
./gradlew assembleDebug -Ppeersig.abis=arm64-v8a   # one ABI: faster
```

The Gradle build runs `cargo ndk` for `peersig-android` (release: the VPN
forwards every packet), copies the desktop app's window
(`crates/app/ui`) with `app/src/main/ui/android.js`, which stands in for
Tauri, and packs both. `cargo test -p peersig-android` runs the native
side's tests on the computer.

A release APK is signed with the study's key, kept out of the repository:

```sh
./gradlew assembleRelease -Ppeersig.keystore=/path/peersig.jks \
    -Ppeersig.keystorePassword=... -Ppeersig.keyAlias=peersig -Ppeersig.keyPassword=...
```

Android installs an update only when it is signed with the same key as
the installed app: keep it. The release workflow signs with the
repository secrets `ANDROID_KEYSTORE` (the keystore, base64),
`ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS` and `ANDROID_KEY_PASSWORD`,
and attaches `PeerSig_<version>_android.apk` to the release only when they
are set.

The study's key, since 0.1.11: certificate `CN=PeerSig, O=UCLouvain, C=BE`
(RSA 4096), SHA-256
`22bc542103fff2ef099a8e2df05d14fd1c8f7ca0d800a3c165517e7f857723ef`.
`apksigner verify --print-certs PeerSig_<version>_android.apk` prints it.

### Trying it on an emulator

```sh
emulator -avd <name> &
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell appops set be.uclouvain.peersig ACTIVATE_VPN allow   # skips the VPN dialog
adb shell run-as be.uclouvain.peersig cat files/logs/status.json
```

A collection server and relay on the computer are at `http://10.0.2.2:<port>`
from the emulator. Debug builds let Chrome's DevTools inspect the window
(`chrome://inspect`).

## Code

| Where | What |
| --- | --- |
| `crates/android` | The native library: VPN forwarding (`forward.rs`), the capture (`capture.rs`), apps by uid (`apps.rs`), the JNI bridge (`jni.rs`). |
| `crates/client` | The participant's side, shared with the desktop app: settings, reports, the window's commands, the notification's text. |
| `crates/probe` | The pipeline, JA4 and log format, used as a library. |
| `android/` | The Gradle project: `CaptureService` (the VPN, the notification), `MainActivity` (the window), `Host` (what the native side asks the system), `BootReceiver`. |
