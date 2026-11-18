# peersig-probe: endpoint ground truth for JA4

`peersig-probe` is PeerSig's capture daemon. It runs on a participant's computer. It watches the packets the
computer sends. For each TLS, QUIC or DTLS ClientHello it computes the JA4
(and JA3), then looks up which process sent it and which application that
process belongs to. It also records the names each process contacts. The
result ties fingerprints seen at the campus TAP to applications and versions.

macOS is complete. Linux has fingerprints and per-ClientHello process lookup
(procfs). Windows has fingerprints, per-ClientHello process lookup (the TCP
and UDP tables) and Windows-specific app naming (see [Windows](#windows)).

It needs libpcap on macOS and Linux; on Windows it uses the packet capture
built into the system, so nothing else is installed. The PeerSig app
(`../app`) installs it, reads its logs and sends what the participant
agrees to; the probe itself never uses the network.

## Build and run (macOS)

```sh
cargo build --release -p peersig-probe
sudo ./target/release/peersig-probe run            # Ctrl-C to stop
./target/release/peersig-probe summary peersig-probe-*.jsonl
```

`run` writes `peersig-probe-<date>-<time>.jsonl` in the current directory, owned by
the user who ran `sudo`. The terminal shows each new (JA4, application)
pair:

```text
14:03:22  quic  q13d0311h3_55b375c5d22e_5a1f323ef56d  Google Chrome 157.0.8103.51  [Google Chrome Helper]  -> www.google.com
```

Options: `--no-names` (no SNI, DNS or HTTP names), `--duration <s>`, `-v`
(print every ClientHello), `-q`, `--save-pcap <file>` (keep the packets,
for debugging), `-i <device>`, `--bpf <filter>`.

Daemon mode, used by the PeerSig app: `run --dir <dir> [--owner <user>]
[--keep-days 14]` writes one `peersig-<date>.jsonl` per day in `<dir>`,
deletes files older than `--keep-days`, refreshes `<dir>/status.json` every
5 s, and closes the capture device while `<dir>/paused` exists. Files belong
to `--owner` (default: the user who ran sudo) and are readable by that user
only.

Root is needed: the PKTAP pseudo-interface, which gives the process of each
packet, is root only. A study install would run it as a LaunchDaemon. That
is not written yet.

`whois <pid>...` prints what the tool knows about running processes. It
needs no root for your own processes and no capture. It is the quickest way
to check the attribution logic:

```sh
./target/release/peersig-probe whois $(pgrep -f 'network.mojom.NetworkService')
```

`read <file.pcap>` runs on a capture file: fingerprints only, plus the
process names when the file has the PKTAP link type (`--save-pcap` output).

## What is recorded

One JSON object per line, with these `type`s:

| type | when | content |
| --- | --- | --- |
| `start` | first line | tool and app-table versions, random session id, OS version and build, Mac model, device, kernel filter |
| `process` | first time a process is seen | pid, start time, executable, bundle chain (id, name, version of each `.app`/`.framework`/`.xpc`), code signature (identifier, team id, Apple platform binary), embedded Info.plist, engine, Go version, Homebrew/Nix package, Chromium helper type, interpreter script name, TLS libraries mapped and linked, responsible pid; on Windows also the version resource, subsystem (gui, console), MSIX/Scoop package and the services a svchost runs |
| `hello` | each ClientHello | time, transport (tcp, quic, dtls), QUIC version, addresses, interface, service class, SNI, ALPN, ECH, `ja4`, `ja4_r`, `ja4_o`, `ja4_ro`, `ja4_legacy`, `ja3`, `ja3_r`, the socket's process (`proc`, `helper`, `stacks`), effective (`eproc`) and responsible (`resp`) processes, and `app` |
| `domain` | every 5 minutes (`--flush-every`) and at exit, for each (process, name) that changed | credited process and app, name, `via` (sni, dns, dns-query, http), cumulative count, first and last time, ports, JA4s |
| `stats` | every 5 minutes and at exit | packets, ClientHellos per transport, failures, libpcap drops |

`app` is the application credited with the traffic:

```json
{"name": "Microsoft Teams", "id": "com.microsoft.teams2", "version": "26289.204.5281.6363",
 "team_id": "UBF8T346G9", "kind": "app", "engine": "chromium 156.0.4314.42",
 "via": "self+responsible", "path": "/Applications/Microsoft Teams.app"}
```

`kind` is `browser` (from [`data/apps.toml`](data/apps.toml)), `system`
(Apple platform binary, or under `/System`, `/usr`), `app`, `cli` or
`unknown`. `engine` is the engine of the process that wrote the ClientHello:
`chromium <v>`, `electron <v>`, `cef <v>`, `gecko <v>` or `webkit <build>`.

## How a ClientHello is tied to an application

1. **Process of the packet.** On macOS, the `pktap` pseudo-interface prefixes
   every packet with its interface, the owning process (pid, name, executable
   UUID), the *effective* process when the socket is delegated, and the
   service class. The probe asks for that header with Apple's
   `pcap_set_want_pktap`; without the call, libpcap strips it (the `start`
   record's `dlt` is then not 149 or 258, and a warning is printed).
   Background downloads are a delegated socket: nsurlsessiond
   downloads for softwareupdated (macOS updates), the App Store or an app
   extension. No socket-table polling is needed, and short-lived processes
   are caught too. When a packet has no process (or on a device other than
   pktap), the socket's owner is looked up once per ClientHello (`lsof` on
   macOS, procfs on Linux): `attribution` is `socket-table`.
2. **Process to executable and app.** `proc_pidpath`, `KERN_PROCARGS2` (only
   Chromium's `--type` and an interpreter's script name are kept, never the
   full command line), the bundles around the executable with their
   `Info.plist`, and the Mach-O itself: the code-signature CodeDirectory
   (identifier, team id, platform), the embedded `__info_plist` (bare
   daemons), linked libraries, and the Go build info. Nothing is executed.
3. **Who it works for.** The responsible process
   (`responsibility_get_pid_responsible_for_pid`, what Activity Monitor uses)
   puts an XPC service under the app that started it. This is how Safari's
   and every WKWebView app's traffic is credited: it is sent by
   `com.apple.WebKit.Networking`. The responsible app is credited only when
   the process is an XPC service, an app extension, a WebKit process, or a
   helper inside that app. A `curl` run in Terminal stays `curl`.
4. **Engine and stack.** A helper inside `<Product> Framework.framework/Versions/<v>/Helpers`
   is Chromium `<v>`. So are Chrome, Edge, Brave and Comet, and Teams through
   its Edge WebView. Electron and CEF are found by their frameworks, Gecko by
   `XUL` and its `platform.ini`, WebKit by its networking process. Mapped
   libraries outside the dyld shared cache (Homebrew OpenSSL, NSS) and linked
   ones (LibreSSL, Network.framework, CFNetwork) give `stacks`.

Checked with `whois` on a macOS 27 laptop: Chrome's network helper is
Google Chrome 157.0.8103.51 (team EQHXZ8M8AV, chromium 157). Teams' WebView
network helper is Microsoft Teams (chromium 156, Edge framework).
`com.apple.WebKit.Networking` processes are credited to the WKWebView apps
that started them (webkit). Firefox is gecko 160 with NSS. VS Code's plugin
helper is Code (electron 43.8.6). nsurlsessiond is a system process.

## Names per process

Each process gets a table of the names it contacts:

- `sni`: the ClientHello's server name;
- `dns`: a TCP or UDP connection to an address that a DNS answer gave. The
  name recorded is the one asked, not the CDN alias. macOS resolves through
  mDNSResponder, so the answers, matched to the connection that follows, are
  what tie a name to an app. The kernel filter lets inbound DNS answers
  through for this (see `net::pktap_filter`);
- `dns-query`: a query the process sent itself (Chromium's built-in resolver,
  Go, dig). mDNSResponder's own queries are not credited to it;
- `http`: the `Host` of a plain HTTP request, or a `CONNECT` target.

Encrypted DNS (DoH, DoT, iCloud Private Relay) leaves no answers to read;
those names come from SNI only, and ECH hides the real SNI. `dns` and `http`
need PKTAP metadata: without it, only SNI fills the table.

## Fingerprints

`ja4` follows FoxIO's [JA4 spec](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md),
and so do `ja4_r`, `ja4_o` and `ja4_ro`. `ja4_legacy` is an earlier,
non-standard value whose extension hash left out the signature algorithms,
to join with TAP records archived with it before 2026-11-16
(`summary --key ja4_legacy` groups by it).

QUIC Initial packets are decrypted (v1, v2, drafts 23 to 34). A ClientHello
split over several packets or datagrams is put back together by CRYPTO
offset; the client's original keys are kept after it switches to the
server's connection id. TCP ClientHellos are reassembled from the SYN, so
out-of-order segments and retransmissions are fine. DTLS handshake fragments
are reassembled by fragment offset. For DTLS, the newest version offered is
the numerically smallest (0xfefc is DTLS 1.3), which matches Wireshark.

### Validation

- `tests/compare_tshark.py` compares JA4 and JA4_r with tshark 4.6, flow by
  flow. All 131 ClientHellos of the test traces matched (TLS 1.0 to 1.3,
  SSLv3, QUIC with ML-KEM over two packets, Retry), and so do the two of
  Wireshark's DTLS test captures (DTLS 1.2, and OpenSSL's pre-standard
  0x0100).
- `tests/data/` holds captures built by `tests/make_pcaps.py` from
  ClientHellos sent by local clients to 127.0.0.1:
  - OpenSSL 4.1 with ML-KEM, split in three segments sent out of order;
  - Python over IPv6;
  - macOS curl;
  - OpenSSL DTLS 1.2 (2 fragments) and DTLS 1.3 (8 fragments, out of order);
  - a PKTAP capture with DNS, HTTP, delegation and an inbound packet.

  Their values match tshark (DTLS 1.3 in order: tshark does not reassemble
  out-of-order DTLS fragments). The header layout of the PKTAP capture also
  matches Wireshark's PKTAP dissector.
- `ja4_legacy` on `quic_retry.pcapng` is `q13d0308h3_55b375c5d22e_861f5c13a969`,
  the value the classifier wrote for it in `tc.json` before the fix. The
  fixed classifier gives the same `ja4` as tshark 4.6 on the 122 TLS and QUIC
  ClientHellos of those traces, as the probe does. `tests/data/traces` keeps the
  small ones (78 ClientHellos).
- `cargo test`: RFC 9001 and RFC 9369 Initial keys, the JA4 spec's worked
  example, the ALPN rules, DNS, and the end-to-end captures above.

Not yet validated: a live capture. Everything above ran from files, and
`whois` on live processes.

## Cost

The kernel filter passes outbound packets and inbound DNS answers only.
Downloads (macOS updates, video) stay in the kernel; outbound ACKs and
uploads reach user space. User space keeps state only for connections whose
ClientHello is in progress (30 s at most), for QUIC/DTLS ClientHellos already
reported (2 min), and for the DNS answer cache. A process is inspected once
per (pid, start time).

## Privacy

- The log stays on the participant's machine. `summary` prints applications
  per JA4 without names; `summary --names` adds them.
- The log keeps: full server names unless `--no-names`, destination
  addresses, local addresses, and executable paths. Paths under
  `/Users/<name>` (`C:\Users\<name>` on Windows) contain the account name.
- Command lines are never stored; only Chromium's helper type and an
  interpreter's script file name are.
- No hostname is stored, only a random session id.

## Other systems

The capture, flow and fingerprint code is portable. What is per-OS
(`src/platform/`):

- **Linux**: no per-packet process. The ClientHello's socket is found
  through `/proc/net/{tcp,udp}[6]` and `/proc/*/fd`, then
  `/proc/<pid>/{exe,cmdline,maps}`. It compiles (`cargo check --target
  x86_64-unknown-linux-gnu`) but has not been run. Next steps: an eBPF probe
  on `tcp_connect`/`udp_sendmsg` for the per-packet process, and package
  versions from dpkg/rpm, Flatpak and Snap.
- **Windows**: see below.

### Windows

```powershell
cargo build --release -p peersig-probe
.\target\release\peersig-probe.exe run            # an administrator terminal
.\target\release\peersig-probe.exe whois 1234
```

- **Capture** (`src/capture/etw.rs`). The packet capture built into
  Windows: the NDIS capture filter (ndiscap.sys, what `netsh trace` and
  `pktmon` use) is bound to every adapter of Windows 10 and 11, and logs
  packets through ETW (Microsoft-Windows-NDIS-PacketCapture) to the trace
  sessions that enable it. The probe runs one real-time session with only
  the send path enabled, so received traffic (downloads) stays in the
  kernel, as with the outbound filter on macOS. Ethernet and Wi-Fi frames
  come as Ethernet, mobile broadband and tunnels as raw IP. Packets from
  adapters without an IP address are left out (a card under a Hyper-V
  switch repeats its virtual adapter's packets). Loopback traffic is not
  seen. There is no BPF; `-i <interface index>` keeps one adapter. Starting
  the session needs an administrator, or LocalSystem for the service;
  buffers are flushed every 100 ms so that a ClientHello arrives while its
  connection is still open. `--save-pcap` writes pcapng, and `read` reads
  pcap and pcapng without libpcap (`src/capture/file.rs`).
- **Process of a ClientHello.** No per-packet process: the socket's owner
  is looked up once per ClientHello in the TCP table (both endpoints) or
  the UDP table (the source port, on that address or on all of them), as
  `netstat -ano` does. `attribution` is `socket-table`. A connection that
  closes before its ClientHello is handled can be missed.
- **Process to app.** `QueryFullProcessImageNameW`, start time and parent
  (`NtQueryInformationProcess`), command line (only Chromium's `--type`
  and an interpreter's script are kept), loaded modules (ToolHelp). The
  executable's version resource is read from the file itself, so its
  product name is the same whatever the display language: it names the
  app, with its product version. An MSIX (Store) app is named by its
  package manifest and versioned by its package; its family name
  (`MSTeams_8wekyb3d8bbwe`) is its `id`. A svchost process is named by the
  service it runs (`wuauserv`, `BITS`, `DoSvc`), from the service manager.
  `kind` is `system` under `%SystemRoot%` and for Windows components,
  `app` for a GUI executable, `cli` for a console one. Browsers are matched
  by executable name (`data/apps.toml`); an executable installed the way
  Chromium browsers are (a version directory with `chrome.dll` or
  `msedge.dll`) is a browser even when it is not listed, so that its names
  are never collected.
- **Who it works for.** A WebView2 process (`msedgewebview2.exe`) works for
  the app that started it, through the parent chain: Teams, Outlook,
  WhatsApp. A Chromium or Electron child works for its browser process
  (same executable). The engine is that of the process that wrote the
  ClientHello: Chromium from the version directory beside `chrome.dll` or
  `msedge.dll`, CEF from `libcef.dll`, Gecko from `xul.dll`, Electron from
  `resources\app.asar` (with a version only when a `version` file shipped).
- **Service.** `peersig-probe service --dir <logs> --owner <SID>` is what
  the PeerSig app installs as the `PeerSigProbe` service (LocalSystem,
  automatic, restarted on failure). It waits until it can capture and says
  why in `status.json` (`error`) meanwhile. The
  log directory gets its own ACL (SYSTEM, Administrators, and the
  participant: read, and add the `paused` file), and files are opened
  without following links or hard links. Warnings go to `probe.log` next
  to it.
- Checked with `whois` on Windows 11, not elevated: Firefox is a browser (gecko,
  NSS); WhatsApp's WebView2 processes are WhatsApp 2.2642.101.0 (chromium
  157, from its WebView2 runtime); Claude and VS Code's helpers are
  credited to their Electron apps; svchost processes carry their service.
  A 30 s live capture on Windows 11 saw 1905 sent packets and 20
  ClientHellos (TCP and QUIC: Spotify, Firefox, VS Code, OneDrive,
  PowerShell...); 17 were attributed, the others came from processes that
  had already exited (curl). Its pcapng gives the same 20 with `read`.
- Not done: the code-signing publisher (Authenticode) as `team_id`; the
  per-packet process (the ETW kernel network events), which would also
  give DNS and HTTP names (they need per-packet metadata, as on Linux).

`data/apps.toml` (browser bundle ids and executable names, stack libraries,
resolver processes) is compiled in; bump its `version` on every change.
