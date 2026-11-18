# PeerSig on a server

For a machine without a desktop, or one that should not need the app,
install the `peersig-headless` package (x86_64, systemd): the probe, the
`peersig` command and two services. It is on the
[Participate](https://peersig.org/participate#server) page (*Linux
server*) and in each release.

```sh
sudo apt install ./peersig-headless_*_amd64.deb      # Debian, Ubuntu
sudo dnf install ./peersig-headless-*.x86_64.rpm      # Fedora, RHEL (zypper on openSUSE)
sudo peersig configure
```

`configure` asks for the enrollment code and whether to share server
names, checks the code with the server, shows what will be sent and asks
for your agreement, writes `/etc/peersig/peersig.conf` and starts the
services. Without a terminal, pass what it would ask:
`sudo peersig configure --code K7QF-2M9D-XW4P --no-share-domains --yes`.
Run it again to change a setting.

The code decides what the machine is:

- **A participant's code** (`K7QF-2M9D-XW4P`, from
  [peersig.org](https://peersig.org/participate#code)): the machine takes
  part as the app does. Once a week, the week before is reported: its
  items wait 24 hours (`--review-hours`), then each goes as a separate
  anonymous ballot, with a blind-signed token, through the relay
  (`https://relay.peersig.org`), at a random time over two hours. Nothing
  about the participant changes: see [privacy.md](privacy.md).
- **A dedicated observer's code** (`OBS-…`, from the study team): the
  machine reports every day, not anonymously, and its items are
  published without threshold: see [observers.md](observers.md).

## Every day

```sh
sudo peersig status                 # settings, code, report under way, probe, system as items name it, services
sudo peersig items                  # what goes out next: last week (yesterday for an observer)
sudo peersig items --current        # this week (today) so far
sudo peersig items --json           # exactly what is sent, one item per line
sudo peersig exclude 3f2a9c81       # leave an item out, by the id `items` shows: never sent
sudo peersig include 3f2a9c81       # put it back
sudo peersig report                 # end this week's review now (an observer: send yesterday now)
journalctl -u peersig               # what the service did
```

Every command reads the settings file first; options and environment
variables of the same names (`PEERSIG_CODE`, `PEERSIG_RELAY`,
`PEERSIG_SHARE_DOMAINS`, `PEERSIG_REVIEW_HOURS`...) override it. The logs
and the state belong to the service's user: run the commands with `sudo`.

## What the package installs

- `peersig-probe.service`: the probe, as the system user `peersig`, with
  the capabilities it needs to capture and to find the process behind
  each connection (`CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`,
  `CAP_SYS_PTRACE`), not as root. It writes one `peersig-<date>.jsonl` per
  day in `/var/lib/peersig/logs`, readable by `peersig` only, and deletes
  them after 14 days. Like the app's probe, it never uses the network.
- `peersig.service`: `peersig run`, which reads those logs and reports. A
  participant's reports, with the tokens not spent yet, are kept in
  `/var/lib/peersig/participant.json`, so that a restart loses nothing; the
  items left out, in `/var/lib/peersig/excluded`. It starts only once
  `/etc/peersig/peersig.conf` exists, and pulls in the probe.
- `/etc/peersig/peersig.conf`, written by `configure`: `KEY=VALUE` lines,
  readable by root and the `peersig` group only, since the code lets
  whoever holds it report for this machine.

The probe captures on every interface (`any`). On a machine that forwards
or bridges other devices' traffic (a router, a Wi-Fi access point, a host
for virtual machines), it sees their handshakes too: only those sent from
this machine's own addresses are tied to a process and can become items.
The others are never sent, but stay in the local logs until they are
deleted. To keep them out of the logs as well, give the probe a kernel
filter for this machine's own addresses, with `sudo systemctl edit
peersig-probe`:

```ini
[Service]
ExecStart=
ExecStart=/usr/lib/peersig/peersig-probe run --dir /var/lib/peersig/logs --quiet --bpf "host 192.0.2.10 or host 2001:db8::10"
```

Nothing is sent while the service is stopped; a week (or, for an
observer, a day older than 7 days) whose window passed is not sent later.
Removing the package stops both services and keeps the settings, state
and logs; `apt purge` deletes them too.

## Without the package

The release's `peersig-v<version>-linux-x86_64.tar.gz` has the same two
programs (or `cargo build --release -p peersig-probe -p
peersig-headless`; the probe needs `libpcap-dev`). Run the probe as root,
or with the capabilities above, and `peersig` as the user that owns the
logs and the state:

```sh
sudo peersig-probe run --dir /var/lib/peersig/logs --owner peersig --quiet
sudo peersig configure --no-start
sudo -u peersig peersig run
```

`crates/headless/packaging/` has the package's units, to copy. On macOS,
run the probe as root the same way (or let the app install it), and
`peersig` as the user that owns the logs.
