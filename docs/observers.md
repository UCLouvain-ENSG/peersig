# Dedicated observers

A dedicated observer is a machine run for the study (a lab server, a test
laptop, a VM that runs the applications we want labelled) whose traffic
may be published. It runs the same probe as a participant, but:

- it reports **every day** (UTC), shortly after midnight;
- its items are published **every day, without threshold**: one observer
  is enough, where a participant's item needs *k* participants;
- its report is **not anonymous**: the day's items go in one request
  with the observer's code, and the server knows which observer sent
  them;
- its items keep their exact versions and server names: they are not
  merged into `2.1.*` or `p*-fmip.icloud.com` as a participant's are.

Never give an observer code to a participant, and do not use one on a
computer someone uses for anything personal. On a shared machine, tell its
users that the applications they run (and, if sharing is on, the server
names those applications connect to) are published daily.

## Codes

Observer codes look like `OBS-K7QF-2M9D-XW4P`. They are made only on the
server, never by the web page:

```sh
peersig-server --db peersig.db codes add --observer --count 12
```

prints `O01  OBS-…` and so on, once: only a hash of each code is stored.
Labels count observers on their own (`O01`, `O02`…; `--prefix` changes
the letter). In the Docker deployment:

```sh
docker exec peersig-server peersig-server --db /data/peersig.db codes add --observer --count 12
```

`codes list` shows each observer with the days it reported and how many
items; `codes revoke O03` withdraws one. A participant's code cannot send
an observer's report, and an observer's code gets no ballot tokens: the
two kinds never mix, so observers never help a participant's item reach
*k*.

## From the command line

For a machine without a desktop, or one that should not need one: the
probe captures, and `peersig-observer` sends. Both are in the release's
`peersig-v<version>-linux-x86_64.tar.gz` (or `cargo build --release -p
peersig-probe -p peersig-observer`; the probe needs `libpcap-dev`).

```sh
sudo install -m 0755 peersig-probe peersig-observer /usr/local/bin/
sudo useradd --system --home /var/lib/peersig peersig
sudo install -d -o peersig -m 0700 /var/lib/peersig
sudo install -d -m 0755 /etc/peersig
sudo sh -c 'umask 077; echo OBS-K7QF-2M9D-XW4P > /etc/peersig/observer-code'
sudo chown peersig /etc/peersig/observer-code
```

The probe needs root (or the capabilities the `.deb` gives it:
`cap_net_raw,cap_net_admin,cap_dac_read_search,cap_sys_ptrace`) to
capture and to find the process behind each connection. It writes one
`peersig-<date>.jsonl` per day in its directory, readable only by the
`--owner`, and deletes them after 14 days:

```ini
# /etc/systemd/system/peersig-probe.service
[Unit]
Description=PeerSig capture probe
After=network.target

[Service]
ExecStart=/usr/local/bin/peersig-probe run --dir /var/lib/peersig/logs --owner peersig --quiet
Restart=always

[Install]
WantedBy=multi-user.target
```

`peersig-observer` runs as that owner, reads the logs and reports each day
at about 00:15 UTC, retrying every 10 minutes while the server cannot be
reached:

```ini
# /etc/systemd/system/peersig-observer.service
[Unit]
Description=PeerSig dedicated observer
After=network-online.target peersig-probe.service
Wants=network-online.target

[Service]
User=peersig
ExecStart=/usr/local/bin/peersig-observer --code-file /etc/peersig/observer-code --logs /var/lib/peersig/logs --share-domains run
Restart=always

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now peersig-probe peersig-observer
journalctl -u peersig-observer     # "2026-11-18: reported 412 items as O03"
```

Leave out `--share-domains` to send applications and fingerprints only,
without the server names non-browser applications connect to. Browsers'
server names are never sent.

Other commands, with the same options (each can also come from the
environment: `PEERSIG_SERVER`, `PEERSIG_CODE_FILE`, `PEERSIG_LOGS`,
`PEERSIG_SHARE_DOMAINS`):

```sh
peersig-observer --logs /var/lib/peersig/logs items                   # yesterday's items, as a table
peersig-observer --logs /var/lib/peersig/logs items --day today --json # exactly what would be sent
peersig-observer --code-file /etc/peersig/observer-code --logs /var/lib/peersig/logs report               # yesterday, now
peersig-observer --code-file /etc/peersig/observer-code --logs /var/lib/peersig/logs report --day 2026-11-15
```

`report` without `run` suits a timer instead of a service. A day is
counted once per observer: sending it again is answered "already
reported". The server accepts a day for 7 days after it ends, so a machine
that was offline can catch up with `report --day`. `--server` defaults to
`https://peersig.org`. A day with no items in the logs (the probe was not
running) is not sent.

On macOS, run the probe as root the same way (`sudo peersig-probe run
--dir <dir> --owner <user>`, or let the app install it), and
`peersig-observer` as that user.

## With the app

Enter the observer code on the app's join screen: the app says it is an
observer code before you join, and then works by day instead of by week.
It sends each day's report shortly after midnight UTC, with no review by
default (*Settings* can add one); the window shows the day being reported
and today so far. The app sends nothing while it is not running; a day it
missed can be sent with `peersig-observer report --day`.

## The published table

- `GET /v1/released/observers`: the days with reports, most recent first,
  each with the number of observers that reported and of distinct items.
- `GET /v1/released/observers/<YYYY-MM-DD>`: that day's items, each with
  the number of observers that reported it.

```json
{"day": "2026-11-17", "observers": 3, "items": [
  {"item": {"type": "hello", "os": "linux 6", "transport": "tcp", "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
            "app": {"name": "curl", "version": "8.5.0", "kind": "cli"}}, "observers": 2}]}
```

A day fills as its observers report, normally within the first hour of
the next day (UTC), and late reports can still add to it for 7 days. On
the server:

```sh
peersig-server --db peersig.db stats                                     # the last 14 days, after the weeks
peersig-server --db peersig.db export --observers --day 2026-11-17       # one day, JSON
peersig-server --db peersig.db export --observers --day 2026-11-01 --since
peersig-server --db peersig.db export --observers --format classifier    # Iris format, all days
```
