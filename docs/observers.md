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

## On a Linux server

For a machine without a desktop, or one that should not need one, install
the `peersig-observer` package (x86_64, systemd): the probe, the
`peersig-observer` command and two services. It is on the
[Participate](https://peersig.org/participate#server) page (*Linux
server*) and in each release.

```sh
sudo apt install ./peersig-observer_*_amd64.deb      # Debian, Ubuntu
sudo dnf install ./peersig-observer-*.x86_64.rpm      # Fedora, RHEL (zypper on openSUSE)
sudo peersig-observer configure
```

`configure` asks for the observer code and whether to share server
names, checks the code with the server, writes `/etc/peersig/observer.conf`
and starts the services. Without a terminal, pass what it would ask:
`sudo peersig-observer configure --code OBS-K7QF-2M9D-XW4P --share-domains`
(or `--no-share-domains`). Run it again to change a setting; `--server`
changes the collection server (default `https://peersig.org`).

```sh
sudo peersig-observer status        # settings, the code's observer and last report, the probe, the services
journalctl -u peersig-observer      # "2026-11-18: reported 412 items as O03"
```

What the package installs:

- `peersig-probe.service`: the probe, as the system user `peersig`, with
  the capabilities it needs to capture and to find the process behind
  each connection (`CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`,
  `CAP_SYS_PTRACE`), not as root. It writes one `peersig-<date>.jsonl` per
  day in `/var/lib/peersig/logs`, readable by `peersig` only, and deletes
  them after 14 days.
- `peersig-observer.service`: reads those logs and reports each day at
  about 00:15 UTC, retrying every 10 minutes while the server cannot be
  reached. It starts only once `/etc/peersig/observer.conf` exists, and
  pulls in the probe.
- `/etc/peersig/observer.conf`, written by `configure`: `KEY=VALUE` lines
  (`PEERSIG_SERVER`, `PEERSIG_CODE`, `PEERSIG_SHARE_DOMAINS`,
  `PEERSIG_LOGS`), readable by root and the `peersig` group only, since
  the code lets whoever holds it report as this observer.

Removing the package stops both services and keeps the settings and logs;
`apt purge` deletes them too.

Every `peersig-observer` command reads the settings file first; options
and environment variables of the same names override it. As root or as
`peersig` (the logs are theirs only):

```sh
sudo peersig-observer items                        # yesterday's items, as a table
sudo peersig-observer items --day today --json     # exactly what would be sent
sudo peersig-observer report                       # send yesterday now
sudo peersig-observer report --day 2026-11-15      # a day that was missed
```

A day is counted once per observer: sending it again is answered "already
reported". The server accepts a day for 7 days after it ends, so a machine
that was offline can catch up with `report --day`. A day with no items in
the logs (the probe was not running) is not sent. Browsers' server names
are never sent.

### Without the package

The release's `peersig-v<version>-linux-x86_64.tar.gz` has the same two
programs (or `cargo build --release -p peersig-probe -p peersig-observer`;
the probe needs `libpcap-dev`). Run the probe as root, or with the
capabilities above, and `peersig-observer` as the user that owns the logs:

```sh
sudo peersig-probe run --dir /var/lib/peersig/logs --owner peersig --quiet
sudo peersig-observer --config /etc/peersig/observer.conf configure --no-start
sudo -u peersig peersig-observer run
```

`crates/observer/packaging/` has the package's units, to copy. On macOS,
run the probe as root the same way (or let the app install it), and
`peersig-observer` as the user that owns the logs.

## With the app

Enter the observer code on the app's join screen: the app says it is an
observer code before you join, and then works by day instead of by week.
It sends each day's report shortly after midnight UTC, with no review by
default (*Settings* can add one); the window shows the day being reported
and today so far. The app sends nothing while it is not running, and a day it
missed is not sent later.

## The published table

On the site: [peersig.org/data](https://peersig.org/data#observers), tab
*Dedicated observers*, a day at a time. For programs:

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
peersig-server --db peersig.db export --observers --format classifier    # one record per JA4, all days
```
