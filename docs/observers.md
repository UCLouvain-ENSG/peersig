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

Being an observer is a matter of the code alone, not of how PeerSig runs:
the app on macOS, Windows or Linux, or `peersig` on a server
([headless.md](headless.md)) each become an observer with an `OBS-` code.

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

## On a server

Install the `peersig-headless` package and run `sudo peersig configure`
with the observer code: see [headless.md](headless.md). The service then
reports each day at about 00:15 UTC, retrying every 10 minutes while the
server cannot be reached; `sudo peersig report --day 2026-11-15` sends a
day it missed (the server accepts a day for 7 days after it ends). A day
is counted once per observer: sending it again is answered "already
reported". A day with no items in the logs (the probe was not running) is
not sent.

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
