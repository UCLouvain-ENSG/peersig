# Running a collection

## Server

```sh
peersig-server --db /var/lib/peersig/peersig.db serve --listen 127.0.0.1:8080
```

Put it behind a TLS proxy with access logs **off** (the server itself never
logs addresses). With Caddy:

```text
peersig.example.org {
    reverse_proxy 127.0.0.1:8080
    log {
        output discard
    }
}
```

With Apache (modules `proxy_http`, `headers`, `ssl`): give the virtual host
its own `CustomLog`, or the server-wide one (Debian's
`other-vhosts-access-log`) records every address.

```apache
<VirtualHost *:443>
    ServerName peersig.example.org
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/peersig.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/peersig.example.org/privkey.pem
    # No access log; errors without the client's address.
    CustomLog /dev/null common
    ErrorLogFormat "[%t] [%-m:%l] %M"
    ProxyPass / http://127.0.0.1:8080/
    # The server does not need the client's address: do not even pass it.
    ProxyAddHeaders Off
</VirtualHost>
```

Or with Docker (image built from the repository's `Dockerfile`):

```sh
docker build -t peersig .
docker run -d -v peersig:/data -p 127.0.0.1:8080:8080 peersig
```

Parameters (flags or environment variables):

| Flag | Env | Default | |
| --- | --- | --- | --- |
| `--epoch-origin` | `PEERSIG_EPOCH_ORIGIN` | Monday of the first run | Fixed when the database is created |
| `--epoch-days` | `PEERSIG_EPOCH_DAYS` | 7 | Fixed when the database is created |
| `--tokens-per-epoch` | `PEERSIG_TOKENS` | 512 | Ballots a participant can send per week |
| `--k-hello` | `PEERSIG_K_HELLO` | 3 | Participants needed to release a fingerprint |
| `--k-domain` | `PEERSIG_K_DOMAIN` | 5 | Participants needed to release a domain |
| `--about-url` | `PEERSIG_ABOUT_URL` | none | Study page, linked from the app |

The web page and enrollment from it (`serve` only):

| Flag | Env | Default | |
| --- | --- | --- | --- |
| `--public-url` | `PEERSIG_PUBLIC_URL` | none | The server's address, for links and GitHub's callback |
| `--relay-url` | `PEERSIG_RELAY_URL` | none | Shown on the page and in messages |
| `--contact` | `PEERSIG_CONTACT` | none | The study team's address, shown on the page and in messages |
| `--smtp-url` | `PEERSIG_SMTP_URL` | none | Codes by e-mail: `smtp://127.0.0.1:25` (a local MTA, no TLS), `smtp://user:pass@host:587?tls=required`, `smtps://user:pass@host:465` |
| `--mail-from` | `PEERSIG_MAIL_FROM` | none | `PeerSig <peersig@example.org>` |
| `--github-client-id`, `--github-client-secret` | `PEERSIG_GITHUB_CLIENT_ID`, `PEERSIG_GITHUB_CLIENT_SECRET` | none | Codes with a GitHub account |
| `--github-min-age-days` | `PEERSIG_GITHUB_MIN_AGE_DAYS` | 30 | Younger GitHub accounts get no code |
| `--codes-per-identity` | `PEERSIG_CODES_PER_IDENTITY` | 3 | Codes per address or GitHub account |
| `--enroll-per-hour` | `PEERSIG_ENROLL_PER_HOUR` | 60 | Codes the page hands out per hour |
| `--enroll-networks` | `PEERSIG_ENROLL_NETWORKS` | none | Address blocks whose visitors get a code with one click, comma-separated (`130.104.0.0/16,2001:6a8:3080::/44`) |
| `--enroll-network-name` | `PEERSIG_ENROLL_NETWORK_NAME` | institution's | Their name on the page |
| `--client-address-header` | `PEERSIG_CLIENT_ADDRESS_HEADER` | none | Behind a proxy: where it puts the client's address on `/enroll/` |
| `--enroll-per-address` | `PEERSIG_ENROLL_PER_ADDRESS` | 5 | Requests for a code by e-mail or GitHub per client address and hour, counted in memory only; 0: no limit |
| `--admin-github` | `PEERSIG_ADMIN_GITHUB` | none | GitHub logins allowed into `/admin`, comma-separated (needs the GitHub app) |
| `--notice` | `PEERSIG_NOTICE` | none | Shown at the top of the page, e.g. the limits of a pilot |

## Relay

Ask someone independent of the study to run it: another lab, the
university's data protection officer, or use a commercial Oblivious HTTP
relay.

```sh
peersig-relay --listen 127.0.0.1:8081 --gateway https://peersig.example.org
```

Same advice: TLS in front, access logs off. It keeps client addresses in
memory for rate limiting only (600 requests per minute and address by
default), and forgets them within two minutes. Behind a proxy on the same
machine, every request comes from 127.0.0.1: pass `--forwarded` so the
relay counts each client by the address the proxy appends to
`X-Forwarded-For` (and keep `ProxyAddHeaders` on in that virtual host). The
header is not passed on to the server.

## Enrolling participants

Participants need a code: it keeps the collection closed to people who are
not taking part (see [privacy.md](privacy.md#0-enrollment)). Either hand
codes out:

```sh
peersig-server --db peersig.db codes add --count 20 --prefix P
```

prints `P01  K7QF-2M9D-XW4P` and so on. Only a hash of each code is stored:
give each participant theirs when they consent. `codes list` shows the
weeks each label took part in (to pay participants), `codes revoke P07`
withdraws one.

Or let the web page hand them out, by e-mail, with GitHub, from a network,
or any of these:

- **E-mail**: `--smtp-url` and `--mail-from`. A local MTA that signs (DKIM)
  and is allowed to send for the sender's domain (SPF) keeps messages out
  of spam folders.
- **GitHub**: register an OAuth app (GitHub → Settings → Developer
  settings → OAuth Apps; for an organisation, its settings), with the
  callback URL `<public-url>/enroll/github/callback`, and pass its client
  id and secret. Accounts younger than `--github-min-age-days` (30) get no
  code.
- **Network**: `--enroll-networks` with the institution's blocks (its
  network and VPN).

Behind a proxy, the server sees 127.0.0.1: have the proxy put the client's
address in a header **on the enrollment paths only**, overwriting what the
client sent, and name it with `--client-address-header`. The server checks
it against the network's blocks, and counts requests for a code by e-mail
or GitHub per address (`--enroll-per-address`, in memory only). Without the
header, nothing is counted per address. With Apache:

```apache
<Location /enroll/>
    RequestHeader set X-PeerSig-Client "expr=%{REMOTE_ADDR}"
</Location>
```

Codes from the page are labelled `M01`, `G02`, `N03`... in `codes list`. The page
needs `--public-url`; without e-mail or GitHub, it says the study team
hands out codes.

### Admin page

`--admin-github alice,bob` opens `/admin` to those GitHub accounts, signed
in through the same OAuth app (GitHub accepts its callback
`<public-url>/enroll/github/callback/admin`, under the registered one). It
does what `codes add`, `codes list`, `codes revoke` and `stats` do, and bans
an e-mail address, a mail domain or a GitHub account from getting codes.
The session is a signed cookie for 12 hours; removing a login from the list
ends its sessions at the next restart.

### Dedicated observers

Machines the study runs, whose items are published every day without
threshold, enroll with an observer code, made only on the server:

```sh
peersig-server --db peersig.db codes add --observer --count 12   # O01  OBS-K7QF-2M9D-XW4P ...
```

The admin page lists and revokes them, but does not make them. They run
the app, or the `peersig-observer` package on a Linux server: see
[observers.md](observers.md).

The app's join screen fills in the addresses compiled in as
`DEFAULT_SERVER` and `DEFAULT_RELAY` (`crates/app/src/core.rs`): change them
for another collection.

## Results

```sh
peersig-server --db peersig.db stats                       # per week: codes, reporters, ballots, items
peersig-server --db peersig.db export                      # released items, JSON
peersig-server --db peersig.db export --format classifier  # one {ja4_hash, desc} record per JA4
```

The released list is also public at `/v1/released`; the observers' daily
table at `/v1/released/observers` (`export --observers`, see
[observers.md](observers.md#the-published-table)). The site's `/data` page
shows both, in two tabs, with a filter and a day picker.

## Releases

Pushing a tag `v<version>` runs `.github/workflows/release.yml`:

- the macOS app (Apple Silicon and Intel: `.dmg`), the Linux app (`.deb`,
  `.rpm`, `.AppImage`) and the Windows app (`.msi`, x64), each with the
  probe inside (on Windows it uses the system's packet capture: nothing
  else to install);
- `peersig-server`, `peersig-relay`, `peersig-probe` and
  `peersig-observer` for Linux x86_64, and the headless observer's
  packages (`peersig-observer_<version>_amd64.deb`,
  `peersig-observer-<version>-1.x86_64.rpm`, built with nfpm by
  `crates/observer/packaging/build.sh`, installed and checked on the
  runner by `smoke.sh`);
- `SHA256SUMS`.

They go to a **draft** release; check it and publish it on GitHub. The tag
must match the version in `Cargo.toml` and `crates/app/tauri.conf.json`.

Without Apple secrets, the macOS builds are signed ad hoc
(`signingIdentity: "-"` in `tauri.conf.json`): the first time, macOS
refuses to open them, and *System Settings → Privacy & Security → Open
Anyway* lets them run. A bundle with no signature at all (only the linker's
on the executable) is reported as "damaged", with no way to open it. To sign
and notarize, add the repository secrets `APPLE_CERTIFICATE` (base64 .p12),
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD` (app-specific) and `APPLE_TEAM_ID`. The workflow passes
them to the Tauri bundler when they are set; `APPLE_SIGNING_IDENTITY`
overrides the ad-hoc identity.

On Linux, install the `.deb` or the `.rpm`: their post-install script gives
the probe the capture capabilities it needs. The AppImage cannot carry
capabilities; the app then asks for them through `pkexec`, which fails on
the read-only image. Both packages are built on Ubuntu; the `.rpm`'s probe
is patched to load `libpcap.so.1`, the name Fedora, RHEL and openSUSE give
the library Debian calls `libpcap.so.0.8`.

### Downloads on the site

The site's `/participate` page links to `/download/<file>` and reads
`/download/latest.json` to offer each visitor the package for their system
(a package missing from that file is not offered). `peersig-server` does
not serve that directory: the web server in front of it does. With Apache,
before the `ProxyPass /` line:

```apache
    Alias /download /var/www/peersig/download
    ProxyPass /download !
```

Once a release is published on GitHub, fill the directory from it:

```sh
scripts/mirror_release.py /var/www/peersig/download          # or --tag v0.1.3
```

It downloads the packages, checks them against the release's `SHA256SUMS`,
gives each a stable name (`PeerSig-windows-x64.msi`,
`peersig-observer-amd64.deb`) and replaces
`latest.json` last. New packages or page text also need the new
`peersig-server`: the pages are compiled in.
