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
| `--rr-epsilon` | `PEERSIG_RR_EPSILON` | ln 9 | Randomized response, per item and week |
| `--k-hello` | `PEERSIG_K_HELLO` | 3 | Participants needed to release a fingerprint |
| `--k-domain` | `PEERSIG_K_DOMAIN` | 5 | Participants needed to release a domain |
| `--epsilon-central` | `PEERSIG_EPSILON_CENTRAL` | 1 | Laplace noise on released counts |
| `--about-url` | `PEERSIG_ABOUT_URL` | none | Study page, linked from the app |

## Relay

Ask someone independent of the study to run it: another lab, the
university's data protection officer, or use a commercial Oblivious HTTP
relay.

```sh
peersig-relay --listen 127.0.0.1:8081 --gateway https://peersig.example.org
```

Same advice: TLS in front, access logs off. It keeps client addresses in
memory for rate limiting only (600 requests per minute and address by
default), and forgets them within two minutes.

## Enrolling participants

```sh
peersig-server --db peersig.db codes add --count 20 --prefix P
```

prints `P01  K7QF-2M9D-XW4P` and so on. Only a hash of each code is stored:
give each participant theirs, with the server and relay addresses, when
they consent. `codes list` shows the weeks each label took part in (to pay
participants), `codes revoke P07` withdraws one.

## Results

```sh
peersig-server --db peersig.db stats                       # per week: codes, reporters, ballots, items
peersig-server --db peersig.db export                      # released items, JSON
peersig-server --db peersig.db export --format classifier  # Iris ja4_fingerprints.json format
```

The released list is also public at `/v1/released`.

## Releases

Pushing a tag `v<version>` runs `.github/workflows/release.yml`:

- the macOS app (Apple Silicon and Intel: `.dmg`) and the Linux app (`.deb`,
  `.AppImage`), each with the probe inside;
- `peersig-server`, `peersig-relay` and `peersig-probe` for Linux x86_64;
- `SHA256SUMS`.

They go to a **draft** release; check it and publish it on GitHub. The tag
must match the version in `Cargo.toml` and `crates/app/tauri.conf.json`.

The macOS builds are not signed. To sign and notarize them, add the
repository secrets `APPLE_CERTIFICATE` (base64 .p12),
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_ID`,
`APPLE_PASSWORD` (app-specific) and `APPLE_TEAM_ID`. The workflow passes
them to the Tauri bundler when they are set.

On Linux, install the `.deb`: its post-install script gives the probe the
capture capabilities it needs. The AppImage cannot carry capabilities; the
app then asks for them through `pkexec`, which fails on the read-only image.
