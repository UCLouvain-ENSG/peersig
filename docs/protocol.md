# Protocol

Version 1. Types are in `crates/proto/src/wire.rs`; bytes are unpadded
URL-safe base64 in JSON.

## Epochs

`EpochSpec { origin, length }` (Unix seconds; one week by default). Epoch
*e* covers `[origin + e·length, origin + (e+1)·length)`. During epoch *c*,
participants report epoch *c − 1* (`report_epoch`). Tokens and ballots are
accepted for the report epoch only.

## Endpoints

| Method and path | Transport | Purpose |
| --- | --- | --- |
| `GET /ohttp-keys` | direct and via relay | Gateway key configuration (`application/ohttp-keys`) |
| `POST /ohttp` | via relay | Oblivious HTTP gateway (`message/ohttp-req` → `message/ohttp-res`) |
| `GET /v1/config` | OHTTP | Epochs, token key of the report epoch, parameters |
| `POST /v1/ballot` | OHTTP only | One ballot |
| `GET /v1/released` | OHTTP or direct | Released items with noisy support |
| `POST /v1/issue` | direct | Token issuance, authenticated by the enrollment code |
| `POST /v1/observe` | direct | A dedicated observer's report of one day |
| `POST /v1/observer` | direct | Which observer a code is, and its last report |
| `GET /v1/released/observers` | direct | Days of the observers' table |
| `GET /v1/released/observers/<YYYY-MM-DD>` | direct | One day of it: every item, no threshold |
| `GET /` | direct | Web page: the collection, and how to get a code |
| `POST /enroll/mail` | direct | Form `email=`: a code by e-mail (when `--smtp-url` is set) |
| `GET /enroll/github`, `GET /enroll/github/callback` | direct | A code with a GitHub account (OAuth, no scope) |
| `POST /enroll/network` | direct | A code for a visitor from `--enroll-networks` |

Inside OHTTP, requests are Binary HTTP (RFC 9292), known-length mode, with
authority `peersig`. The gateway key (key id 1, DHKEM X25519-SHA256,
HKDF-SHA256 with AES-128-GCM or ChaCha20-Poly1305) is derived from a seed
stored by the server, so it survives restarts.

## Enrollment

A code is 60 random bits (`K7QF-2M9D-XW4P`); the server stores
`SHA-256("peersig-code:" ‖ normalized code)` and a label. Codes come from
`peersig-server codes add`, or from the web page:

- by e-mail: the server sends the code to the address. The identity is the
  address, lower case, without a `+tag`;
- with GitHub: the browser goes to GitHub's authorization page with no
  scope and a `state` the server MACs (valid 10 minutes); on the way back
  the server exchanges the code for a token, reads `GET /user` (`id`,
  `created_at`) and drops the token. The identity is the account id;
  accounts younger than `--github-min-age-days` are refused;
- from a network: the server checks the client's address against the
  blocks (the connection's address, or, from a proxy on the same machine,
  the last entry of `--client-address-header`). No identity is kept, and
  no per-identity limit applies.

The server stores `HMAC-SHA256(enroll-key, kind ":" identity)` with a count,
and refuses a code when the count reaches `--codes-per-identity`. Labels
are `M<n>` (e-mail), `G<n>` (GitHub) and `N<n>` (network). The page hands out at most
`--enroll-per-hour` codes per hour, and one message per address every ten
minutes; it answers the same whether or not an address had codes already.

## Tokens

RSABSSA-SHA384-PSS-Randomized (RFC 9474) with a 2048-bit key per epoch. The
signed message is `"peersig/v1/ballot" ‖ epoch (u32, big endian) ‖ nonce
(32 random bytes)`.

```text
app                                             server
 config (OHTTP) -> token_key(report_epoch)
 blind N nonces                 IssueRequest{code, epoch, blinded[N]} ->
                                                 check code, N + issued ≤ budget
                               <- IssueResponse{key_id, signatures[N]}
 finalize: unblind, verify each against token_key
```

`Token { epoch, nonce, randomizer, signature }`. The server keeps spent
`(epoch, nonce)` pairs; a second use returns 409, which the app treats as
already sent.

## Ballots

`Ballot { item, token }`, one per request. `item` is one of:

```json
{"type":"hello","os":"macos 27","transport":"quic","ja4":"q13d0311h3_55b375c5d22e_5a1f323ef56d",
 "app":{"name":"Google Chrome","id":"com.google.Chrome","version":"157.0.8103.51","team_id":"EQHXZ8M8AV",
        "kind":"browser","engine":"chromium 157.0.8103.51"}}
{"type":"domain","os":"macos 27","app":{"name":"Microsoft Teams","id":"com.microsoft.teams2","kind":"app"},
 "domain":"teams.microsoft.com","ja4":"t13d1516h2_8daaf6152771_806a8c22fdea"}
{"type":"presence","shares_domains":true}
```

The server parses the item (unknown fields are rejected), validates it
(`Item::validate`), and counts its canonical serialization.

Before the review, the app merges items that are equal except for a detail
(`crates/proto/src/merge.rs`), when there are two or more of them. A
version number with three components or more, in `app.name`,
`app.version` or `app.engine`, keeps major.minor and ends in `*`
(`2.1.322` and `2.1.326` give `2.1.*`). In a domain, a run of a digit then
hex digits left of the last two labels becomes `*` (`p177-fmip.icloud.com`
and `p63-fmip.icloud.com` give `p*-fmip.icloud.com`). Merged items validate
like any other; `normalize_domain` keeps a label with a `*` unless what is
left of it looks random. Servers before this change (0.1.4 and earlier)
refuse such a label.

## A week, from the app's side

1. At the start of epoch *c*, open the report of *c − 1* for review, with
   near-identical items merged (see Ballots). An item the participant
   removes is never merged into another.
2. After the review: fetch the config through OHTTP; build the ballots
   (`plan::plan`): every item the participant kept, once, and one presence
   ballot, shuffled, capped at the budget.
3. Ask for exactly `tokens_per_epoch` tokens; check each signature against
   the anonymously fetched key.
4. Schedule each ballot at a uniform random time over the spread window,
   and send them one per OHTTP request.

## Dedicated observers

An observer's code is `OBS-` and a participant's code form
(`OBS-K7QF-2M9D-XW4P`); the server marks it as an observer's in `codes`.
Observer days are `EpochSpec::days()`: one day (86 400 s) from the epochs'
origin, midnight UTC. During day *d*, an observer reports day *d − 1*;
days down to *d − 7* are still accepted.

```text
observer                                         server
 config (OHTTP) -> epochs.origin
 ObserverReport{code, day, items[]}  ->           code is an active observer's,
                                                  day in [today − 7, today − 1],
                                                  items valid, not empty, no presence;
                                                  count once per (code, day)
                                    <- 200 ObserverReceipt{label, day, items}
                                       409 if that observer reported that day
```

At most 10 000 items per report (8 MiB). The server counts each distinct
item once per observer: `observed(day, item, n)`, and
`observer_days(code hash, day, items)`. `POST /v1/issue` refuses observer
codes and `POST /v1/observe` participants' codes.

`POST /v1/observer` with `{"code": "OBS-…"}` answers
`{"label": "O03", "days": 12, "last_day": "2026-11-17"}` for an active
observer's code, and 403 for any other (as `/v1/observe` does).
`peersig-observer configure` and `status` use it.

`GET /v1/released/observers` returns
`{"days": [{"day": "2026-11-17", "observers": 3, "items": 412}, …]}`, most
recent first; `GET /v1/released/observers/2026-11-17` returns
`{"day", "observers", "items": [{"item", "observers"}]}`.

## Release

For each item and epoch, the count. Support = maximum over epochs.
Released when support ≥ k (`k_hello`, `k_domain`), with the support. Only
epochs before the current report epoch count.
