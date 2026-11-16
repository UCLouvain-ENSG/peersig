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
| `GET /v1/catalogue/{epoch}` | OHTTP | Frozen catalogue of an epoch |
| `POST /v1/ballot` | OHTTP only | One ballot |
| `GET /v1/released` | OHTTP or direct | Released items with noisy support |
| `POST /v1/issue` | direct | Token issuance, authenticated by the enrollment code |
| `GET /` | direct | Human-readable description of the collection |

Inside OHTTP, requests are Binary HTTP (RFC 9292), known-length mode, with
authority `peersig`. The gateway key (key id 1, DHKEM X25519-SHA256,
HKDF-SHA256 with AES-128-GCM or ChaCha20-Poly1305) is derived from a seed
stored by the server, so it survives restarts.

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
 "domain":"teams.microsoft.com"}
{"type":"presence","shares_domains":true}
```

The server parses the item (unknown fields are rejected), validates it
(`Item::validate`), and counts its canonical serialization.

## A week, from the app's side

1. At the start of epoch *c*, open the report of *c − 1* for review.
2. After the review: fetch the config and the catalogue of *c − 1* through
   OHTTP; build the ballots (`plan::plan`): randomized response over the
   catalogue, every non-catalogue item, one presence ballot, shuffled,
   capped at the budget.
3. Ask for exactly `tokens_per_epoch` tokens; check each signature against
   the anonymously fetched key.
4. Schedule each ballot at a uniform random time over the spread window,
   and send them one per OHTTP request.

## Release

For each item and epoch: the count, debiased if the item was in that
epoch's catalogue (with *n* = presence ballots, or presence ballots sharing
domains for domain items). Support = maximum over epochs. Released when
support + Laplace(1/ε_central) ≥ k. The catalogue of epoch *e* is the
release computed from epochs before *e*, frozen the first time it is asked
for, together with the randomized-response parameter in force.
