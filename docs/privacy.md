# Privacy design

PeerSig collects *(fingerprint, application)* pairs from volunteers. The pairs
themselves describe software, not people. What could describe a person is
**who** runs **which** software, and which names their applications contact.
The design keeps that from the study's operators, as far as the scale of a
study allows. This page says what each party learns, and where the limits
are.

## Parties

- **Participant**: runs the probe (capture, root on macOS) and the app (user
  level, the only part that uses the network).
- **Server**: run by the study. Enrolls participants, issues tokens, counts
  ballots, publishes results.
- **Relay**: run by someone else (another lab, the data protection officer,
  a commercial OHTTP relay). Forwards encrypted requests.

## What leaves the computer

Items (`crates/proto/src/item.rs`), at most once per item and week:

- `hello`: OS family and major version (`macos 27`), transport (tcp, quic,
  dtls), JA4, the JA4 Iris stored before its fix (`ja4_legacy`), and the
  application: name, bundle id, version, code-signing team, kind (browser,
  app, system, cli), engine.
- `domain` (opt-in): the same application fields without version, and a name
  it contacted. Never for browsers. Names under `.local`, `.lan`, `.arpa`,
  `.internal`, IP literals and single labels are dropped; random-looking
  labels (CDN shards, hashes) are replaced by `*`.
- `presence`: "one participant reported this week", and whether it shares
  domains.

Item parsing refuses unknown fields, so a ballot cannot carry more than
this. Handshakes with no identified application are not sent.

## Layers

### 1. Review and consent

The app opens each week's report in *review* for 24 hours (configurable),
with a notification. The participant sees every item, with local-only
details (how often, which processes), and can untick any of them: an
unticked item is never sent, that week or later. Nothing is sent while the
app is not running, and the tray icon changes while ballots are being sent.

### 2. Unlinkable ballots (blind signatures)

Each item is sent as a separate ballot carrying a token: a random nonce with
an RSA blind signature (RFC 9474, RSABSSA-SHA384-PSS-Randomized). To get
tokens, the app sends blinded nonces with the participant's enrollment code;
the server signs without seeing the nonces. When a ballot arrives, the
server checks the signature and that the nonce is unspent, but cannot tell
which issuance it came from. This is the standard anonymous-voting
construction: eligibility is checked, identity is not learned.

- Every participant asks for the **same number of tokens** each week (512 by
  default), whatever they will send, so issuance does not reveal how much a
  participant has.
- Each week has its own signing key. The app fetches it anonymously
  (through the relay) before asking for signatures, and checks every
  signature against it. A server signing one participant's tokens with a
  dedicated key, to recognise their ballots, would be detected.
- The server learns who took part in which week (issuance). That is needed
  to pay participants; it is not linked to any ballot.

### 3. Oblivious HTTP

Ballots, and the configuration and catalogue requests, are encrypted to the
server's gateway key (RFC 9458, X25519 + AES-128-GCM) and posted to the
relay. The relay sees the participant's address and an opaque blob; the
server sees the request, coming from the relay's address. The app fetches
the gateway key both directly and through the relay and refuses to send if
they differ, so neither can substitute a key.

Ballots are sent one per request, at random times spread over two hours.

### 4. Randomized response on known items

The *catalogue* of an epoch is the set of items already released, frozen
when the epoch's reporting starts. For each catalogue item, the app reports
it with probability *p* if it saw it, and with probability *1 − p* if it did
not (a decoy). With *p* = 0.9, ε = ln 9 ≈ 2.2 per item and week: no single
ballot proves that the participant uses that application. The server
estimates counts as (observed − n(1 − p)) / (2p − 1), with *n* the number of
presence ballots.

Items not in the catalogue (new applications, new versions) are sent as
they are. They are protected by the other layers, not by noise. With a few
dozen participants, local DP on new items would drown every signal.

### 5. Counts only

The server stores one counter per *(week, item)*. It does not store ballots,
arrival times or request metadata. Tables are `WITHOUT ROWID`, the journal
is not a WAL and deleted pages are zeroed, so the database file does not
keep the order in which ballots arrived. Spent token nonces are random. The
server never logs request addresses.

### 6. Release thresholds and central DP

An item's support is its largest per-week count: the same participant three
weeks in a row cannot be told from three participants, so this is a lower
bound on distinct participants. Laplace noise (scale 1/ε, ε = 1 by default)
is added, and the item is released only if the noisy support reaches *k*
(3 for hello items, 5 for domains). Released counts are rounded noisy
values. The noise is drawn per item and release from a keyed hash, so asking
twice gives the same answer.

## What each party learns

| | Server | Relay | Someone with the database file |
| --- | --- | --- | --- |
| Who is enrolled, who took part which week | yes | no | yes (as code hashes and labels) |
| A participant's address | at issuance only | yes | no |
| Which items a participant has | no | no | no |
| Which ballots come from one person | no (see limits) | no | no |
| Per-week item counts | yes | no | yes |

## Limits

- **Collusion.** If the relay and the server collude, they can match
  ballots to addresses by timing. Choose a relay operator independent of the
  study.
- **No relay.** Without a relay, the server sees the participant's address
  on each ballot. The app warns about this.
- **Small anonymity sets.** With 20 participants, a ballot is anonymous
  among 20. A ballot for a rare application, sent during the same two-hour
  window as one participant's issuance, narrows it further. Random spreading
  helps; a larger study helps more.
- **Rare items reach the server.** New items are counted even if a single
  participant has them. The threshold only governs what is **published**:
  the server operator can read below-threshold counts. Treat the database
  as confidential.
- **Versions as quasi-identifiers.** A rare application at a rare version
  points to few people. Participants can untick such items during review.
- **Poisoning.** A participant can send up to the token budget per week of
  arbitrary items. Thresholds limit the effect on what is released.
- **Local logs.** The probe's logs hold server names and addresses. They
  stay on the computer, readable by the participant only, and are deleted
  after 14 days.
- **Composition.** The ε of randomized response is per item and week. Over
  a whole report (many items) and many weeks, privacy loss adds up, as it
  does for any repeated measurement.
