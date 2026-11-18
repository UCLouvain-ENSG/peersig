# Privacy design

PeerSig collects *(fingerprint, application)* pairs from volunteers. The pairs
themselves describe software, not people. What could describe a person is
**who** runs **which** software, and which names their applications contact.
The design keeps that from the study's operators, as far as the scale of a
study allows. This page says what each party learns, and where the limits
are.

## Parties

- **Participant**: runs the probe (capture, root on macOS, a LocalSystem
  service on Windows) and the app (user level, the only part that uses the
  network).
- **Server**: run by the study. Enrolls participants, issues tokens, counts
  ballots, publishes results.
- **Relay**: run by someone else (another lab, the data protection officer,
  a commercial OHTTP relay). Forwards encrypted requests.
- For enrollment from the web page, the **mail system** that delivers the
  code, or **GitHub** if the participant signs in with it.
- **Dedicated observers**: machines run for the study, with an observer
  code from the study team. They are not participants and do not get the
  protections below: see [Dedicated observers](#dedicated-observers).

## What leaves the computer

Items (`crates/proto/src/item.rs`), at most once per item and week:

- `hello`: OS family and major version (`macos 27`, `windows 11`), transport (tcp, quic,
  dtls), JA4, an earlier non-standard JA4 (`ja4_legacy`), and the
  application: name, bundle id, version, code-signing team, kind (browser,
  app, system, cli), engine.
- `domain` (opt-in): the same application fields without version, a server
  name it put in a ClientHello (SNI), and the JA4 of that ClientHello: what
  anyone on the network path sees together. Never for browsers. Only SNI:
  names seen only in DNS answers or plain HTTP stay on the computer. Names
  under `.local`, `.lan`, `.arpa`, `.internal`, IP literals and single
  labels are dropped; random-looking labels (CDN shards, hashes) are
  replaced by `*`.
- `presence`: "one participant reported this week", and whether it shares
  domains.

Before the review, items that differ only in a detail are merged, with the
detail replaced by `*`: the components after major.minor of a version
(in the name, version or engine: `2.1.322` and `2.1.326` give `2.1.*`),
and in a server name, a run of a digit then hex digits left of the last
two labels (`p177-fmip.icloud.com` and `p63-fmip.icloud.com` give
`p*-fmip.icloud.com`). Only items equal in everything else merge, and
only two or more; an item the participant removed stays out of merges.

Item parsing refuses unknown fields, so a ballot cannot carry more than
this. Handshakes with no identified application are not sent.

## Layers

### 0. Enrollment

Only enrolled participants get tokens. Enrollment is what keeps the
collection closed: without it, anyone on the internet could flood it with
made-up ballots. It does not identify ballots (layer 2).

The study team can hand out codes (`codes add`), or participants can get
one from the server's web page:

- **By e-mail.** The server sends the code to the address given. It keeps a
  keyed hash of the address (HMAC, with a key stored in the database) and
  how many codes it got, so that one address gets at most three (one per
  computer). It does not keep the address, and nothing links the hash to
  the code. Plus-tags are folded (`alice+x@` counts as `alice@`).
- **With GitHub.** GitHub's sign-in page asks for no permission: the server
  only reads the account's number and creation date (accounts younger than
  30 days are refused, against throwaway accounts). The server keeps a
  keyed hash of the number, as above, and drops GitHub's token at once. The
  code is shown once.
- **From the institution's network** (UCLouvain's, on campus or through its
  VPN). One click: the server checks that the connection's address is in
  the network's blocks, then forgets it; it keeps nothing about the visitor,
  not even a hash. The reverse proxy passes the address for that request
  only. The code is shown once.

The page hands out a limited number of codes per hour, and gives the same
answer whether or not an address had codes already, so it cannot be used
to test addresses.

Against spam, one client address can ask for a code by e-mail or GitHub
only a few times an hour (`--enroll-per-address`, 5). The server counts
those requests in memory, under a hash of the address's /32 (IPv4) or /64
(IPv6) keyed with a random key that is replaced, with the counts, every
hour. It writes nothing and logs nothing about the address, and after the
hour even the server cannot tell which counts were whose. The reverse
proxy passes the client's address on `/enroll/` only. Network enrollment
is not counted: its visitors often share an address.

The study team's admin page (GitHub sign-in, for the accounts the server
lists) creates, lists and revokes codes, like the command line, and can ban
an e-mail address, a mail domain or a GitHub account from getting codes.
A banned address or account is stored as the same keyed hash as above, a
domain in clear. A banned address gets the usual answer and no message.
Banning cannot reach codes already handed out, since nothing links them
to an address or account, and there is no ban by network address: the
server keeps none.

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

Ballots, and the configuration request, are encrypted to the
server's gateway key (RFC 9458, X25519 + AES-128-GCM) and posted to the
relay. The relay sees the participant's address and an opaque blob; the
server sees the request, coming from the relay's address. The app fetches
the gateway key both directly and through the relay and refuses to send if
they differ, so neither can substitute a key.

Ballots are sent one per request, at random times spread over two hours.

### 4. Counts only

The server stores one counter per *(week, item)*. It does not store ballots,
arrival times or request metadata. Tables are `WITHOUT ROWID`, the journal
is not a WAL and deleted pages are zeroed, so the database file does not
keep the order in which ballots arrived. Spent token nonces are random. The
server never logs request addresses.

### 5. Release thresholds

An item's support is its largest per-week count: the same participant three
weeks in a row cannot be told from three participants, so this is a lower
bound on distinct participants. An item is released only once its support
reaches *k* (3 for hello items, 5 for domains), with that support.

## Dedicated observers

An observer code (`OBS-…`, made only with `codes add --observer` on the
server) turns a machine into a dedicated observer
([observers.md](observers.md)). Its items are the same as a participant's,
but:

- each day's items go in **one report, with the code**, straight to the
  server: the server knows which observer sent which items. It keeps one
  counter per (day, item) and which observer reported which day, not the
  reports;
- each day is **published without threshold**, with the number of
  observers that reported each item;
- the app joins as an observer only with such a code, says so before
  joining, and has no review by default.

Observers are kept apart from participants: an observer code gets no
ballot tokens, a participant's code cannot send an observer report, and
observer counts never enter the participants' counts. So observers
cannot push a participant's rare item over *k*, nor make its support say
more than the participants' ballots do. Use observer codes only on
machines whose traffic may be published, never on someone's own
computer.

## What each party learns

| | Server | Relay | Someone with the database file |
| --- | --- | --- | --- |
| Who is enrolled, who took part which week | yes | no | yes (as code hashes and labels) |
| A participant's e-mail address or GitHub account (web enrollment) | while sending the code | no | can test a guess |
| A participant's address | at issuance, and at enrollment from the network | yes | no |
| Which items a participant has | no | no | no |
| Which ballots come from one person | no (see limits) | no | no |
| Per-week item counts | yes | no | yes |
| An observer's items, per day | yes (published) | no | yes (counts) |

## Limits

- **Collusion.** If the relay and the server collude, they can match
  ballots to addresses by timing. Choose a relay operator independent of the
  study.
- **No relay.** Without a relay, the server sees the participant's address
  on each ballot. The app warns about this.
- **Relay on the server's machine.** A relay run by the server's operator,
  or on the same machine, protects nothing against that operator: it is
  collusion by construction. Acceptable for a pilot; move the relay to an
  independent party before a real collection.
- **Web enrollment.** The mail system's logs hold the address and the time
  the message left, and the codes table holds the day each code was made:
  together, they can tell the server's operator which label is whose, and
  so which weeks that person took part. That is what the study team knows
  anyway about codes it hands out; it does not reach the ballots. Someone
  with the database file has the key of the identity hashes, and can check
  whether a given address or GitHub account enrolled. GitHub knows its user
  signed in to PeerSig.
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
  after 14 days. On Windows they are in `%ProgramData%\PeerSig\logs`,
  readable by the participant and by the computer's administrators (as
  root can read them on macOS).
- **Windows app names.** Windows has no bundle ids: an application is
  named by its executable's version resource (product name and version),
  an MSIX app by its package, a Windows service host by its service name.
  These are the same fields as on macOS (`name`, `id`, `version`, `kind`,
  `engine`); `team_id` stays empty.
- **No noise.** Released supports are exact counts, and nothing hides
  whether a ballot is real: the protection is that ballots are unlinkable
  and that only items reported by *k* participants are published. A ballot
  for a rare item still says that some participant has it.

## Future plans

- **Differential privacy.** An earlier design had randomized response on
  items the server already knew (local DP) and Laplace noise on published
  counts (central DP). It was removed: the ε of randomized response is per
  item and week, and composes over a whole report and over months into a
  weak guarantee; and noise drawn again at each weekly release averages out
  across releases. A sound version needs a privacy budget accounted over
  the whole study (for instance a single noisy release per item, or noise
  that is drawn once and kept), and enough participants for the noise not
  to drown the signal.
- **An independent relay**, run by a party other than the study.
