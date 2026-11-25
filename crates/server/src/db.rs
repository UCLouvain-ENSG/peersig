//! Storage. What the server keeps, and what it does not:
//!
//! - `codes`: the hash of each enrollment code and a label (e.g. "P07")
//!   to pay participants. Not the code itself.
//! - `issuance`: tokens issued per code and epoch: who took part when.
//!   Nothing links it to ballots.
//! - `spent`: spent token nonces (random), against double spending.
//! - `counts`: one counter per (epoch, item). Ballots are not stored, nor
//!   when they arrived, nor from where. Tables are WITHOUT ROWID, the
//!   journal is not a WAL and deleted pages are zeroed, so the file does
//!   not keep the order ballots arrived in.
//! - `identities`: for codes handed out by the web page, a keyed hash of
//!   the e-mail address or GitHub account and how many codes it holds
//!   against its limit: one fewer each week, for every row at once. Not
//!   the address, not which code, not when.
//! - `bans`: e-mail addresses and GitHub accounts refused a code, as the
//!   same keyed hash, and mail domains, in clear; the admin's note and the
//!   day. Never a network address.
//! - `token_keys`, `meta`: the keys and the epoch layout.
//!
//! Dedicated observers (codes with `observer = 1`, made only with
//! `codes add --observer`) are kept apart from participants:
//!
//! - `observer_days`: which observer reported which day, and how many
//!   items. Like `issuance`, it says who took part when.
//! - `observed`: one counter per (day, item): how many observers reported
//!   it. Their reports are not stored either. These counts never mix with
//!   `counts`, so observers never help a participant's item over k.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use peersig_proto::{code, Class, Item};

pub const SCHEMA: &str = "
PRAGMA journal_mode = DELETE;
PRAGMA secure_delete = ON;
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS codes(hash TEXT PRIMARY KEY, label TEXT NOT NULL, created TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS issuance(hash TEXT NOT NULL, epoch INTEGER NOT NULL, tokens INTEGER NOT NULL,
    PRIMARY KEY(hash, epoch)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS token_keys(epoch INTEGER PRIMARY KEY, secret BLOB NOT NULL, public BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS spent(epoch INTEGER NOT NULL, nonce BLOB NOT NULL, PRIMARY KEY(epoch, nonce)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS counts(epoch INTEGER NOT NULL, item TEXT NOT NULL, class TEXT NOT NULL, n INTEGER NOT NULL,
    PRIMARY KEY(epoch, item)) WITHOUT ROWID;
-- Randomized response is gone: so are its catalogue snapshots.
DROP TABLE IF EXISTS frozen;
DROP TABLE IF EXISTS catalogue;
CREATE TABLE IF NOT EXISTS identities(hash TEXT PRIMARY KEY, codes INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bans(kind TEXT NOT NULL, value TEXT NOT NULL, note TEXT NOT NULL, created TEXT NOT NULL,
    PRIMARY KEY(kind, value)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS observer_days(hash TEXT NOT NULL, day INTEGER NOT NULL, items INTEGER NOT NULL,
    PRIMARY KEY(hash, day)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS observed(day INTEGER NOT NULL, item TEXT NOT NULL, class TEXT NOT NULL, n INTEGER NOT NULL,
    PRIMARY KEY(day, item)) WITHOUT ROWID;
";

/// Columns added after a release, for databases made before.
fn migrate(c: &Connection) -> Result<()> {
    let has = |table: &str, col: &str| -> Result<bool> {
        let mut st = c.prepare(&format!("PRAGMA table_info({})", table))?;
        let cols: Vec<String> = st.query_map([], |r| r.get::<_, String>(1))?.collect::<Result<_, _>>()?;
        Ok(cols.iter().any(|x| x == col))
    };
    if !has("codes", "observer")? {
        c.execute_batch("ALTER TABLE codes ADD COLUMN observer INTEGER NOT NULL DEFAULT 0")?;
    }
    Ok(())
}

pub fn open(path: &str) -> Result<Connection> {
    let mut c = Connection::open(path).with_context(|| path.to_string())?;
    c.execute_batch(SCHEMA)?;
    migrate(&c)?;
    canonical_keys(&mut c)?;
    Ok(c)
}

/// Counters stored under a key that is no longer their item's (a field
/// older apps sent, which `Item` now drops) are added to the item's current
/// key: the same item is counted once, not split in two below k.
fn canonical_keys(c: &mut Connection) -> Result<()> {
    let tx = c.transaction()?;
    for (table, period) in [("counts", "epoch"), ("observed", "day")] {
        let rows: Vec<(i64, String, i64)> = {
            let mut st = tx.prepare(&format!("SELECT {period}, item, n FROM {table}"))?;
            let rows = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?;
            rows
        };
        for (p, key, n) in rows {
            let Some(item) = Item::from_key(&key) else { continue };
            let current = item.key();
            if current == key {
                continue;
            }
            tx.execute(&format!("DELETE FROM {table} WHERE {period} = ?1 AND item = ?2"), params![p, key])?;
            tx.execute(
                &format!(
                    "INSERT INTO {table}({period}, item, class, n) VALUES(?1, ?2, ?3, ?4)
                     ON CONFLICT({period}, item) DO UPDATE SET n = n + excluded.n"
                ),
                params![p, current, item.class().name(), n],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn meta_get(c: &Connection, k: &str) -> Result<Option<Vec<u8>>> {
    Ok(c.query_row("SELECT v FROM meta WHERE k = ?1", [k], |r| r.get(0)).optional()?)
}

pub fn meta_set(c: &Connection, k: &str, v: &[u8]) -> Result<()> {
    c.execute("INSERT INTO meta(k, v) VALUES(?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v", params![k, v])?;
    Ok(())
}

/// A random secret stored under `k`, created on first use.
pub fn secret(c: &Connection, k: &str) -> Result<Vec<u8>> {
    if let Some(v) = meta_get(c, k)? {
        return Ok(v);
    }
    let mut v = vec![0u8; 32];
    rand::fill(&mut v[..]);
    meta_set(c, k, &v)?;
    Ok(v)
}

// ---- enrollment codes ----

/// Codes look like `K7QF-2M9D-XW4P`: 60 random bits, Crockford base32.
pub fn new_code() -> String {
    const A: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut b = [0u8; 12];
    rand::fill(&mut b[..]);
    let s: String = b.iter().map(|x| A[(*x & 31) as usize] as char).collect();
    format!("{}-{}-{}", &s[0..4], &s[4..8], &s[8..12])
}

/// A dedicated observer's code: `OBS-K7QF-2M9D-XW4P`.
pub fn new_observer_code() -> String {
    format!("{}-{}", code::OBSERVER_PREFIX, new_code())
}

pub fn normalize_code(code: &str) -> String {
    code::normalize(code)
}

pub fn code_hash(code: &str) -> String {
    peersig_proto::short_hash(format!("peersig-code:{}", normalize_code(code)).as_bytes(), 32)
}

pub fn add_code(c: &Connection, code: &str, label: &str) -> Result<()> {
    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
    c.execute("INSERT INTO codes(hash, label, created) VALUES(?1, ?2, ?3)", params![code_hash(code), label, day])?;
    Ok(())
}

/// A dedicated observer's code (`new_observer_code`).
pub fn add_observer_code(c: &Connection, code: &str, label: &str) -> Result<()> {
    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
    c.execute("INSERT INTO codes(hash, label, created, observer) VALUES(?1, ?2, ?3, 1)", params![code_hash(code), label, day])?;
    Ok(())
}

/// Active code -> true; revoked -> false; unknown -> None.
pub fn code_active(c: &Connection, hash: &str) -> Result<Option<bool>> {
    Ok(code_status(c, hash)?.map(|s| s.active))
}

pub struct CodeStatus {
    pub label: String,
    pub active: bool,
    pub observer: bool,
}

/// None for an unknown code.
pub fn code_status(c: &Connection, hash: &str) -> Result<Option<CodeStatus>> {
    Ok(c.query_row("SELECT label, revoked, observer FROM codes WHERE hash = ?1", [hash], |r| {
        Ok(CodeStatus { label: r.get(0)?, active: r.get::<_, i64>(1)? == 0, observer: r.get::<_, i64>(2)? != 0 })
    })
    .optional()?)
}

pub fn revoke(c: &Connection, code_or_label: &str) -> Result<usize> {
    set_revoked(c, code_or_label, true)
}

/// Revokes, or restores, a code (by code or label). Returns how many.
pub fn set_revoked(c: &Connection, code_or_label: &str, revoked: bool) -> Result<usize> {
    Ok(c.execute(
        "UPDATE codes SET revoked = ?3 WHERE hash = ?1 OR label = ?2",
        params![code_hash(code_or_label), code_or_label, revoked as i64],
    )?)
}

/// `count` new codes labelled `<prefix><n>`, n counting all codes, as
/// (label, code). The codes are returned once: only their hash is stored.
pub fn add_codes(c: &mut Connection, count: u32, prefix: &str) -> Result<Vec<(String, String)>> {
    let tx = c.transaction()?;
    let existing: u32 = tx.query_row("SELECT COUNT(*) FROM codes", [], |r| r.get(0))?;
    let mut out = Vec::new();
    for i in 0..count {
        let code = new_code();
        let label = format!("{}{:02}", prefix, existing + i + 1);
        add_code(&tx, &code, &label)?;
        out.push((label, code));
    }
    tx.commit()?;
    Ok(out)
}

/// `count` new observer codes (`OBS-…`), labelled `<prefix><n>`, n
/// counting observers only (O01, O02…). Returns (label, code) pairs.
pub fn add_observer_codes(c: &mut Connection, count: u32, prefix: &str) -> Result<Vec<(String, String)>> {
    let tx = c.transaction()?;
    let existing: u32 = tx.query_row("SELECT COUNT(*) FROM codes WHERE observer = 1", [], |r| r.get(0))?;
    let mut out = Vec::new();
    for i in 0..count {
        let code = new_observer_code();
        let label = format!("{}{:02}", prefix, existing + i + 1);
        add_observer_code(&tx, &code, &label)?;
        out.push((label, code));
    }
    tx.commit()?;
    Ok(out)
}

/// A new code labelled `<prefix><n>`, n counting all codes. Returns (code, label).
pub fn add_labelled_code(c: &Connection, prefix: &str) -> Result<(String, String)> {
    let total: u32 = c.query_row("SELECT COUNT(*) FROM codes", [], |r| r.get(0))?;
    let code = new_code();
    let label = format!("{}{:02}", prefix, total + 1);
    add_code(c, &code, &label)?;
    Ok((code, label))
}

/// A new code for `identity` (a keyed hash), labelled `<prefix><n>`, if
/// it holds fewer than `cap` codes. Returns (code, label). Each week the
/// count drops by one (`renew_identities`): `cap` codes at once, then one
/// more a week, for a lost code or a new device.
pub fn enroll(c: &mut Connection, identity: &str, prefix: &str, cap: u32, now: i64) -> Result<Option<(String, String)>> {
    let tx = c.transaction()?;
    renew_identities(&tx, now)?;
    let had: u32 = tx.query_row("SELECT codes FROM identities WHERE hash = ?1", [identity], |r| r.get(0)).optional()?.unwrap_or(0);
    if had >= cap {
        return Ok(None);
    }
    let (code, label) = add_labelled_code(&tx, prefix)?;
    tx.execute(
        "INSERT INTO identities(hash, codes) VALUES(?1, 1) ON CONFLICT(hash) DO UPDATE SET codes = codes + 1",
        [identity],
    )?;
    tx.commit()?;
    Ok(Some((code, label)))
}

/// Weeks since 1970, starting on Mondays (UTC).
pub fn week(t: i64) -> i64 {
    (t + 3 * 86400).div_euclid(7 * 86400)
}

/// Every identity's count drops by one for each week begun since the
/// last time (rows reaching zero go), all at once: one week number for the
/// whole table, in `meta`, so nothing says when an identity got its codes.
fn renew_identities(c: &Connection, now: i64) -> Result<()> {
    let w = week(now);
    let last = meta_get(c, "identities-week")?.and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok()).map(i64::from_le_bytes);
    match last {
        Some(l) if l >= w => return Ok(()),
        Some(l) => {
            c.execute("UPDATE identities SET codes = codes - ?1", [w - l])?;
            c.execute("DELETE FROM identities WHERE codes <= 0", [])?;
        }
        None => {}
    }
    meta_set(c, "identities-week", &w.to_le_bytes())
}

/// Undoes [`enroll`] when the code could not be delivered.
pub fn unenroll(c: &mut Connection, identity: &str, code: &str) -> Result<()> {
    let tx = c.transaction()?;
    tx.execute("DELETE FROM codes WHERE hash = ?1", [code_hash(code)])?;
    tx.execute("UPDATE identities SET codes = codes - 1 WHERE hash = ?1", [identity])?;
    tx.execute("DELETE FROM identities WHERE hash = ?1 AND codes <= 0", [identity])?;
    tx.commit()?;
    Ok(())
}

pub struct CodeRow {
    pub label: String,
    pub created: String,
    pub revoked: bool,
    pub observer: bool,
    /// Participant: epoch -> tokens issued. Observer: day -> items reported.
    pub epochs: BTreeMap<u32, u32>,
}

pub fn list_codes(c: &Connection) -> Result<Vec<CodeRow>> {
    let mut st = c.prepare("SELECT hash, label, created, revoked, observer FROM codes ORDER BY label")?;
    let rows: Vec<(String, String, String, i64, i64)> =
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for (hash, label, created, revoked, observer) in rows {
        let q = if observer != 0 {
            "SELECT day, items FROM observer_days WHERE hash = ?1"
        } else {
            "SELECT epoch, tokens FROM issuance WHERE hash = ?1"
        };
        let mut q = c.prepare(q)?;
        let epochs = q.query_map([&hash], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?)))?.collect::<Result<_, _>>()?;
        out.push(CodeRow { label, created, revoked: revoked != 0, observer: observer != 0, epochs });
    }
    Ok(out)
}

// ---- bans ----

/// What a ban is on: `mail` and `github` hold the keyed hash of
/// `enroll::identity`, `domain` a mail domain.
pub const BAN_KINDS: [&str; 3] = ["mail", "domain", "github"];

pub struct BanRow {
    pub kind: String,
    pub value: String,
    pub note: String,
    pub created: String,
}

pub fn add_ban(c: &Connection, kind: &str, value: &str, note: &str) -> Result<()> {
    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
    c.execute(
        "INSERT INTO bans(kind, value, note, created) VALUES(?1, ?2, ?3, ?4)
         ON CONFLICT(kind, value) DO UPDATE SET note = excluded.note",
        params![kind, value, note, day],
    )?;
    Ok(())
}

pub fn remove_ban(c: &Connection, kind: &str, value: &str) -> Result<usize> {
    Ok(c.execute("DELETE FROM bans WHERE kind = ?1 AND value = ?2", params![kind, value])?)
}

pub fn banned(c: &Connection, kind: &str, value: &str) -> Result<bool> {
    Ok(c.query_row("SELECT 1 FROM bans WHERE kind = ?1 AND value = ?2", params![kind, value], |_| Ok(())).optional()?.is_some())
}

pub fn list_bans(c: &Connection) -> Result<Vec<BanRow>> {
    let mut st = c.prepare("SELECT kind, value, note, created FROM bans ORDER BY created, kind, value")?;
    let rows = st.query_map([], |r| Ok(BanRow { kind: r.get(0)?, value: r.get(1)?, note: r.get(2)?, created: r.get(3)? }))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

pub fn issued(c: &Connection, hash: &str, epoch: u32) -> Result<u32> {
    Ok(c.query_row("SELECT tokens FROM issuance WHERE hash = ?1 AND epoch = ?2", params![hash, epoch], |r| r.get(0))
        .optional()?
        .unwrap_or(0))
}

pub fn add_issued(c: &Connection, hash: &str, epoch: u32, n: u32) -> Result<()> {
    c.execute(
        "INSERT INTO issuance(hash, epoch, tokens) VALUES(?1, ?2, ?3)
         ON CONFLICT(hash, epoch) DO UPDATE SET tokens = tokens + excluded.tokens",
        params![hash, epoch, n],
    )?;
    Ok(())
}

// ---- token keys ----

pub fn token_key(c: &Connection, epoch: u32) -> Result<Option<Vec<u8>>> {
    Ok(c.query_row("SELECT secret FROM token_keys WHERE epoch = ?1", [epoch], |r| r.get(0)).optional()?)
}

pub fn put_token_key(c: &Connection, epoch: u32, secret: &[u8], public: &[u8]) -> Result<()> {
    c.execute("INSERT OR IGNORE INTO token_keys(epoch, secret, public) VALUES(?1, ?2, ?3)", params![epoch, secret, public])?;
    Ok(())
}

// ---- ballots ----

pub enum Spend {
    Counted,
    AlreadySpent,
}

/// Spends the token and counts the item, atomically.
pub fn count_ballot(c: &mut Connection, epoch: u32, nonce: &[u8], item: &Item) -> Result<Spend> {
    let tx = c.transaction()?;
    let fresh = tx.execute("INSERT OR IGNORE INTO spent(epoch, nonce) VALUES(?1, ?2)", params![epoch, nonce])? == 1;
    if !fresh {
        return Ok(Spend::AlreadySpent);
    }
    tx.execute(
        "INSERT INTO counts(epoch, item, class, n) VALUES(?1, ?2, ?3, 1)
         ON CONFLICT(epoch, item) DO UPDATE SET n = n + 1",
        params![epoch, item.key(), item.class().name()],
    )?;
    tx.commit()?;
    Ok(Spend::Counted)
}

// ---- dedicated observers ----

/// Counts an observer's report of `day`, once per observer and day.
/// `items` are distinct and validated. AlreadySpent if that observer
/// reported that day already.
pub fn count_observer_report(c: &mut Connection, hash: &str, day: u32, items: &[Item]) -> Result<Spend> {
    let tx = c.transaction()?;
    let fresh = tx.execute("INSERT OR IGNORE INTO observer_days(hash, day, items) VALUES(?1, ?2, ?3)", params![hash, day, items.len() as i64])? == 1;
    if !fresh {
        return Ok(Spend::AlreadySpent);
    }
    {
        let mut st = tx.prepare(
            "INSERT INTO observed(day, item, class, n) VALUES(?1, ?2, ?3, 1)
             ON CONFLICT(day, item) DO UPDATE SET n = n + 1",
        )?;
        for item in items {
            st.execute(params![day, item.key(), item.class().name()])?;
        }
    }
    tx.commit()?;
    Ok(Spend::Counted)
}

/// An observer's reports: (days reported, last day).
pub fn observer_reports(c: &Connection, hash: &str) -> Result<(u32, Option<u32>)> {
    Ok(c.query_row("SELECT COUNT(*), MAX(day) FROM observer_days WHERE hash = ?1", [hash], |r| Ok((r.get(0)?, r.get(1)?)))?)
}

/// Days with observer reports, most recent first: (day, observers, items).
pub fn observed_days(c: &Connection) -> Result<Vec<(u32, u32, u32)>> {
    let mut items: BTreeMap<u32, u32> = BTreeMap::new();
    let mut st = c.prepare("SELECT day, COUNT(*) FROM observed GROUP BY day")?;
    for r in st.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?)))? {
        let (d, n) = r?;
        items.insert(d, n);
    }
    let mut st = c.prepare("SELECT day, COUNT(*) FROM observer_days GROUP BY day ORDER BY day DESC")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?)))?;
    let mut out = Vec::new();
    for r in rows {
        let (d, observers) = r?;
        out.push((d, observers, items.get(&d).copied().unwrap_or(0)));
    }
    Ok(out)
}

/// One day: observers that reported, and item key -> observers.
pub fn observed_day(c: &Connection, day: u32) -> Result<(u32, BTreeMap<String, u32>)> {
    let observers: u32 = c.query_row("SELECT COUNT(*) FROM observer_days WHERE day = ?1", [day], |r| r.get(0))?;
    let mut st = c.prepare("SELECT item, n FROM observed WHERE day = ?1")?;
    let items = st.query_map([day], |r| Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?)))?.collect::<Result<_, _>>()?;
    Ok((observers, items))
}

/// Per epoch before `until`: item key -> count (presence ballots left out).
pub fn counts_before(c: &Connection, until: u32) -> Result<BTreeMap<u32, BTreeMap<String, i64>>> {
    let mut out: BTreeMap<u32, BTreeMap<String, i64>> = BTreeMap::new();
    let mut st = c.prepare("SELECT epoch, item, n FROM counts WHERE epoch < ?1 AND class != ?2")?;
    let rows = st.query_map(params![until, Class::Presence.name()], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?)))?;
    for row in rows {
        let (e, item, n) = row?;
        out.entry(e).or_default().insert(item, n);
    }
    Ok(out)
}

pub struct EpochStats {
    pub epoch: u32,
    pub codes: u32,
    pub tokens: u32,
    pub presence: u64,
    pub ballots: u64,
    pub items: u64,
}

pub fn stats(c: &Connection) -> Result<Vec<EpochStats>> {
    let mut by: BTreeMap<u32, EpochStats> = BTreeMap::new();
    let mut st = c.prepare("SELECT epoch, COUNT(*), SUM(tokens) FROM issuance GROUP BY epoch")?;
    for r in st.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?, r.get::<_, u32>(2)?)))? {
        let (e, codes, tokens) = r?;
        by.insert(e, EpochStats { epoch: e, codes, tokens, presence: 0, ballots: 0, items: 0 });
    }
    let mut st = c.prepare("SELECT epoch, class, COUNT(*), SUM(n) FROM counts GROUP BY epoch, class")?;
    for r in st.query_map([], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?, r.get::<_, i64>(3)?)))? {
        let (e, class, items, n) = r?;
        let (items, n) = (items as u64, n as u64);
        let s = by.entry(e).or_insert(EpochStats { epoch: e, codes: 0, tokens: 0, presence: 0, ballots: 0, items: 0 });
        s.ballots += n;
        if class == Class::Presence.name() {
            s.presence += n;
        } else {
            s.items += items;
        }
    }
    Ok(by.into_values().collect())
}
