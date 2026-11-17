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
//!   the e-mail address or GitHub account and how many codes it got. Not
//!   the address, not which code, not when.
//! - `token_keys`, `meta`: the keys and the epoch layout.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use peersig_proto::{Class, Item};

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
";

pub fn open(path: &str) -> Result<Connection> {
    let c = Connection::open(path).with_context(|| path.to_string())?;
    c.execute_batch(SCHEMA)?;
    Ok(c)
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

pub fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

pub fn code_hash(code: &str) -> String {
    peersig_proto::short_hash(format!("peersig-code:{}", normalize_code(code)).as_bytes(), 32)
}

pub fn add_code(c: &Connection, code: &str, label: &str) -> Result<()> {
    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
    c.execute("INSERT INTO codes(hash, label, created) VALUES(?1, ?2, ?3)", params![code_hash(code), label, day])?;
    Ok(())
}

/// Active code -> true; revoked -> false; unknown -> None.
pub fn code_active(c: &Connection, hash: &str) -> Result<Option<bool>> {
    Ok(c.query_row("SELECT revoked FROM codes WHERE hash = ?1", [hash], |r| r.get::<_, i64>(0)).optional()?.map(|r| r == 0))
}

pub fn revoke(c: &Connection, code_or_label: &str) -> Result<usize> {
    Ok(c.execute(
        "UPDATE codes SET revoked = 1 WHERE hash = ?1 OR label = ?2",
        params![code_hash(code_or_label), code_or_label],
    )?)
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
/// it got fewer than `cap` codes so far. Returns (code, label).
pub fn enroll(c: &mut Connection, identity: &str, prefix: &str, cap: u32) -> Result<Option<(String, String)>> {
    let tx = c.transaction()?;
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
    /// epoch -> tokens issued.
    pub epochs: BTreeMap<u32, u32>,
}

pub fn list_codes(c: &Connection) -> Result<Vec<CodeRow>> {
    let mut st = c.prepare("SELECT hash, label, created, revoked FROM codes ORDER BY label")?;
    let rows: Vec<(String, String, String, i64)> =
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?;
    let mut out = Vec::new();
    for (hash, label, created, revoked) in rows {
        let mut q = c.prepare("SELECT epoch, tokens FROM issuance WHERE hash = ?1")?;
        let epochs = q.query_map([&hash], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u32>(1)?)))?.collect::<Result<_, _>>()?;
        out.push(CodeRow { label, created, revoked: revoked != 0, epochs });
    }
    Ok(out)
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
