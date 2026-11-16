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
//! - `token_keys`, `frozen`, `catalogue`, `meta`: keys, per-epoch
//!   parameters and the catalogue snapshot each epoch randomized against.

use std::collections::{BTreeMap, BTreeSet};

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
CREATE TABLE IF NOT EXISTS frozen(epoch INTEGER PRIMARY KEY, rr_p REAL NOT NULL);
CREATE TABLE IF NOT EXISTS catalogue(epoch INTEGER NOT NULL, item TEXT NOT NULL, PRIMARY KEY(epoch, item)) WITHOUT ROWID;
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

pub struct EpochCounts {
    /// Presence ballots: participants who reported, and those who share domains.
    pub n_all: f64,
    pub n_domains: f64,
    pub rr_p: Option<f64>,
    pub catalogue: BTreeSet<String>,
    /// item key -> (class, count)
    pub items: BTreeMap<String, (String, f64)>,
}

/// Everything about the epochs before `until`.
pub fn counts_before(c: &Connection, until: u32) -> Result<BTreeMap<u32, EpochCounts>> {
    let mut out: BTreeMap<u32, EpochCounts> = BTreeMap::new();
    let mut st = c.prepare("SELECT epoch, item, class, n FROM counts WHERE epoch < ?1")?;
    let rows = st.query_map([until], |r| Ok((r.get::<_, u32>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i64>(3)?)))?;
    for row in rows {
        let (e, item, class, n) = row?;
        let ec = out.entry(e).or_insert_with(|| EpochCounts {
            n_all: 0.0,
            n_domains: 0.0,
            rr_p: None,
            catalogue: BTreeSet::new(),
            items: BTreeMap::new(),
        });
        if class == Class::Presence.name() {
            ec.n_all += n as f64;
            if item == (Item::Presence { shares_domains: true }).key() {
                ec.n_domains += n as f64;
            }
        } else {
            ec.items.insert(item, (class, n as f64));
        }
    }
    for (e, ec) in out.iter_mut() {
        ec.rr_p = frozen_p(c, *e)?;
        ec.catalogue = catalogue(c, *e)?.into_iter().collect();
    }
    Ok(out)
}

pub fn frozen_p(c: &Connection, epoch: u32) -> Result<Option<f64>> {
    Ok(c.query_row("SELECT rr_p FROM frozen WHERE epoch = ?1", [epoch], |r| r.get(0)).optional()?)
}

pub fn catalogue(c: &Connection, epoch: u32) -> Result<Vec<String>> {
    let mut st = c.prepare("SELECT item FROM catalogue WHERE epoch = ?1 ORDER BY item")?;
    let v = st.query_map([epoch], |r| r.get(0))?.collect::<Result<_, _>>()?;
    Ok(v)
}

pub fn freeze(c: &mut Connection, epoch: u32, rr_p: f64, items: &[String]) -> Result<()> {
    let tx = c.transaction()?;
    if tx.execute("INSERT OR IGNORE INTO frozen(epoch, rr_p) VALUES(?1, ?2)", params![epoch, rr_p])? == 1 {
        for i in items {
            tx.execute("INSERT OR IGNORE INTO catalogue(epoch, item) VALUES(?1, ?2)", params![epoch, i])?;
        }
    }
    tx.commit()?;
    Ok(())
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
