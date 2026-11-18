//! PeerSig collection server: issues blind ballot tokens to enrolled
//! participants, counts anonymous ballots arriving through Oblivious HTTP,
//! and publishes the items reported by enough participants. Apart from
//! them, it counts the daily reports of dedicated observers, and publishes
//! those day by day, without threshold.

pub mod admin;
pub mod api;
pub mod db;
pub mod enroll;
pub mod release;
pub mod web;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rusqlite::Connection;

use peersig_proto::token::Issuer;
use peersig_proto::{oblivious, EpochSpec};

/// Collection parameters.
#[derive(Clone, Debug)]
pub struct Settings {
    pub epochs: EpochSpec,
    pub tokens_per_epoch: u32,
    pub k_hello: u32,
    pub k_domain: u32,
    pub about_url: Option<String>,
}

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct State {
    pub db: Mutex<Connection>,
    pub settings: Settings,
    pub gateway: oblivious::Server,
    pub key_config: Vec<u8>,
    keys: Mutex<HashMap<u32, Arc<Issuer>>>,
    released: Mutex<Option<(u32, Vec<u8>)>>,
    pub clock: Clock,
}

pub fn system_clock() -> Clock {
    Arc::new(|| chrono::Utc::now().timestamp())
}

impl State {
    pub fn new(db: Connection, settings: Settings, clock: Clock) -> Result<Arc<Self>> {
        let seed = db::secret(&db, "ohttp-seed")?;
        let gateway = oblivious::gateway(&seed)?;
        let key_config = oblivious::key_config(&gateway)?;
        Ok(Arc::new(State {
            db: Mutex::new(db),
            settings,
            gateway,
            key_config,
            keys: Mutex::new(HashMap::new()),
            released: Mutex::new(None),
            clock,
        }))
    }

    /// (current epoch, epoch being reported). Equal when nothing can be
    /// reported yet.
    pub fn epochs(&self) -> Option<(u32, u32)> {
        let cur = self.settings.epochs.at((self.clock)())?;
        Some((cur, cur.saturating_sub(1)))
    }

    /// (today, first day an observer may still report): days from the
    /// epochs' origin. Observers report days before today.
    pub fn observer_days(&self) -> Option<(u32, u32)> {
        let today = self.settings.epochs.days().at((self.clock)())?;
        Some((today, today.saturating_sub(peersig_proto::wire::OBSERVER_LATE_DAYS)))
    }

    /// The token key of `epoch`, created on first use.
    pub fn issuer(&self, epoch: u32) -> Result<Arc<Issuer>> {
        if let Some(k) = self.keys.lock().unwrap().get(&epoch) {
            return Ok(k.clone());
        }
        let stored = db::token_key(&self.db.lock().unwrap(), epoch)?;
        let issuer = match stored {
            Some(sk) => Issuer::from_der(&sk)?,
            None => {
                let k = Issuer::generate()?;
                let db = self.db.lock().unwrap();
                db::put_token_key(&db, epoch, &k.secret_der()?, k.public_der())?;
                // Another request may have stored one first: use the stored one.
                Issuer::from_der(&db::token_key(&db, epoch)?.expect("just stored"))?
            }
        };
        let issuer = Arc::new(issuer);
        self.keys.lock().unwrap().insert(epoch, issuer.clone());
        Ok(issuer)
    }

    /// Released items as JSON, computed once per reporting epoch.
    pub fn released_json(&self, until: u32) -> Result<Vec<u8>> {
        if let Some((u, j)) = &*self.released.lock().unwrap() {
            if *u == until {
                return Ok(j.clone());
            }
        }
        let r = release::released(&self.db.lock().unwrap(), &self.settings, until)?;
        let j = serde_json::to_vec(&r)?;
        *self.released.lock().unwrap() = Some((until, j.clone()));
        Ok(j)
    }
}
