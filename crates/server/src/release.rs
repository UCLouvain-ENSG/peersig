//! Which items are released, with what support.
//!
//! Per epoch, an item's count is the number of participants who reported
//! it (each sends an item at most once per epoch). An item's support is its
//! largest per-epoch count: ballots are unlinkable, so the same participant
//! seen three weeks in a row cannot be told from three participants. The
//! item is released once its support reaches k (k_hello, k_domain).
//!
//! There is no noise: noise drawn again at every weekly release would
//! average out, and per-item, per-week privacy budgets add up over a
//! report and over weeks. Differential privacy is future work
//! (docs/privacy.md).

use std::collections::BTreeMap;

use anyhow::Result;
use rusqlite::Connection;

use peersig_proto::wire::{Released, ReleasedItem};
use peersig_proto::Item;

use crate::db;
use crate::Settings;

/// Items released from the counts of epochs before `until`.
pub fn released(c: &Connection, s: &Settings, until: u32) -> Result<Released> {
    let mut support: BTreeMap<String, i64> = BTreeMap::new();
    for counts in db::counts_before(c, until)?.into_values() {
        for (key, n) in counts {
            let e = support.entry(key).or_insert(0);
            *e = (*e).max(n);
        }
    }
    let mut items = Vec::new();
    for (key, support) in support {
        let Some(item) = Item::from_key(&key) else { continue };
        let k = match &item {
            Item::Hello { .. } => s.k_hello,
            Item::Domain { .. } => s.k_domain,
            Item::Presence { .. } => continue,
        } as i64;
        if support >= k {
            items.push(ReleasedItem { item, support });
        }
    }
    Ok(Released { until_epoch: until, k_hello: s.k_hello, k_domain: s.k_domain, items })
}
