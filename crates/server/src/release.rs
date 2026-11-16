//! Which items are released, with what support.
//!
//! Per epoch, an item's count is the number of participants who reported
//! it (each sends an item at most once per epoch). Catalogue items went
//! through randomized response, so their count is debiased with the
//! number of presence ballots. An item's support is its largest
//! per-epoch count: ballots are unlinkable, so the same participant seen
//! three weeks in a row cannot be told from three participants. Support
//! gets Laplace noise (central DP), and the item is released if the noisy
//! value reaches k (k_hello, k_domain). Noise is drawn per item and per
//! release, from a keyed hash, so asking again gives the same value.

use std::collections::BTreeMap;

use anyhow::Result;
use hmac::{Hmac, Mac};
use rusqlite::Connection;
use sha2::Sha256;

use peersig_proto::rr;
use peersig_proto::wire::{Released, ReleasedItem};
use peersig_proto::Item;

use crate::db;
use crate::Settings;

/// Laplace(0, scale) from a keyed hash of (item, release).
fn noise(secret: &[u8], key: &str, until: u32, scale: f64) -> f64 {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("any key length");
    m.update(key.as_bytes());
    m.update(&until.to_be_bytes());
    let h = m.finalize().into_bytes();
    let x = u64::from_be_bytes(h[..8].try_into().unwrap());
    // Uniform in (-0.5, 0.5), never exactly +-0.5.
    let u = ((x >> 11) as f64 + 0.5) / (1u64 << 53) as f64 - 0.5;
    -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
}

/// Items released from the counts of epochs before `until`.
pub fn released(c: &Connection, s: &Settings, until: u32) -> Result<Released> {
    let secret = db::secret(c, "noise")?;
    let mut support: BTreeMap<String, f64> = BTreeMap::new();
    for ec in db::counts_before(c, until)?.values() {
        for (key, (class, n)) in &ec.items {
            let est = match (ec.catalogue.contains(key), ec.rr_p) {
                (true, Some(p)) => {
                    let n_rr = if class == "domain" { ec.n_domains } else { ec.n_all };
                    rr::debias(*n, n_rr, p)
                }
                _ => *n,
            };
            let e = support.entry(key.clone()).or_insert(f64::MIN);
            *e = e.max(est);
        }
    }
    let scale = 1.0 / s.epsilon_central.max(1e-3);
    let mut items = Vec::new();
    for (key, sup) in support {
        let Some(item) = Item::from_key(&key) else { continue };
        let k = match &item {
            Item::Hello { .. } => s.k_hello,
            Item::Domain { .. } => s.k_domain,
            Item::Presence { .. } => continue,
        } as f64;
        let noisy = sup + noise(&secret, &key, until, scale);
        if noisy >= k {
            items.push(ReleasedItem { item, support: noisy.round() as i64 });
        }
    }
    Ok(Released { until_epoch: until, k_hello: s.k_hello, k_domain: s.k_domain, epsilon_central: s.epsilon_central, items })
}

/// The catalogue of `epoch`: frozen the first time it is asked for, from
/// the items released before it, with the randomized-response parameter of
/// that moment.
pub fn frozen_catalogue(c: &mut Connection, s: &Settings, epoch: u32) -> Result<(f64, Vec<Item>)> {
    if db::frozen_p(c, epoch)?.is_none() {
        let r = released(c, s, epoch)?;
        let keys: Vec<String> = r.items.iter().map(|i| i.item.key()).collect();
        db::freeze(c, epoch, s.rr_p, &keys)?;
    }
    let p = db::frozen_p(c, epoch)?.unwrap_or(s.rr_p);
    let items = db::catalogue(c, epoch)?.iter().filter_map(|k| Item::from_key(k)).collect();
    Ok((p, items))
}

#[cfg(test)]
mod tests {
    use super::noise;

    #[test]
    fn noise_is_stable_and_centered() {
        let a = noise(b"k", "item", 3, 1.0);
        assert_eq!(a, noise(b"k", "item", 3, 1.0));
        assert_ne!(a, noise(b"k", "item", 4, 1.0));
        let mean: f64 = (0..20000).map(|i| noise(b"k", &i.to_string(), 0, 1.0)).sum::<f64>() / 20000.0;
        let var: f64 = (0..20000).map(|i| noise(b"k", &i.to_string(), 0, 1.0).powi(2)).sum::<f64>() / 20000.0;
        assert!(mean.abs() < 0.05, "{}", mean);
        assert!((var - 2.0).abs() < 0.2, "{}", var); // Laplace(1): variance 2
    }
}
