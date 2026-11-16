//! From one epoch's real items to the list of ballots the app will send.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{rr, Class, Item};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Plan {
    pub epoch: u32,
    /// Shuffled; one token each.
    pub ballots: Vec<Item>,
    /// Real items in `ballots`.
    pub real: usize,
    /// Catalogue items not seen, sent as decoys.
    pub decoys: usize,
    /// Catalogue items seen but not sent (randomized response).
    pub withheld: usize,
    /// Items left out because there were more than tokens.
    pub dropped: usize,
}

/// `real`: what the participant saw and agreed to send. `catalogue`: the
/// frozen catalogue of the epoch. `budget`: tokens available.
pub fn plan(
    epoch: u32,
    real: &[Item],
    catalogue: &[Item],
    p: f64,
    shares_domains: bool,
    budget: usize,
    uniform: &mut impl FnMut() -> f64,
) -> Plan {
    let wanted = |i: &Item| match i.class() {
        Class::Hello => true,
        Class::Domain => shares_domains,
        Class::Presence => false,
    };
    let real: BTreeSet<String> = real.iter().filter(|i| wanted(i)).map(Item::key).collect();
    let cat: Vec<String> = catalogue.iter().filter(|i| wanted(i)).map(Item::key).collect::<BTreeSet<_>>().into_iter().collect();
    let in_cat: BTreeSet<&String> = cat.iter().collect();

    let mut out = Plan { epoch, ..Default::default() };
    let mut keys: Vec<String> = Vec::new();
    for (k, is_real) in rr::respond(&cat, |k| real.contains(k), p, uniform) {
        if is_real {
            out.real += 1;
        } else {
            out.decoys += 1;
        }
        keys.push(k.clone());
    }
    out.withheld = cat.iter().filter(|k| real.contains(*k)).count() - out.real;
    for k in real.iter().filter(|k| !in_cat.contains(k)) {
        out.real += 1;
        keys.push(k.clone());
    }
    let mut ballots: Vec<Item> = keys.iter().filter_map(|k| Item::from_key(k)).collect();
    // Over budget: keep a uniform sample (one token goes to presence).
    shuffle(&mut ballots, uniform);
    let room = budget.saturating_sub(1);
    if ballots.len() > room {
        out.dropped = ballots.len() - room;
        ballots.truncate(room);
    }
    ballots.push(Item::Presence { shares_domains });
    shuffle(&mut ballots, uniform);
    out.ballots = ballots;
    out
}

pub fn shuffle<T>(v: &mut [T], uniform: &mut impl FnMut() -> f64) {
    for i in (1..v.len()).rev() {
        let j = ((uniform() * (i + 1) as f64) as usize).min(i);
        v.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppRef;

    fn hello(ja4: &str) -> Item {
        Item::Hello {
            os: "macos 27".into(),
            transport: "tcp".into(),
            ja4: ja4.into(),
            ja4_legacy: None,
            app: AppRef { name: "X".into(), id: None, version: None, team_id: None, kind: "app".into(), engine: None },
        }
    }

    #[test]
    fn decoys_and_budget() {
        let a = hello("t13d1516h2_8daaf6152771_e5627efa2ab1");
        let b = hello("t13d1516h2_8daaf6152771_000000000001");
        let new = hello("t13d1516h2_8daaf6152771_000000000002");
        let mut x = 7u64;
        let mut u = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 11) as f64 / (1u64 << 53) as f64
        };
        // p = 1: no noise; the new item always goes, the catalogue item only if seen.
        let pl = plan(3, &[a.clone(), new.clone()], &[a.clone(), b.clone()], 1.0, false, 100, &mut u);
        let keys: BTreeSet<String> = pl.ballots.iter().map(Item::key).collect();
        assert!(keys.contains(&a.key()) && keys.contains(&new.key()) && !keys.contains(&b.key()));
        assert_eq!((pl.real, pl.decoys, pl.withheld, pl.ballots.len()), (2, 0, 0, 3));
        assert!(pl.ballots.iter().any(|i| i.class() == Class::Presence));
        // p = 0: every catalogue answer is flipped.
        let pl = plan(3, &[a.clone()], &[a.clone(), b.clone()], 0.0, false, 100, &mut u);
        assert_eq!((pl.real, pl.decoys, pl.withheld), (0, 1, 1));
        // Budget: presence is always kept.
        let pl = plan(3, &[a, new], &[], 1.0, false, 2, &mut u);
        assert_eq!((pl.ballots.len(), pl.dropped), (2, 1));
        assert!(pl.ballots.iter().any(|i| i.class() == Class::Presence));
    }
}
