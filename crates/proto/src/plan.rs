//! From one epoch's real items to the list of ballots the app will send.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Class, Item};

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Plan {
    pub epoch: u32,
    /// Shuffled; one token each. The last-but-shuffled one is presence.
    pub ballots: Vec<Item>,
    /// Real items in `ballots`.
    pub real: usize,
    /// Items left out because there were more than tokens.
    pub dropped: usize,
}

/// `real`: what the participant saw and agreed to send. `budget`: tokens
/// available. Every item goes once, plus one presence ballot ("I took
/// part"); over budget, a uniform sample is kept.
pub fn plan(epoch: u32, real: &[Item], shares_domains: bool, budget: usize, uniform: &mut impl FnMut() -> f64) -> Plan {
    let wanted = |i: &Item| match i.class() {
        Class::Hello => true,
        Class::Domain => shares_domains,
        Class::Presence => false,
    };
    let keys: BTreeSet<String> = real.iter().filter(|i| wanted(i)).map(Item::key).collect();
    let mut ballots: Vec<Item> = keys.iter().filter_map(|k| Item::from_key(k)).collect();
    let mut out = Plan { epoch, ..Default::default() };
    // Over budget: keep a uniform sample (one token goes to presence).
    shuffle(&mut ballots, uniform);
    let room = budget.saturating_sub(1);
    if ballots.len() > room {
        out.dropped = ballots.len() - room;
        ballots.truncate(room);
    }
    out.real = ballots.len();
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
    fn items_presence_and_budget() {
        let a = hello("t13d1516h2_8daaf6152771_e5627efa2ab1");
        let b = hello("t13d1516h2_8daaf6152771_000000000001");
        let mut x = 7u64;
        let mut u = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 11) as f64 / (1u64 << 53) as f64
        };
        // Each item once, plus presence.
        let pl = plan(3, &[a.clone(), b.clone(), a.clone()], false, 100, &mut u);
        let keys: BTreeSet<String> = pl.ballots.iter().map(Item::key).collect();
        assert!(keys.contains(&a.key()) && keys.contains(&b.key()));
        assert_eq!((pl.real, pl.dropped, pl.ballots.len()), (2, 0, 3));
        assert!(pl.ballots.iter().any(|i| i.class() == Class::Presence));
        // Budget: presence is always kept.
        let pl = plan(3, &[a, b], false, 2, &mut u);
        assert_eq!((pl.real, pl.dropped, pl.ballots.len()), (1, 1, 2));
        assert!(pl.ballots.iter().any(|i| i.class() == Class::Presence));
    }
}
