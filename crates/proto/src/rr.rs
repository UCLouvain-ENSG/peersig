//! Randomized response over the public catalogue: local differential
//! privacy for "did this participant see this item".
//!
//! The catalogue lists items already released (seen by enough
//! participants). For each catalogue item, the app reports it with
//! probability `p` if it really saw it, and with probability `1 - p` if it
//! did not (a decoy). Any single catalogue ballot may be a decoy, which
//! gives epsilon = ln(p / (1 - p)) per item and epoch. Items not yet in the
//! catalogue are sent as they are: they are protected by the release
//! threshold and by the ballots being unlinkable, not by noise.
//!
//! The server debiases counts with the number of participants who reported
//! (presence ballots): E[observed] = c p + (n - c)(1 - p).

/// Probability of reporting the truth for a given epsilon.
pub fn p_for_epsilon(epsilon: f64) -> f64 {
    let e = epsilon.exp();
    e / (1.0 + e)
}

pub fn epsilon(p: f64) -> f64 {
    (p / (1.0 - p)).ln()
}

/// Catalogue items to report. `has(i)` says whether item `i` was really
/// seen; `uniform()` returns a uniform number in [0, 1).
pub fn respond<'a>(
    catalogue: &'a [String],
    has: impl Fn(&str) -> bool,
    p: f64,
    uniform: &mut impl FnMut() -> f64,
) -> Vec<(&'a String, bool)> {
    catalogue
        .iter()
        .filter_map(|k| {
            let real = has(k);
            let report = if real { uniform() < p } else { uniform() < 1.0 - p };
            report.then_some((k, real))
        })
        .collect()
}

/// Unbiased estimate of how many of `n` participants saw an item that was
/// reported `observed` times under randomized response.
pub fn debias(observed: f64, n: f64, p: f64) -> f64 {
    if (2.0 * p - 1.0).abs() < 1e-9 {
        return 0.0;
    }
    (observed - n * (1.0 - p)) / (2.0 * p - 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift: deterministic uniform numbers for tests.
    pub fn uniform(seed: u64) -> impl FnMut() -> f64 {
        let mut x = seed;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 11) as f64 / (1u64 << 53) as f64
        }
    }

    #[test]
    fn epsilon_round_trip() {
        assert!((epsilon(p_for_epsilon(2.0)) - 2.0).abs() < 1e-12);
        assert!((p_for_epsilon(9f64.ln()) - 0.9).abs() < 1e-12);
    }

    #[test]
    fn debiased_counts() {
        // 1000 participants, 300 of whom saw item "a"; nobody saw "b".
        let cat = vec!["a".to_string(), "b".to_string()];
        let p = 0.8;
        let mut u = uniform(42);
        let (mut a, mut b) = (0.0, 0.0);
        for i in 0..1000 {
            for (k, _) in respond(&cat, |k| k == "a" && i < 300, p, &mut u) {
                if k == "a" {
                    a += 1.0
                } else {
                    b += 1.0
                }
            }
        }
        let (ea, eb) = (debias(a, 1000.0, p), debias(b, 1000.0, p));
        assert!((ea - 300.0).abs() < 50.0, "{}", ea);
        assert!(eb.abs() < 50.0, "{}", eb);
    }
}
