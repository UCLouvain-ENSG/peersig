//! Collection periods. Observations are grouped by epoch (a week by
//! default); epoch `e` is reported during epoch `e + 1`, and the server
//! stores nothing finer than the epoch number.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochSpec {
    /// Start of epoch 0, Unix seconds.
    pub origin: i64,
    /// Seconds.
    pub length: i64,
}

impl EpochSpec {
    pub const WEEK: i64 = 7 * 24 * 3600;

    /// Epoch containing Unix time `t`, if after the origin.
    pub fn at(&self, t: i64) -> Option<u32> {
        if t < self.origin || self.length <= 0 {
            return None;
        }
        u32::try_from((t - self.origin) / self.length).ok()
    }

    pub fn start(&self, e: u32) -> i64 {
        self.origin + e as i64 * self.length
    }

    /// End of epoch `e` (exclusive), which is the start of `e + 1`.
    pub fn end(&self, e: u32) -> i64 {
        self.start(e) + self.length
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        let s = EpochSpec { origin: 1000, length: 10 };
        assert_eq!(s.at(999), None);
        assert_eq!(s.at(1000), Some(0));
        assert_eq!(s.at(1009), Some(0));
        assert_eq!(s.at(1010), Some(1));
        assert_eq!((s.start(3), s.end(3)), (1030, 1040));
    }
}
