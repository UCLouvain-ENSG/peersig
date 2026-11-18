//! Enrollment codes, as people type them.
//!
//! A participant's code looks like `K7QF-2M9D-XW4P`: 60 random bits,
//! Crockford base32. A dedicated observer's code has the same random part
//! after `OBS-`, so that the app knows, before joining, that this computer
//! will report as an observer (daily, published without threshold). The
//! server decides from its own records, not from the prefix.

/// What the server hashes: letters and digits, upper case, with the
/// letters people confuse with digits folded (`O` is `0`, `I` and `L` are
/// `1`).
pub fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

pub const OBSERVER_PREFIX: &str = "OBS";

/// An observer's code: `OBS-` and twelve characters.
pub fn is_observer(code: &str) -> bool {
    let n = normalize(code);
    n.len() == 15 && n.starts_with(&normalize(OBSERVER_PREFIX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms() {
        assert_eq!(normalize("k7qf-2m9d-xw4p"), "K7QF2M9DXW4P");
        assert_eq!(normalize("OIL0"), "0110");
        assert!(is_observer("OBS-K7QF-2M9D-XW4P"));
        assert!(is_observer("obs k7qf 2m9d xw4p"));
        assert!(is_observer("0BSK7QF2M9DXW4P"));
        assert!(!is_observer("K7QF-2M9D-XW4P"));
        // A participant's code that happens to start with 0BS.
        assert!(!is_observer("0BSK-2M9D-XW4P"));
    }
}
