//! Which items deserve a second look before they are sent: those whose
//! application or server name falls in a sensitive category
//! (`data/sensitive.txt`: health, dating, religion...), or contains one of
//! the participant's own words (their name, their account's, words they
//! chose). The review shows them first. Nothing is removed, and nothing
//! here leaves the device: it only orders what the participant sees.

use std::sync::OnceLock;

use crate::Item;

const LIST: &str = include_str!("../data/sensitive.txt");

/// One entry of the list.
#[derive(Debug, PartialEq)]
enum Pattern {
    /// The start of a word (5 letters or more).
    Prefix(String),
    /// A whole word.
    Word(String),
    /// Whole words in a row.
    Words(Vec<String>),
    /// A server name and those under it.
    Domain(String),
}

/// The categories of `data/sensitive.txt`, each with its patterns.
fn categories() -> &'static [(String, Vec<Pattern>)] {
    static LIST_PARSED: OnceLock<Vec<(String, Vec<Pattern>)>> = OnceLock::new();
    LIST_PARSED.get_or_init(|| parse(LIST))
}

fn parse(text: &str) -> Vec<(String, Vec<Pattern>)> {
    let mut out: Vec<(String, Vec<Pattern>)> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push((name.to_string(), Vec::new()));
            continue;
        }
        let Some((_, patterns)) = out.last_mut() else { continue };
        for entry in line.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            patterns.push(pattern(entry));
        }
    }
    out
}

fn pattern(entry: &str) -> Pattern {
    let quoted = entry.len() > 2 && entry.starts_with('"') && entry.ends_with('"');
    let entry = entry.trim_matches('"').to_lowercase();
    if entry.contains('.') {
        return Pattern::Domain(entry);
    }
    let w = words(&entry);
    match w.len() {
        1 if quoted || w[0].chars().count() < 5 => Pattern::Word(w[0].clone()),
        1 => Pattern::Prefix(w[0].clone()),
        _ => Pattern::Words(w),
    }
}

/// Lower-cased words: cut at anything not a letter or a digit.
fn words(s: &str) -> Vec<String> {
    s.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(String::from).collect()
}

impl Pattern {
    fn matches(&self, w: &[String], domain: Option<&str>) -> bool {
        match self {
            Pattern::Prefix(p) => w.iter().any(|x| x.starts_with(p.as_str())),
            Pattern::Word(p) => w.iter().any(|x| x == p),
            Pattern::Words(p) => w.windows(p.len()).any(|x| x == p.as_slice()),
            Pattern::Domain(d) => domain.is_some_and(|n| n == d || n.ends_with(&format!(".{}", d))),
        }
    }
}

/// The names of an item a person could be recognized by: the application's
/// name and id, and the server name.
fn names(item: &Item) -> (Vec<String>, Option<&str>) {
    match item {
        Item::Hello { app, .. } => (app_words(app), None),
        Item::Domain { app, domain, .. } => {
            let mut w = app_words(app);
            w.extend(words(domain));
            (w, Some(domain.as_str()))
        }
        Item::Presence { .. } => (vec![], None),
    }
}

fn app_words(app: &crate::AppRef) -> Vec<String> {
    let mut w = words(&app.name);
    if let Some(id) = &app.id {
        w.extend(words(id));
    }
    w
}

/// The participant's own words, as they are matched: lower-cased letters
/// and digits, 4 or more.
pub fn own_word(s: &str) -> Option<String> {
    let w: String = s.to_lowercase().chars().filter(|c| c.is_alphanumeric()).collect();
    (w.chars().count() >= 4).then_some(w)
}

/// Why an item deserves a second look: the categories it falls in, then
/// the participant's own words it contains (`own`, from `own_word`),
/// each once. Empty for most.
pub fn reasons(item: &Item, own: &[String]) -> Vec<Reason> {
    let (w, domain) = names(item);
    if w.is_empty() {
        return vec![];
    }
    let mut out: Vec<Reason> = categories()
        .iter()
        .filter(|(_, patterns)| patterns.iter().any(|p| p.matches(&w, domain)))
        .map(|(name, _)| Reason::Category(name.clone()))
        .collect();
    // Anywhere in a word: "barbette" in "tombarbette.be".
    for o in own {
        if w.iter().any(|x| x.contains(o.as_str())) {
            out.push(Reason::Own(o.clone()));
        }
    }
    out
}

/// Why an item is shown first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A category of `data/sensitive.txt` ("health").
    Category(String),
    /// One of the participant's own words.
    Own(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppRef;

    fn app(name: &str, id: Option<&str>) -> AppRef {
        AppRef { name: name.into(), id: id.map(String::from), version: Some("1.0".into()), team_id: None, kind: "app".into(), engine: None }
    }
    fn hello(name: &str, id: Option<&str>) -> Item {
        Item::Hello { os: "macos 27".into(), transport: "tcp".into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(), app: app(name, id) }
    }
    fn domain(name: &str, d: &str) -> Item {
        Item::Domain { os: "macos 27".into(), app: app(name, None), domain: d.into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into() }
    }
    fn cats(i: &Item) -> Vec<String> {
        reasons(i, &[]).into_iter().map(|r| match r {
            Reason::Category(c) => c,
            Reason::Own(o) => o,
        }).collect()
    }

    #[test]
    fn the_list_parses() {
        let c = categories();
        assert!(c.len() >= 8);
        assert!(c.iter().all(|(_, p)| !p.is_empty()));
        assert_eq!(pattern("pregnan"), Pattern::Prefix("pregnan".into()));
        assert_eq!(pattern("tor"), Pattern::Word("tor".into()));
        assert_eq!(pattern("\"hallow\""), Pattern::Word("hallow".into()));
        assert_eq!(pattern("period tracker"), Pattern::Words(vec!["period".into(), "tracker".into()]));
        assert_eq!(pattern("flo.health"), Pattern::Domain("flo.health".into()));
    }

    #[test]
    fn categories_match_names() {
        assert_eq!(cats(&hello("Grindr", Some("com.grindrapp.android"))), vec!["sexuality and dating"]);
        assert_eq!(cats(&hello("Muslim Pro", Some("com.bitsmedia.android.muslimpro"))), vec!["religion"]);
        assert_eq!(cats(&domain("Flo", "api.flo.health")), vec!["health"]);
        assert_eq!(cats(&hello("PokerStars", None)), vec!["money troubles and gambling"]);
        assert_eq!(cats(&domain("Firefox", "ladbrokes.be")), vec!["money troubles and gambling"]);
        assert_eq!(cats(&hello("My Period Tracker", None)), vec!["health"]);
        // Whole words and quoted words do not match inside others.
        for ordinary in [
            hello("Activity Monitor", Some("com.apple.ActivityMonitor")),
            hello("Tailscale", Some("io.tailscale.ipn.macos")),
            hello("Halloween Countdown", None),
            domain("NetNewsWire", "feeds.syndication.example.com"),
            domain("Grafana", "healthcheck.example.com"),
            hello("CryptoTokenKit", Some("com.apple.ctkd")),
            hello("Slack", Some("com.tinyspeck.slackmacgap")),
            domain("Microsoft Teams", "teams.microsoft.com"),
            domain("Spotify", "spclient.wg.spotify.com"),
        ] {
            assert_eq!(cats(&ordinary), Vec::<String>::new(), "{:?}", ordinary);
        }
    }

    #[test]
    fn own_words_match_inside_names() {
        let own: Vec<String> = ["Barbette", "tbarbette", "Tom"].iter().filter_map(|w| own_word(w)).collect();
        assert_eq!(own, vec!["barbette", "tbarbette"], "3 letters are too few");
        let r = reasons(&domain("Nextcloud", "cloud.tombarbette.be"), &own);
        assert_eq!(r, vec![Reason::Own("barbette".into())]);
        assert!(reasons(&domain("Thunderbird", "mail.barbette-family.org"), &own).contains(&Reason::Own("barbette".into())));
        assert!(reasons(&domain("Nextcloud", "cloud.example.org"), &own).is_empty());
        assert!(reasons(&Item::Presence { shares_domains: true }, &own).is_empty());
    }
}
