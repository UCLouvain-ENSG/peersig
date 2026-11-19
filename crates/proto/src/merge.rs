//! Pre-merging: items that differ only in a detail that splits one fact
//! into many are merged before the participant reviews them.
//!
//! - Versions: the components after major.minor of a version number, in an
//!   application's name, version or engine. `2.1.322` and `2.1.326` give
//!   `2.1.*`; `157.0.8103.51` and `157.0.8103.79` give `157.0.*`, whatever
//!   else they share, so that the merged item is the same for everyone
//!   and from week to week. The name counts too: Claude Code's
//!   command-line binary is named after its version.
//! - Server names: runs that start with a digit and go on with hex digits,
//!   in the labels left of the last two (CDN shards, numbered servers).
//!   `p177-fmip.icloud.com` and `p63-fmip.icloud.com` give
//!   `p*-fmip.icloud.com`.
//!
//! Items merge only when they are equal in everything else, and only when
//! there are at least two: a lone `2.1.322` stays as it is. Items the
//! participant removed stay out of merges, so a removed item is never sent
//! inside a merged one. Fewer, less specific items: more of them fit the
//! token budget, and a rare version points to fewer people.

use std::collections::{BTreeMap, BTreeSet};

use crate::item::Observed;
use crate::Item;

/// Marks a variable part in a template. Control characters fail
/// validation, so it cannot occur in an item.
const HOLE: char = '\u{1}';

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Version,
    Run,
}

/// A variable part: its kind, its value, and what it must share with the
/// parts it merges with (major.minor for a version, nothing for a run).
struct Part {
    kind: Kind,
    value: String,
    class: String,
}

/// Version numbers with three components or more, as byte ranges.
fn versions(s: &str) -> Vec<(usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() || (i > 0 && (b[i - 1].is_ascii_digit() || b[i - 1] == b'.')) {
            i += 1;
            continue;
        }
        let (start, mut j, mut parts) = (i, i, 0);
        loop {
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            parts += 1;
            if j + 1 < b.len() && b[j] == b'.' && b[j + 1].is_ascii_digit() {
                j += 1;
            } else {
                break;
            }
        }
        if parts >= 3 {
            out.push((start, j));
        }
        i = j;
    }
    out
}

/// Runs of a digit then hex digits, in the labels left of the last two.
fn runs(domain: &str) -> Vec<(usize, usize)> {
    let Some(last) = domain.rfind('.') else { return Vec::new() };
    let Some(cut) = domain[..last].rfind('.') else { return Vec::new() };
    let b = domain.as_bytes();
    let hex = |c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c);
    let mut out = Vec::new();
    let mut i = 0;
    while i < cut {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < cut && hex(b[i]) {
                i += 1;
            }
            out.push((start, i));
        } else {
            i += 1;
        }
    }
    out
}

/// The fields that may hold variable parts, always in the same order.
fn fields(item: &mut Item) -> Vec<(&mut String, Kind)> {
    let mut v = Vec::new();
    let (app, domain) = match item {
        Item::Hello { app, .. } => (app, None),
        Item::Domain { app, domain, .. } => (app, Some(domain)),
        Item::Presence { .. } => return v,
    };
    v.push((&mut app.name, Kind::Version));
    if let Some(x) = app.version.as_mut() {
        v.push((x, Kind::Version));
    }
    if let Some(x) = app.engine.as_mut() {
        v.push((x, Kind::Version));
    }
    if let Some(d) = domain {
        v.push((d, Kind::Run));
    }
    v
}

/// The item with its variable parts replaced by holes, and the parts.
fn template(item: &Item) -> (Item, Vec<Part>) {
    let mut t = item.clone();
    let mut parts = Vec::new();
    for (s, kind) in fields(&mut t) {
        let ranges = match kind {
            Kind::Version => versions(s),
            Kind::Run => runs(s),
        };
        if ranges.is_empty() {
            continue;
        }
        let mut out = String::new();
        let mut prev = 0;
        for (a, b) in ranges {
            out.push_str(&s[prev..a]);
            out.push(HOLE);
            let value = s[a..b].to_string();
            let class = match kind {
                Kind::Version => value.split('.').take(2).collect::<Vec<_>>().join("."),
                Kind::Run => String::new(),
            };
            parts.push(Part { kind, value, class });
            prev = b;
        }
        out.push_str(&s[prev..]);
        *s = out;
    }
    (t, parts)
}

fn fill(mut t: Item, values: &[String]) -> Item {
    let mut it = values.iter();
    for (s, _) in fields(&mut t) {
        if s.contains(HOLE) {
            *s = s.chars().fold(String::new(), |mut out, c| {
                match c {
                    HOLE => out.push_str(it.next().expect("one value per hole")),
                    c => out.push(c),
                }
                out
            });
        }
    }
    t
}

/// One value for a part: unchanged if all agree; else `*` for a run, and
/// major.minor followed by `*` for a version (`class` is major.minor).
fn merged_value(kind: Kind, class: &str, values: &[&str]) -> String {
    if values.iter().all(|v| *v == values[0]) {
        return values[0].to_string();
    }
    match kind {
        Kind::Run => "*".into(),
        Kind::Version => format!("{}.*", class),
    }
}

fn absorb(into: &mut Observed, o: Observed) {
    into.count += o.count;
    into.first = into.first.min(o.first);
    into.last = into.last.max(o.last);
    for p in o.procs {
        if into.procs.len() < 8 {
            into.procs.insert(p);
        }
    }
    if o.merged.is_empty() {
        into.merged.push(o.item.label());
    } else {
        into.merged.extend(o.merged);
    }
}

/// Merges items equal except for sub-minor versions and random-looking
/// runs in server names. Items whose key is in `removed` are left alone.
pub fn merge(items: Vec<Observed>, removed: &BTreeSet<String>) -> Vec<Observed> {
    type Group = (Item, Vec<(Kind, String)>, Vec<(Vec<String>, Observed)>);
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    let mut out: Vec<Observed> = Vec::new();
    for o in items {
        if removed.contains(&o.key) {
            out.push(o);
            continue;
        }
        let (t, parts) = template(&o.item);
        if parts.is_empty() {
            out.push(o);
            continue;
        }
        let classes: Vec<&str> = parts.iter().map(|p| p.class.as_str()).collect();
        let key = format!("{}\n{}", t.key(), classes.join("\n"));
        let kinds = parts.iter().map(|p| (p.kind, p.class.clone())).collect();
        let values = parts.into_iter().map(|p| p.value).collect();
        groups.entry(key).or_insert_with(|| (t, kinds, Vec::new())).2.push((values, o));
    }
    for (t, kinds, members) in groups.into_values() {
        if members.len() < 2 {
            out.extend(members.into_iter().map(|(_, o)| o));
            continue;
        }
        let values: Vec<String> = kinds
            .iter()
            .enumerate()
            .map(|(i, (k, class))| merged_value(*k, class, &members.iter().map(|(v, _)| v[i].as_str()).collect::<Vec<_>>()))
            .collect();
        let item = fill(t, &values);
        if item.validate().is_err() {
            out.extend(members.into_iter().map(|(_, o)| o));
            continue;
        }
        let mut m = Observed {
            key: item.key(),
            item,
            count: 0,
            first: i64::MAX,
            last: i64::MIN,
            procs: BTreeSet::new(),
            merged: Vec::new(),
        };
        for (_, o) in members {
            absorb(&mut m, o);
        }
        out.push(m);
    }
    // A merged item can equal one that was there already.
    let mut by_key: BTreeMap<String, Observed> = BTreeMap::new();
    for o in out {
        match by_key.get_mut(&o.key) {
            Some(e) => {
                if e.merged.is_empty() {
                    e.merged.push(e.item.label());
                }
                absorb(e, o);
            }
            None => {
                by_key.insert(o.key.clone(), o);
            }
        }
    }
    by_key.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppRef;

    const JA4: &str = "t13d1714h1_5b57614c22b0_b505ce4c9bf3";
    const JA4_B: &str = "t13d181100_5d04281c6031_dc7e9eda0726";

    fn app(name: &str, version: Option<&str>) -> AppRef {
        AppRef { name: name.into(), id: Some("com.example".into()), version: version.map(String::from), team_id: None, kind: "cli".into(), engine: None }
    }
    fn hello(name: &str, version: Option<&str>, ja4: &str) -> Item {
        Item::Hello { os: "macos 27".into(), transport: "tcp".into(), ja4: ja4.into(), app: app(name, version) }
    }
    fn domain(name: &str, d: &str) -> Item {
        Item::Domain { os: "macos 27".into(), app: app(name, None), domain: d.into(), ja4: JA4.into() }
    }
    fn obs(item: Item, count: u64) -> Observed {
        Observed { key: item.key(), item, count, first: count as i64, last: count as i64, procs: BTreeSet::new(), merged: Vec::new() }
    }
    fn run(items: Vec<Item>, removed: &[&Item]) -> Vec<Observed> {
        let removed: BTreeSet<String> = removed.iter().map(|i| i.key()).collect();
        let out = merge(items.into_iter().enumerate().map(|(i, it)| obs(it, i as u64 + 1)).collect(), &removed);
        assert!(out.iter().all(|o| o.item.validate().is_ok() && o.key == o.item.key()));
        out
    }
    fn names(out: &[Observed]) -> BTreeSet<String> {
        out.iter()
            .map(|o| match &o.item {
                Item::Hello { app, ja4, .. } => format!("{} {} {}", app.name, app.version.as_deref().unwrap_or("-"), &ja4[..4]),
                Item::Domain { app, domain, .. } => format!("{} {}", app.name, domain),
                Item::Presence { .. } => "presence".into(),
            })
            .collect()
    }
    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn version_tokens() {
        let v = |s: &str| versions(s).into_iter().map(|(a, b)| s[a..b].to_string()).collect::<Vec<_>>();
        assert_eq!(v("2.1.322"), ["2.1.322"]);
        assert_eq!(v("chromium 157.0.8103.51"), ["157.0.8103.51"]);
        assert_eq!(v("Antidote 12"), Vec::<String>::new());
        assert_eq!(v("python3.12"), Vec::<String>::new());
        assert_eq!(v("1.2.3-beta 4.5.6."), ["1.2.3", "4.5.6"]);
    }

    /// Claude Code's binary is named after its version.
    #[test]
    fn versions_in_names_and_fields() {
        let out = run(
            vec![
                hello("2.1.322", None, JA4),
                hello("2.1.326", None, JA4),
                hello("2.1.326", None, JA4_B),
                hello("Chrome", Some("157.0.8103.51"), JA4),
                hello("Chrome", Some("157.0.8103.79"), JA4),
                hello("Chrome", Some("158.0.8140.2"), JA4),
            ],
            &[],
        );
        assert_eq!(names(&out), set(&["2.1.* - t13d", "2.1.326 - t13d", "Chrome 157.0.* t13d", "Chrome 158.0.8140.2 t13d"]));
        let m = out.iter().find(|o| o.key.contains("2.1.*")).unwrap();
        assert_eq!((m.count, m.first, m.last, m.merged.len()), (3, 1, 2, 2));
    }

    #[test]
    fn server_name_shards() {
        let out = run(
            vec![
                domain("Find My", "p177-fmip.icloud.com"),
                domain("Find My", "p63-fmip.icloud.com"),
                domain("Maps", "gspe1-ssl.ls.apple.com"),
                domain("Maps", "gspe35-ssl.ls.apple.com"),
                domain("Teams", "pub-ent-euwe-02-t.trouter.teams.microsoft.com"),
                domain("Teams", "pub-ent-euwe-08-t.trouter.teams.microsoft.com"),
                domain("Teams", "pub-ent-sece-04-t.trouter.teams.microsoft.com"),
                // Different letters: not shards of one name.
                domain("aws", "ssm.ap-south-1.amazonaws.com"),
                domain("aws", "ssm.eu-west-2.amazonaws.com"),
                // The last two labels never change.
                domain("x", "cdn2.org"),
                domain("x", "cdn3.org"),
            ],
            &[],
        );
        assert_eq!(
            names(&out),
            set(&[
                "Find My p*-fmip.icloud.com",
                "Maps gspe*-ssl.ls.apple.com",
                "Teams pub-ent-euwe-*-t.trouter.teams.microsoft.com",
                "Teams pub-ent-sece-04-t.trouter.teams.microsoft.com",
                "aws ssm.ap-south-1.amazonaws.com",
                "aws ssm.eu-west-2.amazonaws.com",
                "x cdn2.org",
                "x cdn3.org",
            ])
        );
    }

    /// Versions and shards together; different applications never merge.
    #[test]
    fn both_and_only_alike() {
        let out = run(
            vec![
                domain("2.1.322", "a1.cdn.example.com"),
                domain("2.1.323", "a7.cdn.example.com"),
                domain("2.1.323", "a1.cdn.example.com"),
                domain("claude", "a1.cdn.example.com"),
            ],
            &[],
        );
        assert_eq!(names(&out), set(&["2.1.* a*.cdn.example.com", "claude a1.cdn.example.com"]));
    }

    /// A removed item is never folded into a merged one.
    #[test]
    fn removed_items_stay_apart() {
        let (a, b, c) = (hello("2.1.322", None, JA4), hello("2.1.323", None, JA4), hello("2.1.325", None, JA4));
        let out = run(vec![a.clone(), b.clone(), c.clone()], &[&a]);
        assert_eq!(names(&out), set(&["2.1.322 - t13d", "2.1.* - t13d"]));
        let out = run(vec![a.clone(), b.clone()], &[&a]);
        assert_eq!(names(&out), set(&["2.1.322 - t13d", "2.1.323 - t13d"]));
    }
}
