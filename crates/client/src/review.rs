//! Which items the review shows first, and why. A week holds hundreds or
//! thousands of items: the participant cannot read them all, so items that
//! could say something about them come first:
//!
//! - the list of sensitive words (`peersig_proto::sensitive`): health,
//!   dating, religion...;
//! - their own words: the account's name, their full name, words they
//!   added in Settings;
//! - where the device has a language model of its own (macOS: Apple
//!   Intelligence), what it says of each application and server name.
//!
//! All of it stays on the device: the model runs there, and only orders
//! what the participant sees. Nothing is removed without them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use peersig_proto::sensitive::{self, Reason};
use peersig_proto::{AppRef, Item};

/// Why an item is shown first.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Flag {
    /// `list` (sensitive words), `own` (the participant's words) or
    /// `model` (the device's model).
    pub by: &'static str,
    pub why: String,
}

/// What the device's model said of a batch of names.
#[derive(Debug)]
pub enum ModelReply {
    /// The names it flagged (their index in the batch), each with why.
    Flags(Vec<(usize, String)>),
    /// No model, or it is off: why, for the window.
    Unavailable(String),
    Error(String),
}

/// What the device's model said so far, kept in `model.json` next to the
/// state, so that each name is asked about once.
#[derive(Serialize, Deserialize, Default)]
pub struct Answers {
    /// Each name asked about, with why it was flagged (`None`: ordinary).
    pub names: BTreeMap<String, Option<String>>,
}

/// At most this many names are kept (about a year of a busy computer).
const MAX_ANSWERS: usize = 50_000;

impl Answers {
    pub fn path(state: &Path) -> PathBuf {
        state.with_file_name("model.json")
    }

    pub fn load(state: &Path) -> Answers {
        std::fs::read(Self::path(state)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self, state: &Path) -> std::io::Result<()> {
        let path = Self::path(state);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &path)
    }

    /// Records a batch's answers.
    pub fn record(&mut self, names: &[String], flags: &[(usize, String)]) {
        if self.names.len() + names.len() > MAX_ANSWERS {
            self.names.clear();
        }
        for n in names {
            self.names.insert(n.clone(), None);
        }
        for (i, why) in flags {
            if let Some(n) = names.get(*i) {
                self.names.insert(n.clone(), Some(why.clone()));
            }
        }
    }
}

fn app_name(app: &AppRef) -> String {
    match &app.id {
        Some(id) if id != &app.name => format!("Application: {} ({})", app.name, id),
        _ => format!("Application: {}", app.name),
    }
}

fn words(s: &str) -> Vec<String> {
    s.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| w.len() >= 3).map(String::from).collect()
}

/// A server name that carries its application's vendor (teams.microsoft.com
/// for Microsoft Teams, *.apple.com for com.apple.*): the vendor's own
/// server, nothing more to learn from it.
fn vendors_own(app: &AppRef, domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    let site = labels[labels.len().saturating_sub(2)];
    let mut aw = words(&app.name);
    if let Some(id) = &app.id {
        aw.extend(words(id));
    }
    words(site).iter().any(|w| aw.contains(w))
}

/// What the device's model is asked about an item, as it reads it: the
/// application, and the server name with the application that contacted it
/// (the model judges a name better knowing who uses it). Not the system's
/// own components: their names (familycircled, searchpartyd) misled it,
/// and they say nothing of the person but the system.
pub fn subjects(item: &Item) -> Vec<String> {
    let app_subject = |app: &AppRef| if app.kind == "system" { vec![] } else { vec![app_name(app)] };
    match item {
        Item::Hello { app, .. } => app_subject(app),
        Item::Domain { app, domain, .. } => {
            let mut v = app_subject(app);
            if !vendors_own(app, domain) {
                v.push(format!("Server name: {} (used by the application {})", domain, app.name));
            }
            v
        }
        Item::Presence { .. } => vec![],
    }
}

/// Why the review shows `item` first: empty for most items.
pub fn flags(item: &Item, own: &[String], answers: &Answers) -> Vec<Flag> {
    let reasons = sensitive::reasons(item, own);
    let found: Vec<&String> = reasons.iter().filter_map(|r| if let Reason::Own(w) = r { Some(w) } else { None }).collect();
    let mut out: Vec<Flag> = reasons
        .iter()
        .filter_map(|r| match r {
            Reason::Category(c) => Some(Flag { by: "list", why: c.clone() }),
            // "barbette" goes without saying next to "tombarbette".
            Reason::Own(w) if found.iter().any(|f| f.len() > w.len() && f.contains(w.as_str())) => None,
            Reason::Own(w) => Some(Flag { by: "own", why: w.clone() }),
        })
        .collect();
    for s in subjects(item) {
        if let Some(Some(why)) = answers.names.get(&s) {
            let f = Flag { by: "model", why: why.clone() };
            if !out.contains(&f) {
                out.push(f);
            }
        }
    }
    out
}

/// The participant's own words: the system's (`local::own_words`), then
/// those added in Settings, cut into words.
pub fn own_words(system: &[String], added: &[String]) -> Vec<String> {
    let mut out: Vec<String> = system.to_vec();
    for w in added.iter().flat_map(|a| a.split(|c: char| !c.is_alphanumeric())).filter_map(sensitive::own_word) {
        if !out.contains(&w) {
            out.push(w);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str, id: Option<&str>) -> AppRef {
        AppRef { name: name.into(), id: id.map(String::from), version: None, team_id: None, kind: "app".into(), engine: None }
    }
    fn domain(a: AppRef, d: &str) -> Item {
        Item::Domain { os: "macos 27".into(), app: a, domain: d.into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into() }
    }

    #[test]
    fn subjects_skip_the_vendors_own_servers() {
        let teams = app("Microsoft Teams", Some("com.microsoft.teams2"));
        assert_eq!(subjects(&domain(teams.clone(), "teams.microsoft.com")), vec!["Application: Microsoft Teams (com.microsoft.teams2)"]);
        let siri = app("Siri", Some("com.apple.siri.embeddedspeech"));
        assert_eq!(subjects(&domain(siri, "guzzoni.apple.com")).len(), 1);
        let mut daemon = app("familycircled", Some("com.apple.familycircled"));
        daemon.kind = "system".into();
        assert!(subjects(&Item::Hello { os: "macos 27".into(), transport: "tcp".into(), ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(), app: daemon.clone() }).is_empty());
        assert_eq!(subjects(&domain(daemon, "familycircle.example.net")), vec!["Server name: familycircle.example.net (used by the application familycircled)"]);
        let nc = app("Nextcloud", Some("com.nextcloud.desktopclient"));
        assert_eq!(
            subjects(&domain(nc, "cloud.example.org"))[1],
            "Server name: cloud.example.org (used by the application Nextcloud)"
        );
    }

    #[test]
    fn flags_from_every_source() {
        let nc = domain(app("Nextcloud", Some("com.nextcloud.desktopclient")), "cloud.tombarbette.be");
        let own = own_words(&["tbarbette".into(), "tombarbette".into()], &["Barbette, Tom".into()]);
        assert_eq!(own, vec!["tbarbette", "tombarbette", "barbette"]);
        let mut answers = Answers::default();
        let names = subjects(&nc);
        answers.record(&names, &[(1, "a personal, family or small association server".into())]);
        assert_eq!(answers.names.len(), 2);
        let f = flags(&nc, &own, &answers);
        assert_eq!(
            f,
            vec![
                Flag { by: "own", why: "tombarbette".into() },
                Flag { by: "model", why: "a personal, family or small association server".into() }
            ]
        );
        let teams = domain(app("Microsoft Teams", Some("com.microsoft.teams2")), "teams.microsoft.com");
        assert!(flags(&teams, &own, &answers).is_empty());
    }
}
