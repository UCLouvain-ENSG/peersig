//! Which app a uid is, as the probe's records name apps (`attrib::App`).
//!
//! Android gives each app a uid, and the system says which uid owns a
//! connection (`ConnectivityManager.getConnectionOwnerUid`). The app's
//! Kotlin side reads what the package manager says of that uid
//! ([`PackageFacts`]); this module decides the name, version and kind, so
//! that the rules sit beside the desktop's, with the browser list of
//! `data/apps.toml`:
//!
//! - `name`: the app's label in English, whatever the phone's language
//!   (as Windows names apps by their version resource): the same app gives
//!   the same item on every phone. Its package name when it has no label.
//!   A uid that several packages share is named after the one that does
//!   the networking when it is known (Google Play services), and after the
//!   shared uid otherwise (`android.uid.phone`).
//! - `id`: the package name; `version`: its `versionName`.
//! - `kind`: `browser` when `apps.toml` lists the package, or when the app
//!   opens any web address (Android's own definition of a browser), so
//!   that the names browsers contact are never collected; `system` for the
//!   system's own uids (below 10000) and for apps signed with the
//!   platform's key (parts of Android itself); `cli` for the shell (adb);
//!   `app` otherwise.
//! - no `engine` and no `team_id`: another app's libraries and signature
//!   are not inspected.

use std::sync::Arc;

use serde::Deserialize;

use peersig_probe::attrib::{App, AppsDb, Process};

/// The first uid of apps (`AID_APP_START`): below are the system's own.
pub const FIRST_APP_UID: u32 = 10_000;
/// Users' uids are `user * 100000 + app id` (a work profile is a user).
const PER_USER: u32 = 100_000;
/// Isolated processes (renderers, sandboxed services) have no package.
const ISOLATED: std::ops::Range<u32> = 90_000..100_000;
const AID_SHELL: u32 = 2000;

/// Packages that, in a shared uid, are the app: Google Play services
/// shares its uid with Google Services Framework, and sends its traffic.
const SHARED_MAIN: &[&str] = &["com.google.android.gms"];

/// One package of a shared uid.
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(default)]
pub struct PackageApp {
    pub package: String,
    pub label: Option<String>,
    pub version: Option<String>,
}

/// What the package manager says of a uid (`Host.packageFacts` in the
/// app). Read in English, as the app sees it.
#[derive(Deserialize, Debug, Default, Clone)]
#[serde(default)]
pub struct PackageFacts {
    /// The packages that run under the uid: one, except for a shared uid.
    pub packages: Vec<String>,
    /// With one package: its label in English.
    pub label: Option<String>,
    /// With one package: its `versionName`.
    pub version: Option<String>,
    /// The name of a shared uid (`android.uid.system`).
    pub shared: Option<String>,
    /// With several packages: each one's label and version.
    pub apps: Vec<PackageApp>,
    /// One of the packages is signed with the platform's key.
    pub platform: bool,
    /// One of the packages opens any web address.
    pub browses: bool,
}

/// The system's own uids, from Android's `android_filesystem_config.h`.
fn system_uid_name(uid: u32) -> Option<&'static str> {
    Some(match uid {
        0 => "root",
        1000 => "system",
        1001 => "radio",
        1002 => "bluetooth",
        1010 => "wifi",
        1013 => "media",
        1016 => "vpn",
        1019 => "drm",
        1020 => "mdnsr",
        1021 => "gps",
        1041 => "audioserver",
        1047 => "cameraserver",
        1051 => "dns",
        1052 => "dns_tether",
        1073 => "network_stack",
        2000 => "shell",
        9999 => "nobody",
        _ => return None,
    })
}

fn clean(s: Option<&str>) -> Option<String> {
    let s = s?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// The app behind `uid`, and the process the logs name it by
/// (`uid:10123`, named after its package). None for an isolated process
/// or an app uid the package manager does not know.
pub fn app_of(uid: u32, facts: Option<&PackageFacts>, db: &AppsDb) -> Option<(Arc<Process>, App)> {
    let app_id = uid % PER_USER;
    let empty = PackageFacts::default();
    let f = facts.unwrap_or(&empty);
    let single = (f.packages.len() == 1).then(|| f.packages[0].as_str());
    if app_id >= FIRST_APP_UID && (ISOLATED.contains(&app_id) || f.packages.is_empty()) {
        return None;
    }
    let (name, id, version) = if f.packages.iter().any(|p| p == "android") {
        // system_server and the packages that share its uid.
        ("Android System".to_string(), Some("android".to_string()), None)
    } else if let Some(p) = single {
        (clean(f.label.as_deref()).unwrap_or_else(|| p.to_string()), Some(p.to_string()), clean(f.version.as_deref()))
    } else if let Some(a) = SHARED_MAIN.iter().find_map(|m| f.apps.iter().find(|a| a.package == *m)) {
        (clean(a.label.as_deref()).unwrap_or_else(|| a.package.clone()), Some(a.package.clone()), clean(a.version.as_deref()))
    } else if let Some(s) = clean(f.shared.as_deref()) {
        // Several packages: which one sent cannot be told.
        (s, None, None)
    } else {
        (system_uid_name(app_id).map(str::to_string).unwrap_or_else(|| format!("uid {}", app_id)), None, None)
    };
    let browser = f.packages.iter().find_map(|p| db.browser(Some(p), "")).or_else(|| f.browses.then(|| "other".to_string()));
    let kind = if browser.is_some() {
        "browser"
    } else if app_id == AID_SHELL {
        "cli"
    } else if app_id < FIRST_APP_UID || f.platform {
        "system"
    } else {
        "app"
    };
    let proc_name = single.map(str::to_string).or_else(|| clean(f.shared.as_deref())).unwrap_or_else(|| name.clone());
    let app = App {
        name,
        id,
        version,
        team_id: None,
        kind: kind.into(),
        browser,
        engine: None,
        detail: None,
        via: "uid".into(),
        path: None,
    };
    Some((Arc::new(Process::of_uid(uid, &proc_name)), app))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(packages: &[&str], label: Option<&str>, version: Option<&str>) -> PackageFacts {
        PackageFacts {
            packages: packages.iter().map(|s| s.to_string()).collect(),
            label: label.map(str::to_string),
            version: version.map(str::to_string),
            ..Default::default()
        }
    }

    fn kind_name(uid: u32, f: Option<&PackageFacts>) -> Option<(String, String)> {
        let db = AppsDb::load();
        app_of(uid, f, &db).map(|(_, a)| (a.kind, a.name))
    }

    #[test]
    fn apps_and_browsers() {
        let db = AppsDb::load();
        let (p, a) = app_of(10_123, Some(&facts(&["com.whatsapp"], Some("WhatsApp"), Some("2.24.25.78"))), &db).unwrap();
        assert_eq!((a.name.as_str(), a.id.as_deref(), a.version.as_deref(), a.kind.as_str()), ("WhatsApp", Some("com.whatsapp"), Some("2.24.25.78"), "app"));
        assert_eq!((p.id.as_str(), p.name.as_str(), p.uid), ("uid:10123", "com.whatsapp", Some(10_123)));
        // A work profile's copy is the same app.
        assert_eq!(app_of(1_010_123, Some(&facts(&["com.whatsapp"], Some("WhatsApp"), None)), &db).unwrap().1.kind, "app");
        // Listed browsers, and any app that opens web addresses.
        assert_eq!(kind_name(10_200, Some(&facts(&["com.android.chrome"], Some("Chrome"), Some("131.0.6778.81")))).unwrap().0, "browser");
        let mut unlisted = facts(&["com.example.browser"], Some("Example Browser"), None);
        assert_eq!(kind_name(10_201, Some(&unlisted)).unwrap().0, "app");
        unlisted.browses = true;
        assert_eq!(kind_name(10_201, Some(&unlisted)).unwrap().0, "browser");
        // No label: the package name.
        assert_eq!(kind_name(10_202, Some(&facts(&["org.example.tool"], Some("  "), None))).unwrap().1, "org.example.tool");
    }

    #[test]
    fn system_uids() {
        let mut sys = facts(&["android", "com.android.settings", "com.android.providers.settings"], None, None);
        sys.shared = Some("android.uid.system".into());
        sys.platform = true;
        assert_eq!(kind_name(1000, Some(&sys)), Some(("system".into(), "Android System".into())));
        assert_eq!(kind_name(1051, None), Some(("system".into(), "dns".into())));
        assert_eq!(kind_name(0, None), Some(("system".into(), "root".into())));
        assert_eq!(kind_name(2000, Some(&facts(&["com.android.shell"], Some("Shell"), Some("15")))).unwrap().0, "cli");
        // Apps signed with the platform's key are part of Android.
        let mut phone = facts(&["com.android.phone"], Some("Phone Services"), Some("15"));
        phone.platform = true;
        assert_eq!(kind_name(10_001, Some(&phone)).unwrap().0, "system");
        // A shared app uid is named by its shared name...
        let mut shared = facts(&["com.example.a", "com.example.b"], None, None);
        shared.shared = Some("com.example.shared".into());
        let (p, a) = app_of(10_150, Some(&shared), &AppsDb::load()).unwrap();
        assert_eq!((a.name.as_str(), a.id, a.version, p.name.as_str()), ("com.example.shared", None, None, "com.example.shared"));
        // ... unless it is Google Play services'.
        let mut gms = facts(&["com.google.android.gms", "com.google.android.gsf"], None, None);
        gms.shared = Some("com.google.uid.shared".into());
        gms.apps = vec![
            PackageApp { package: "com.google.android.gsf".into(), label: Some("Google Services Framework".into()), version: Some("15".into()) },
            PackageApp { package: "com.google.android.gms".into(), label: Some("Google Play services".into()), version: Some("24.26.32 (190400-650348051)".into()) },
        ];
        let (_, a) = app_of(10_151, Some(&gms), &AppsDb::load()).unwrap();
        assert_eq!((a.name.as_str(), a.id.as_deref(), a.version.as_deref(), a.kind.as_str()), ("Google Play services", Some("com.google.android.gms"), Some("24.26.32 (190400-650348051)"), "app"));
    }

    #[test]
    fn unknown() {
        // Isolated processes, and app uids without a package.
        assert!(kind_name(99_005, Some(&facts(&["com.android.chrome"], None, None))).is_none());
        assert!(kind_name(10_999, None).is_none());
    }
}
