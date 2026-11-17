//! Bundles around an executable (innermost first) and the web engine they
//! embed. A Chrome network helper lives in
//! `Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/
//! Versions/<v>/Helpers/Google Chrome Helper.app`: the chain is the helper,
//! the framework (Chromium <v>), then Google Chrome.app.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Bundle {
    pub kind: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
}

impl Bundle {
    pub fn from_dict(kind: &str, path: &str, d: &plist::Dictionary) -> Bundle {
        let s = |k: &str| d.get(k).and_then(|v| v.as_string()).map(str::to_string).filter(|s| !s.is_empty());
        Bundle {
            kind: kind.into(),
            path: path.into(),
            id: s("CFBundleIdentifier"),
            name: s("CFBundleDisplayName").or_else(|| s("CFBundleName")),
            version: s("CFBundleShortVersionString"),
            build: s("CFBundleVersion"),
        }
    }
    /// Short version, else the build number.
    pub fn best_version(&self) -> Option<String> {
        self.version.clone().or_else(|| self.build.clone())
    }
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            Path::new(&self.path).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default()
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Engine {
    /// chromium, electron, cef, gecko, webkit
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The framework or file it was recognised by.
    pub via: String,
}

impl Engine {
    pub fn label(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {}", self.name, v),
            None => self.name.clone(),
        }
    }
}

const BUNDLE_EXTS: &[&str] =
    &["app", "appex", "xpc", "framework", "bundle", "plugin", "jdk", "systemextension", "kext", "driver", "dext"];

#[derive(Default)]
pub struct Bundles {
    cache: HashMap<PathBuf, Option<plist::Dictionary>>,
}

fn read_plist(p: &Path) -> Option<plist::Dictionary> {
    match plist::Value::from_file(p).ok()? {
        plist::Value::Dictionary(d) => Some(d),
        _ => None,
    }
}

impl Bundles {
    fn plist(&mut self, p: PathBuf) -> Option<plist::Dictionary> {
        self.cache.entry(p.clone()).or_insert_with(|| read_plist(&p)).clone()
    }

    /// Info.plist of a bundle directory. `version_dir` is the framework
    /// version the executable runs from (`Versions/<v>/...`), when known.
    fn info(&mut self, dir: &Path, version_dir: Option<&str>) -> Option<plist::Dictionary> {
        let mut cands: Vec<PathBuf> = Vec::new();
        if let Some(v) = version_dir {
            cands.push(dir.join("Versions").join(v).join("Resources/Info.plist"));
        }
        cands.push(dir.join("Contents/Info.plist"));
        cands.push(dir.join("Resources/Info.plist"));
        cands.push(dir.join("Versions/Current/Resources/Info.plist"));
        cands.push(dir.join("Info.plist"));
        for c in cands {
            if c.is_file() {
                if let Some(d) = self.plist(c) {
                    return Some(d);
                }
            }
        }
        None
    }

    pub fn chain(&mut self, exe: &Path) -> Vec<Bundle> {
        let mut out = Vec::new();
        let comps: Vec<_> = exe.components().collect();
        for i in (0..comps.len()).rev() {
            let dir: PathBuf = comps[..=i].iter().collect();
            let Some(ext) = dir.extension().and_then(|e| e.to_str()) else { continue };
            if !BUNDLE_EXTS.contains(&ext) || dir.as_path() == exe {
                continue;
            }
            // Framework executables run from Versions/<v>/.
            let version_dir = (ext == "framework")
                .then(|| {
                    let next = comps.get(i + 1)?.as_os_str().to_str()?;
                    (next == "Versions").then(|| comps.get(i + 2)?.as_os_str().to_str())?
                })
                .flatten();
            let path = dir.to_string_lossy().into_owned();
            let b = match self.info(&dir, version_dir) {
                Some(d) => Bundle::from_dict(ext, &path, &d),
                None => Bundle { kind: ext.into(), path, id: None, name: None, version: None, build: None },
            };
            out.push(b);
        }
        out
    }

    /// The engine a process runs on: from its own bundle chain first (a
    /// helper inside a Chromium framework), then the frameworks its apps
    /// embed (innermost app first: Teams' WebView app before Teams).
    pub fn engine(&mut self, exe: &Path, chain: &[Bundle]) -> Option<Engine> {
        let exe_name = exe.file_name()?.to_string_lossy();
        if exe_name.starts_with("com.apple.WebKit.") || chain.iter().any(|b| b.id.as_deref() == Some("com.apple.WebKit")) {
            let wk = chain.iter().find(|b| b.id.as_deref() == Some("com.apple.WebKit"));
            return Some(Engine {
                name: "webkit".into(),
                version: wk.and_then(|b| b.build.clone()),
                via: "WebKit.framework".into(),
            });
        }
        for b in chain.iter().filter(|b| b.kind == "framework") {
            if let Some(e) = self.framework_engine(Path::new(&b.path), b) {
                return Some(e);
            }
        }
        for b in chain.iter().filter(|b| b.kind == "app") {
            let app = Path::new(&b.path);
            if app.join("Contents/MacOS/XUL").is_file() {
                let milestone = std::fs::read_to_string(app.join("Contents/Resources/platform.ini"))
                    .ok()
                    .and_then(|s| s.lines().find_map(|l| l.strip_prefix("Milestone=").map(|v| v.trim().to_string())));
                return Some(Engine { name: "gecko".into(), version: milestone.or_else(|| b.best_version()), via: "XUL".into() });
            }
            let Ok(rd) = std::fs::read_dir(app.join("Contents/Frameworks")) else { continue };
            let mut fws: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().map_or(false, |e| e == "framework")).collect();
            fws.sort();
            for fw in fws {
                let Some(d) = self.info(&fw, None) else { continue };
                let fb = Bundle::from_dict("framework", &fw.to_string_lossy(), &d);
                if let Some(e) = self.framework_engine(&fw, &fb) {
                    return Some(e);
                }
            }
        }
        None
    }

    fn framework_engine(&mut self, fw: &Path, b: &Bundle) -> Option<Engine> {
        let name = fw.file_stem()?.to_string_lossy().into_owned();
        if name == "Electron Framework" {
            return Some(Engine { name: "electron".into(), version: b.build.clone().or_else(|| b.version.clone()), via: name });
        }
        if name == "Chromium Embedded Framework" {
            return Some(Engine { name: "cef".into(), version: b.best_version(), via: name });
        }
        // Chromium browsers and Edge WebView: "<Product> Framework" with
        // the helper apps inside.
        let has_helpers = fw.join("Helpers").is_dir()
            || fw.join("Versions/Current/Helpers").is_dir()
            || b.version.as_ref().map_or(false, |v| fw.join("Versions").join(v).join("Helpers").is_dir());
        if name.ends_with(" Framework") && has_helpers {
            return Some(Engine { name: "chromium".into(), version: b.version.clone(), via: name });
        }
        None
    }
}

/// Package manager installs, from the path: Homebrew Cellar/Caskroom, Nix;
/// on Windows, MSIX/Store packages (`WindowsApps\<full name>`) and Scoop.
#[derive(Debug, Clone, Serialize)]
pub struct Package {
    pub manager: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// MSIX package family name (`MSTeams_8wekyb3d8bbwe`): the app's
    /// identity whatever its version, like a bundle id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// MSIX: the name in the package manifest.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// The `<DisplayName>` of an MSIX package's manifest (`WindowsApps\<full
/// name>\AppxManifest.xml`), unless it points to a translated resource.
pub fn msix_display_name(exe_path: &str) -> Option<String> {
    const DIR: &str = "\\windowsapps\\";
    let i = exe_path.to_ascii_lowercase().find(DIR)? + DIR.len();
    let pkg = exe_path[i..].split('\\').next()?;
    let manifest = Path::new(&exe_path[..i]).join(pkg).join("AppxManifest.xml");
    let xml = std::fs::read_to_string(manifest).ok()?;
    let props = &xml[xml.find("<Properties>")?..];
    let s = props.find("<DisplayName>")? + "<DisplayName>".len();
    let e = s + props[s..].find("</DisplayName>")?;
    let name = props[s..e]
        .trim()
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");
    (!name.is_empty() && !name.starts_with("ms-resource:") && name.chars().count() <= 128).then_some(name)
}

pub fn package_of(path: &str) -> Option<Package> {
    let parts: Vec<&str> = path.split(['/', '\\']).collect();
    for (i, p) in parts.iter().enumerate() {
        if *p == "Cellar" || *p == "Caskroom" {
            let name = parts.get(i + 1)?;
            return Some(Package {
                manager: if *p == "Cellar" { "homebrew" } else { "homebrew-cask" }.into(),
                name: name.to_string(),
                version: parts.get(i + 2).map(|s| s.to_string()),
                family: None,
                display_name: None,
            });
        }
        if *p == "store" && i > 0 && parts[i - 1] == "nix" {
            let entry = parts.get(i + 1)?;
            let nv = entry.get(33..).unwrap_or(entry);
            return Some(Package { manager: "nix".into(), name: nv.to_string(), version: None, family: None, display_name: None });
        }
        // Name_Version_Architecture_ResourceId_PublisherId
        if p.eq_ignore_ascii_case("WindowsApps") {
            let f: Vec<&str> = parts.get(i + 1)?.split('_').collect();
            if f.len() == 5 && !f[0].is_empty() && f[1].chars().all(|c| c.is_ascii_digit() || c == '.') {
                return Some(Package {
                    manager: "msix".into(),
                    name: f[0].to_string(),
                    version: Some(f[1].to_string()),
                    family: Some(format!("{}_{}", f[0], f[4])),
                    display_name: None,
                });
            }
        }
        if p.eq_ignore_ascii_case("scoop") && parts.get(i + 1).is_some_and(|a| a.eq_ignore_ascii_case("apps")) {
            let name = parts.get(i + 2)?;
            let version = parts.get(i + 3).filter(|v| !v.eq_ignore_ascii_case("current")).map(|v| v.to_string());
            return Some(Package { manager: "scoop".into(), name: name.to_string(), version, family: None, display_name: None });
        }
    }
    None
}

/// Directory names Chromium browsers install their version in
/// (`Application\131.0.6778.86\chrome.dll`).
fn is_version_dir(name: &str) -> bool {
    let p: Vec<&str> = name.split('.').collect();
    p.len() >= 3 && p.iter().all(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
}

fn version_key(v: &str) -> Vec<u64> {
    v.split('.').map(|x| x.parse().unwrap_or(0)).collect()
}

/// The library a Chromium build keeps next to its version directory.
const CHROMIUM_DLLS: &[&str] = &["chrome.dll", "msedge.dll", "vivaldi.dll", "opera_browser.dll"];

/// The web engine of a Windows executable, from the files installed with
/// it (nothing is run):
/// - Chromium browsers and Edge WebView2: a version directory holding the
///   browser DLL, beside the executable or around it (`chromium <v>`; for
///   a browser that numbers its own versions, like Brave, `<v>` is that
///   number, as on macOS);
/// - CEF: libcef.dll, versioned by its resource;
/// - Electron: an `app.asar` (or `app` folder) in `resources`, with
///   Chromium's paks; the version from a `version` file when it shipped;
/// - Gecko: xul.dll, versioned by `platform.ini`'s Milestone.
///
/// `exe_version` is the executable's own product version: during an update
/// two version directories exist, and the running one has that number.
pub fn windows_engine(exe: &Path, exe_version: Option<&str>) -> Option<Engine> {
    let dir = exe.parent()?;
    let has = |d: &Path, f: &str| d.join(f).is_file();
    // The executable runs from the version directory (msedgewebview2.exe).
    if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
        if is_version_dir(name) {
            if let Some(dll) = CHROMIUM_DLLS.iter().find(|d| has(dir, d)) {
                return Some(Engine { name: "chromium".into(), version: Some(name.to_string()), via: dll.to_string() });
            }
        }
    }
    // The version directory is beside the executable (chrome.exe).
    let mut versions: Vec<(String, &str)> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if !is_version_dir(&n) {
                        return None;
                    }
                    let dll = CHROMIUM_DLLS.iter().find(|d| has(&e.path(), d))?;
                    Some((n, *dll))
                })
                .collect()
        })
        .unwrap_or_default();
    versions.sort_by_key(|(v, _)| version_key(v));
    let running = exe_version.and_then(|ev| versions.iter().find(|(v, _)| v == ev));
    if let Some((v, dll)) = running.or(versions.last()) {
        return Some(Engine { name: "chromium".into(), version: Some(v.clone()), via: dll.to_string() });
    }
    if has(dir, "libcef.dll") {
        let v = crate::binary::pe_version(&dir.join("libcef.dll"));
        let version = v.as_ref().and_then(|v| v.product_version.clone().or_else(|| v.file_version.clone()));
        return Some(Engine { name: "cef".into(), version, via: "libcef.dll".into() });
    }
    if has(dir, "xul.dll") {
        let ini = |f: &str, k: &str| {
            std::fs::read_to_string(dir.join(f))
                .ok()
                .and_then(|s| s.lines().find_map(|l| l.strip_prefix(k).map(|v| v.trim().to_string())))
        };
        let version = ini("platform.ini", "Milestone=").or_else(|| ini("application.ini", "Version="));
        return Some(Engine { name: "gecko".into(), version, via: "xul.dll".into() });
    }
    let res = dir.join("resources");
    let paks = has(dir, "chrome_100_percent.pak") || has(dir, "resources.pak") || has(dir, "v8_context_snapshot.bin");
    if paks && (res.join("app.asar").is_file() || res.join("app").is_dir() || res.join("default_app.asar").is_file()) {
        let version = std::fs::read_to_string(dir.join("version"))
            .ok()
            .map(|s| s.trim().trim_start_matches('v').to_string())
            .filter(|s| !s.is_empty() && s.len() < 32);
        return Some(Engine { name: "electron".into(), version, via: "resources\\app.asar".into() });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages() {
        let p = package_of("/opt/homebrew/Cellar/curl/8.11.0/bin/curl").unwrap();
        assert_eq!((p.manager.as_str(), p.name.as_str(), p.version.as_deref()), ("homebrew", "curl", Some("8.11.0")));
        let p = package_of("/nix/store/0123456789abcdefghijklmnopqrstuv-curl-8.4.0/bin/curl").unwrap();
        assert_eq!(p.name, "curl-8.4.0");
        assert!(package_of("/usr/bin/curl").is_none());
        let p = package_of(r"C:\Program Files\WindowsApps\MSTeams_25290.205.4069.4894_x64__8wekyb3d8bbwe\ms-teams.exe").unwrap();
        assert_eq!(
            (p.manager.as_str(), p.name.as_str(), p.version.as_deref(), p.family.as_deref()),
            ("msix", "MSTeams", Some("25290.205.4069.4894"), Some("MSTeams_8wekyb3d8bbwe"))
        );
        let p = package_of(r"C:\Users\x\scoop\apps\curl\8.11.0_1\bin\curl.exe").unwrap();
        assert_eq!((p.manager.as_str(), p.name.as_str(), p.version.as_deref()), ("scoop", "curl", Some("8.11.0_1")));
        assert!(package_of(r"C:\Program Files\Google\Chrome\Application\chrome.exe").is_none());
    }

    /// Install layouts, made in a temporary directory.
    #[test]
    fn windows_engines() {
        let root = std::env::temp_dir().join(format!("peersig-engines-{}", std::process::id()));
        let mk = |rel: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"").unwrap();
            p
        };
        let chrome = mk("Chrome/Application/chrome.exe");
        mk("Chrome/Application/130.0.6723.117/chrome.dll");
        mk("Chrome/Application/131.0.6778.86/chrome.dll");
        let e = windows_engine(&chrome, None).unwrap();
        assert_eq!((e.name.as_str(), e.version.as_deref()), ("chromium", Some("131.0.6778.86")));
        // The running version, when the update has not been applied yet.
        assert_eq!(windows_engine(&chrome, Some("130.0.6723.117")).unwrap().version.as_deref(), Some("130.0.6723.117"));
        let wv = mk("EdgeWebView/Application/131.0.2903.70/msedgewebview2.exe");
        mk("EdgeWebView/Application/131.0.2903.70/msedge.dll");
        assert_eq!(windows_engine(&wv, None).unwrap().label(), "chromium 131.0.2903.70");
        let ff = mk("Firefox/firefox.exe");
        mk("Firefox/xul.dll");
        std::fs::write(root.join("Firefox/platform.ini"), "[Build]\nMilestone=133.0\n").unwrap();
        assert_eq!(windows_engine(&ff, None).unwrap().label(), "gecko 133.0");
        let code = mk("Code/Code.exe");
        mk("Code/chrome_100_percent.pak");
        mk("Code/resources/app.asar");
        assert_eq!(windows_engine(&code, None).unwrap().label(), "electron");
        let plain = mk("Tool/tool.exe");
        assert!(windows_engine(&plain, None).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
