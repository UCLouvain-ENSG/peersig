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

/// Package manager installs, from the path: Homebrew Cellar/Caskroom, Nix.
#[derive(Debug, Clone, Serialize)]
pub struct Package {
    pub manager: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

pub fn package_of(path: &str) -> Option<Package> {
    let parts: Vec<&str> = path.split('/').collect();
    for (i, p) in parts.iter().enumerate() {
        if *p == "Cellar" || *p == "Caskroom" {
            let name = parts.get(i + 1)?;
            return Some(Package {
                manager: if *p == "Cellar" { "homebrew" } else { "homebrew-cask" }.into(),
                name: name.to_string(),
                version: parts.get(i + 2).map(|s| s.to_string()),
            });
        }
        if *p == "store" && i > 0 && parts[i - 1] == "nix" {
            let entry = parts.get(i + 1)?;
            let nv = entry.get(33..).unwrap_or(entry);
            return Some(Package { manager: "nix".into(), name: nv.to_string(), version: None });
        }
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
    }
}
