//! macOS: the review's names, asked of Apple's on-device language model
//! (Apple Intelligence) through `peersig-hint` (crates/app/hint), which the
//! app ships next to its executable. The model runs on the Mac: the names
//! do not leave it. Other systems have no model here (the list of
//! sensitive words still applies).

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use peersig_client::review::ModelReply;
use serde_json::Value;

/// `peersig-hint` next to the app's executable (macOS only).
pub fn helper() -> Option<PathBuf> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let p = std::env::current_exe().ok()?.parent()?.join("peersig-hint");
    p.exists().then_some(p)
}

/// Asks the model about `names`; gives up after 30 seconds a name.
pub fn ask(names: &[String]) -> ModelReply {
    let Some(exe) = helper() else { return ModelReply::Unavailable("no model in this version of PeerSig".into()) };
    let mut child = match Command::new(exe).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
        Ok(c) => c,
        Err(e) => return ModelReply::Error(format!("cannot start the model's helper: {}", e)),
    };
    let request = serde_json::json!({ "entries": names }).to_string();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(request.as_bytes());
    }
    let deadline = Instant::now() + Duration::from_secs(60 + 30 * names.len() as u64);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return ModelReply::Error("the model did not answer in time".into());
            }
        }
    }
    let mut out = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut out);
    }
    let Ok(r) = serde_json::from_str::<Value>(out.trim()) else { return ModelReply::Error("the model's helper gave no answer".into()) };
    let detail = r.get("detail").and_then(Value::as_str).map(String::from);
    match r.get("status").and_then(Value::as_str) {
        Some("ok") => ModelReply::Flags(
            r.get("flags")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|f| Some((f.get("entry")?.as_u64()? as usize, f.get("reason")?.as_str()?.to_string())))
                        .filter(|(i, _)| *i < names.len())
                        .collect()
                })
                .unwrap_or_default(),
        ),
        Some("unavailable") => ModelReply::Unavailable(detail.unwrap_or_else(|| "Apple Intelligence is not available".into())),
        other => ModelReply::Error(detail.unwrap_or_else(|| other.unwrap_or("no status").to_string())),
    }
}
