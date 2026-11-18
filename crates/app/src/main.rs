//! PeerSig tray app. It shows what the probe collected, lets the
//! participant remove items, and sends each week's report as anonymous
//! ballots. The tray icon changes while ballots are being sent. With an
//! observer's code, it sends each day's report instead (see core.rs).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;
mod local;
mod probe;

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent, Wry};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_notification::NotificationExt;
use tokio::sync::{Mutex, Notify};

use crate::core::{now, utc_day, Core, ReportState};

type Shared = Arc<Mutex<Core>>;
struct Wake(Arc<Notify>);

struct Tray {
    status: MenuItem<Wry>,
    report: MenuItem<Wry>,
    send: MenuItem<Wry>,
    pause: CheckMenuItem<Wry>,
}

#[cfg(target_os = "linux")]
struct Child(std::sync::Mutex<Option<std::process::Child>>);

const ICON_IDLE: &[u8] = include_bytes!("../icons/tray.png");
const ICON_SENDING: &[u8] = include_bytes!("../icons/tray-sending.png");
const ICON_PAUSED: &[u8] = include_bytes!("../icons/tray-paused.png");

fn notify(app: &AppHandle, body: &str) {
    let _ = app.notification().builder().title("PeerSig").body(body).show();
}

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

type R<T> = Result<T, String>;

fn e2s(e: impl std::fmt::Display) -> String {
    e.to_string()
}

// ---------------------------------------------------------------- commands

#[tauri::command]
async fn get_state(core: State<'_, Shared>) -> R<core::View> {
    Ok(core.lock().await.view())
}

/// Items of the epoch being reported, or of the current one (`current`).
#[tauri::command]
async fn get_items(core: State<'_, Shared>, current: bool) -> R<serde_json::Value> {
    let mut c = core.lock().await;
    let Some(cy) = c.cycle() else { return Ok(json!(null)) };
    let epoch = if current { cy.current } else { cy.report };
    let Some((items, skipped)) = c.items(epoch) else { return Ok(json!(null)) };
    let excluded = c.p.excluded.clone();
    let items: Vec<serde_json::Value> = items
        .into_iter()
        .map(|o| {
            let mut v = serde_json::to_value(&o).unwrap_or_default();
            v["excluded"] = json!(excluded.contains(&o.key));
            v
        })
        .collect();
    Ok(json!({
        "epoch": epoch,
        "from": cy.spec.start(epoch),
        "to": cy.spec.end(epoch),
        "current": current,
        "items": items,
        "skipped": skipped,
    }))
}

#[tauri::command]
async fn set_excluded(app: AppHandle, core: State<'_, Shared>, key: String, excluded: bool) -> R<()> {
    let mut c = core.lock().await;
    if excluded {
        c.p.excluded.insert(key);
    } else {
        c.p.excluded.remove(&key);
    }
    c.save().map_err(e2s)?;
    let _ = app.emit("state", c.view());
    Ok(())
}

#[tauri::command]
async fn enroll(
    core: State<'_, Shared>,
    wake: State<'_, Wake>,
    server: String,
    relay: String,
    code: String,
    share_domains: bool,
) -> R<()> {
    let mut s = core.lock().await.p.settings.clone();
    s.server = server.trim().trim_end_matches('/').to_string();
    s.relay = relay.trim().trim_end_matches('/').to_string();
    s.code = code.trim().to_uppercase();
    s.share_domains = share_domains;
    if s.server.is_empty() || s.code.is_empty() {
        return Err("The server address and the enrollment code are both needed.".into());
    }
    // A dedicated observer runs unattended: its daily report goes out
    // shortly after midnight (UTC). Settings can add a review.
    if s.observer() {
        s.review_hours = 0;
    }
    // Checks the server, and the relay's and server's keys agree.
    let cfg = s.client().map_err(e2s)?.config().await.map_err(|e| format!("Cannot reach the server: {:#}", e))?;
    s.consented = Some(chrono::Utc::now().to_rfc3339());
    let mut c = core.lock().await;
    c.p.settings = s;
    c.config = Some((now(), cfg));
    c.last_error = None;
    c.save().map_err(e2s)?;
    wake.0.notify_one();
    Ok(())
}

#[tauri::command]
async fn save_settings(
    core: State<'_, Shared>,
    wake: State<'_, Wake>,
    relay: String,
    share_domains: bool,
    review_hours: u32,
    spread_minutes: u32,
) -> R<()> {
    let mut c = core.lock().await;
    let s = &mut c.p.settings;
    s.relay = relay.trim().trim_end_matches('/').to_string();
    s.share_domains = share_domains;
    s.review_hours = review_hours.clamp(0, 96);
    s.spread_minutes = spread_minutes.clamp(5, 24 * 60);
    c.config = None;
    c.save().map_err(e2s)?;
    wake.0.notify_one();
    Ok(())
}

#[tauri::command]
async fn send_now(core: State<'_, Shared>, wake: State<'_, Wake>) -> R<()> {
    core.lock().await.request_send()?;
    wake.0.notify_one();
    Ok(())
}

#[tauri::command]
async fn set_paused(app: AppHandle, core: State<'_, Shared>, paused: bool) -> R<()> {
    let c = core.lock().await;
    probe::set_paused(&c.p.settings.logs(), paused).map_err(e2s)?;
    let view = c.view();
    drop(c);
    update_tray(&app, &view);
    let _ = app.emit("state", view);
    Ok(())
}

#[tauri::command]
async fn install_probe(core: State<'_, Shared>, wake: State<'_, Wake>) -> R<()> {
    let logs = core.lock().await.p.settings.logs();
    tauri::async_runtime::spawn_blocking(move || probe::install(&logs)).await.map_err(e2s)?.map_err(e2s)?;
    wake.0.notify_one();
    Ok(())
}

#[tauri::command]
async fn uninstall_probe(wake: State<'_, Wake>) -> R<()> {
    tauri::async_runtime::spawn_blocking(probe::uninstall).await.map_err(e2s)?.map_err(e2s)?;
    wake.0.notify_one();
    Ok(())
}

#[tauri::command]
async fn open_logs(core: State<'_, Shared>) -> R<()> {
    let logs = core.lock().await.p.settings.logs_dir.clone();
    probe::open(&logs).map_err(e2s)
}

#[tauri::command]
async fn open_url(url: String) -> R<()> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("not a web address".into());
    }
    probe::open(&url).map_err(e2s)
}

#[tauri::command]
async fn autostart(app: AppHandle, enabled: Option<bool>) -> R<bool> {
    let m = app.autolaunch();
    match enabled {
        Some(true) => m.enable().map_err(e2s)?,
        Some(false) => m.disable().map_err(e2s)?,
        None => {}
    }
    m.is_enabled().map_err(e2s)
}

/// Leaves the study: forgets the code and history; optionally deletes the
/// local logs.
#[tauri::command]
async fn leave(core: State<'_, Shared>, delete_logs: bool) -> R<()> {
    let mut c = core.lock().await;
    let logs = c.p.settings.logs();
    c.p.settings.code.clear();
    c.p.settings.consented = None;
    c.p.reports.clear();
    c.p.excluded.clear();
    c.config = None;
    c.save().map_err(e2s)?;
    if delete_logs {
        if let Ok(rd) = std::fs::read_dir(&logs) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("peersig-") && n.ends_with(".jsonl") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- tray

fn update_tray(app: &AppHandle, v: &core::View) {
    let Some(tray) = app.tray_by_id("main") else { return };
    let status = if !v.enrolled {
        "Not enrolled: open PeerSig to join".to_string()
    } else if v.observer && !v.paused && v.probe.running {
        format!("Observing ({} handshakes seen)", v.probe.hellos)
    } else if v.paused {
        "Capture paused".to_string()
    } else if !v.probe.running {
        "Capture is not running".to_string()
    } else {
        format!("Capturing ({} handshakes seen)", v.probe.hellos)
    };
    let of = if v.observer { "Day of" } else { "Week of" };
    let day = |t: i64| if v.observer { utc_day(t) } else { core::day(t) };
    let report = match &v.current {
        Some(r) if r.state == ReportState::Review => {
            let h = ((r.review_until - v.now).max(0) + 3599) / 3600;
            format!("{} {}: sends in {} h", of, day(r.from), h)
        }
        Some(r) if r.state == ReportState::Sending => format!("Sending week of {}: {}/{}", day(r.from), r.sent, r.total),
        Some(r) if r.state == ReportState::Sent => format!("{} {} sent", of, day(r.from)),
        Some(r) => format!("{} {}: not sent", of, day(r.from)),
        None => match &v.cycle {
            Some(c) if c.report >= c.current => format!("First report: from {}", day(c.spec.end(c.current))),
            _ => "Nothing to send yet".to_string(),
        },
    };
    let in_review = v.current.as_ref().filter(|r| r.state == ReportState::Review);
    let sending = v.reports.iter().any(|r| r.state == ReportState::Sending);
    let icon = if sending {
        ICON_SENDING
    } else if v.paused || !v.probe.running || !v.enrolled {
        ICON_PAUSED
    } else {
        ICON_IDLE
    };
    if let Some(t) = app.try_state::<Tray>() {
        let _ = t.status.set_text(&status);
        let _ = t.report.set_text(&report);
        let _ = t.pause.set_checked(v.paused);
        let _ = t.send.set_enabled(in_review.is_some());
        let _ = t.send.set_text(match in_review {
            Some(r) => format!("Send the {} of {} now", if v.observer { "day" } else { "week" }, day(r.from)),
            None => "Send the report now".to_string(),
        });
    }
    if let Ok(img) = Image::from_bytes(icon) {
        let _ = tray.set_icon(Some(img));
        #[cfg(target_os = "macos")]
        let _ = tray.set_icon_as_template(true);
    }
    let _ = tray.set_tooltip(Some(format!("PeerSig: {}. {}", status, report)));
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "PeerSig", false, None::<&str>)?;
    let report = MenuItem::with_id(app, "report", "Nothing to send yet", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Open PeerSig…", true, None::<&str>)?;
    let pause = CheckMenuItem::with_id(app, "pause", "Pause capture", true, false, None::<&str>)?;
    let send = MenuItem::with_id(app, "send", "Send the report now", false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit PeerSig", true, None::<&str>)?;
    let sep = || PredefinedMenuItem::separator(app);
    let menu = Menu::with_items(app, &[&status, &report, &sep()?, &open, &pause, &send, &sep()?, &quit])?;
    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(ICON_PAUSED)?)
        .icon_as_template(true)
        .tooltip("PeerSig")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, ev| {
            let app = app.clone();
            match ev.id.as_ref() {
                "open" => show_window(&app),
                "quit" => app.exit(0),
                "pause" => {
                    tauri::async_runtime::spawn(async move {
                        let core = app.state::<Shared>().inner().clone();
                        let c = core.lock().await;
                        let logs = c.p.settings.logs();
                        let _ = probe::set_paused(&logs, !probe::is_paused(&logs));
                        let v = c.view();
                        drop(c);
                        update_tray(&app, &v);
                        let _ = app.emit("state", v);
                    });
                }
                "send" => {
                    tauri::async_runtime::spawn(async move {
                        let r = app.state::<Shared>().lock().await.request_send();
                        match r {
                            Ok(_) => {
                                app.state::<Wake>().0.notify_one();
                                show_window(&app);
                            }
                            Err(why) => notify(&app, &why),
                        }
                    });
                }
                _ => {}
            }
        })
        .build(app)?;
    app.manage(Tray { status, report, send, pause });
    Ok(())
}

// ---------------------------------------------------------------- worker

async fn tick(app: &AppHandle, core: &Shared) {
    let settings = {
        let mut c = core.lock().await;
        c.probe = local::status(&c.p.settings.logs());
        c.p.settings.clone()
    };
    #[cfg(target_os = "linux")]
    keep_linux_probe(app, &settings);
    if !settings.enrolled() {
        return;
    }

    // Configuration: every 30 min, and when an epoch ends.
    let stale = {
        let c = core.lock().await;
        c.config.as_ref().map_or(true, |(t, cfg)| now() - t > 1800 || now() >= cfg.epochs.end(cfg.current_epoch))
    };
    if stale {
        let r = match settings.client() {
            Ok(mut cl) => cl.config().await,
            Err(e) => Err(e),
        };
        let mut c = core.lock().await;
        match r {
            Ok(cfg) => {
                c.config = Some((now(), cfg));
                c.last_error = None;
            }
            Err(e) => c.last_error = Some(format!("Cannot reach the server: {:#}", e)),
        }
    }

    // A new week to report.
    {
        let mut c = core.lock().await;
        if c.open_report() {
            let _ = c.save();
            let observer = c.p.settings.observer();
            let day = |t: i64| if observer { utc_day(t) } else { core::day(t) };
            if let Some(r) = c.current_report() {
                // An observer without a review sends unattended: nothing to announce.
                if !observer || settings.review_hours > 0 {
                    let msg = format!(
                        "Your report for the {} of {} is ready. It will be sent in about {} hours: open PeerSig to see it, or remove items.",
                        if observer { "day" } else { "week" },
                        day(r.from),
                        ((r.review_until - now()) + 1800) / 3600
                    );
                    notify(app, &msg);
                }
            }
        }
    }

    // Review over: build the ballots.
    let due = {
        let mut c = core.lock().await;
        match (c.due_for_preparation(), c.config.as_ref().map(|x| x.1.clone())) {
            (Some(e), Some(cfg)) => {
                let excluded = c.p.excluded.clone();
                let real: Vec<_> = c.items(e).map(|(o, _)| o).unwrap_or_default().into_iter().filter(|o| !excluded.contains(&o.key)).map(|o| o.item).collect();
                Some((e, cfg, real))
            }
            _ => None,
        }
    };
    if let (Some((e, _, real)), true) = (&due, settings.observer()) {
        let (e, real) = (*e, real.clone());
        // A day with nothing seen is not sent (the server refuses it).
        let r = if real.is_empty() { Ok(None) } else { core::observe(&settings, e, real.clone()).await };
        let mut c = core.lock().await;
        c.send_now = None;
        match r {
            // Counted, or counted before (a retry whose answer was lost).
            Ok(_) => {
                core::observed(&mut c, e, real);
                c.last_error = None;
            }
            Err(err) => {
                let msg = format!("{:#}", err);
                if let Some(r) = c.p.reports.get_mut(&e) {
                    if msg.contains("(400)") || msg.contains("(403)") || msg.contains("(413)") {
                        r.state = ReportState::Failed;
                    } else {
                        r.review_until = now() + 600; // retry in 10 min
                    }
                    r.error = Some(msg.clone());
                }
                c.last_error = Some(msg);
            }
        }
        let _ = c.save();
    } else if let Some((e, cfg, real)) = due {
        let r = core::prepare(&settings, &cfg, real).await;
        let mut c = core.lock().await;
        match r {
            Ok(p) => {
                let window = c.p.reports.get(&e).map(|r| r.send_by - now() - 600).unwrap_or(0).max(60);
                let spread = if c.send_now == Some(e) { 300 } else { settings.spread_minutes as i64 * 60 }.min(window);
                let real_n = p.real.len();
                core::schedule(&mut c, e, p, spread);
                c.send_now = None;
                let _ = c.save();
                notify(
                    app,
                    &format!(
                        "Sending your week's report: {} items, one anonymous ballot each, over the next {} minutes.",
                        real_n,
                        (spread + 59) / 60
                    ),
                );
            }
            Err(err) => {
                let msg = format!("{:#}", err);
                c.send_now = None;
                if let Some(r) = c.p.reports.get_mut(&e) {
                    if msg.contains("(403)") || msg.contains("(429)") {
                        r.state = ReportState::Failed;
                    } else {
                        r.review_until = now() + 600; // retry in 10 min
                    }
                    r.error = Some(msg.clone());
                }
                c.last_error = Some(msg);
                let _ = c.save();
            }
        }
    }

    // Ballots whose time has come, one request each.
    let mut client = match settings.client() {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut sent = 0;
    loop {
        let next = core.lock().await.next_ballot();
        let Some((e, b)) = next else { break };
        if sent == 0 {
            let v = core.lock().await.view();
            update_tray(app, &v);
        }
        match client.ballot(&b).await {
            Ok(()) => {
                let mut c = core.lock().await;
                c.ballot_sent(e, &b.token.nonce);
                sent += 1;
                if sent % 10 == 0 || !c.sending() {
                    let _ = c.save();
                }
            }
            Err(err) => {
                core.lock().await.last_error = Some(format!("Sending: {:#}", err));
                break;
            }
        }
    }
    if sent > 0 {
        let _ = core.lock().await.save();
    }
}

#[cfg(target_os = "linux")]
fn keep_linux_probe(app: &AppHandle, s: &core::Settings) {
    let child = app.state::<Child>();
    let mut g = child.0.lock().unwrap();
    let alive = g.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)));
    if !alive && s.enrolled() {
        *g = probe::spawn(&s.logs()).ok();
    }
}

async fn worker(app: AppHandle, core: Shared, wake: Arc<Notify>) {
    loop {
        tick(&app, &core).await;
        let v = core.lock().await.view();
        update_tray(&app, &v);
        let _ = app.emit("state", &v);
        let wait = if v.reports.iter().any(|r| r.state == ReportState::Sending) { 5 } else { 30 };
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(wait)) => {}
            _ = wake.notified() => {}
        }
    }
}

fn main() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec!["--background"])))
        .invoke_handler(tauri::generate_handler![
            get_state,
            get_items,
            set_excluded,
            enroll,
            save_settings,
            send_now,
            set_paused,
            install_probe,
            uninstall_probe,
            open_logs,
            open_url,
            autostart,
            leave
        ])
        .setup(|app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let dir = app.path().app_data_dir()?;
            let core = Core::load(&dir);
            let enrolled = core.p.settings.enrolled();
            let core: Shared = Arc::new(Mutex::new(core));
            app.manage(core.clone());
            let wake = Arc::new(Notify::new());
            app.manage(Wake(wake.clone()));
            #[cfg(target_os = "linux")]
            app.manage(Child(std::sync::Mutex::new(None)));
            build_tray(app)?;
            if !enrolled || !std::env::args().any(|a| a == "--background") {
                show_window(app.handle());
            }
            tauri::async_runtime::spawn(worker(app.handle().clone(), core, wake));
            Ok(())
        })
        .on_window_event(|w, e| {
            // Closing the window keeps PeerSig in the tray.
            if let WindowEvent::CloseRequested { api, .. } = e {
                api.prevent_close();
                let _ = w.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("PeerSig failed to start");
    app.run(|_app, e| match e {
        // Only "Quit PeerSig" (an explicit exit code) quits.
        RunEvent::ExitRequested { api, code: None, .. } => api.prevent_exit(),
        #[cfg(target_os = "linux")]
        RunEvent::Exit => {
            if let Some(mut c) = _app.state::<Child>().0.lock().unwrap().take() {
                let _ = c.kill();
            }
        }
        _ => {}
    });
}
