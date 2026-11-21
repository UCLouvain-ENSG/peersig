//! PeerSig tray app. It shows what the probe collected, lets the
//! participant remove items, and sends each week's report as anonymous
//! ballots. The tray icon changes while ballots are being sent. With an
//! observer's code, it sends each day's report instead (see core.rs).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod probe;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State, WindowEvent, Wry};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_notification::NotificationExt;
use tokio::sync::{Mutex, Notify};

use peersig_client::core::{self, Core};
use peersig_client::tray::Icon;
use peersig_client::{commands, Host, Shared};

struct Wake(peersig_client::Wake);

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
    Ok(commands::state(&core).await)
}

/// Items of the epoch being reported, or of the current one (`current`).
#[tauri::command]
async fn get_items(core: State<'_, Shared>, current: bool) -> R<serde_json::Value> {
    Ok(commands::items(&core, current).await)
}

#[tauri::command]
async fn set_excluded(app: AppHandle, core: State<'_, Shared>, key: String, excluded: bool) -> R<()> {
    let view = commands::set_excluded(&core, key, excluded).await?;
    let _ = app.emit("state", view);
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
    commands::enroll(&core, &wake.0, server, relay, code, share_domains).await
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
    commands::save_settings(&core, &wake.0, relay, share_domains, review_hours, spread_minutes).await
}

#[tauri::command]
async fn send_now(core: State<'_, Shared>, wake: State<'_, Wake>) -> R<()> {
    commands::send_now(&core, &wake.0).await
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
async fn install_probe(app: AppHandle, core: State<'_, Shared>, wake: State<'_, Wake>) -> R<()> {
    let logs = core.lock().await.p.settings.logs();
    let dir = logs.clone();
    tauri::async_runtime::spawn_blocking(move || probe::install(&dir)).await.map_err(e2s)?.map_err(e2s)?;
    // The window shows the service as its status file describes it, and
    // the new service writes that file only once it runs: wait for it (a
    // few seconds), or the window keeps showing the old one, and its
    // "Update capture service" button, until a later refresh.
    if cfg!(any(target_os = "macos", windows)) {
        for _ in 0..40 {
            let tool = peersig_client::local::status(&logs).tool;
            if tool.as_deref().is_some_and(probe::shipped) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }
    let view = commands::state(&core).await;
    update_tray(&app, &view);
    let _ = app.emit("state", view);
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
    commands::leave(&core, delete_logs).await
}

// ---------------------------------------------------------------- tray

fn update_tray(app: &AppHandle, v: &core::View) {
    let Some(tray) = app.tray_by_id("main") else { return };
    let t = peersig_client::tray::tray(v);
    let icon = match t.icon {
        Icon::Sending => ICON_SENDING,
        Icon::Paused => ICON_PAUSED,
        Icon::Idle => ICON_IDLE,
    };
    if let Some(m) = app.try_state::<Tray>() {
        let _ = m.status.set_text(&t.status);
        let _ = m.report.set_text(&t.report);
        let _ = m.pause.set_checked(t.paused);
        let _ = m.send.set_enabled(t.send.is_some());
        let _ = m.send.set_text(t.send.as_deref().unwrap_or("Send the report now"));
    }
    if let Ok(img) = Image::from_bytes(icon) {
        let _ = tray.set_icon(Some(img));
        #[cfg(target_os = "macos")]
        let _ = tray.set_icon_as_template(true);
    }
    let _ = tray.set_tooltip(Some(format!("PeerSig: {}. {}", t.status, t.report)));
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

// ---------------------------------------------------------------- host

/// The desktop app's side of `peersig_client`: the probe installed as a
/// service (or, on Linux, run as a child), the tray, notifications.
struct Desktop(AppHandle);

impl Host for Desktop {
    fn default_logs_dir(&self) -> PathBuf {
        probe::default_logs_dir()
    }
    fn capture_installed(&self) -> bool {
        probe::installed()
    }
    fn capture_outdated(&self, tool: Option<&str>) -> bool {
        probe::service_outdated(tool)
    }
    fn paused(&self, logs: &Path) -> bool {
        probe::is_paused(logs)
    }
    fn notify(&self, body: &str) {
        notify(&self.0, body);
    }
    fn show(&self, view: &core::View) {
        update_tray(&self.0, view);
        let _ = self.0.emit("state", view);
    }
    #[cfg(target_os = "linux")]
    fn tick(&self, s: &core::Settings) {
        keep_linux_probe(&self.0, s);
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
            let core = Core::load(&dir, Arc::new(Desktop(app.handle().clone())));
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
            tauri::async_runtime::spawn(peersig_client::worker::run(core, wake));
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
