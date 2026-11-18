//! Windows service: what a LaunchDaemon is on macOS. The PeerSig app
//! installs `peersig-probe service --dir <logs> --owner <SID>` as an
//! automatic LocalSystem service named `PeerSigProbe`: LocalSystem can
//! read every process, as root can on macOS.
//!
//! The service manager starts the process, which must hand over to
//! `StartServiceCtrlDispatcherW` at once; `service_main` then runs the
//! capture (`run`) and Stop or Shutdown set its stop flag. Its stderr
//! (warnings) goes to `probe.log` next to the log directory.

use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{bail, Result};
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

use crate::platform::wide;
use crate::RunArgs;

pub const NAME: &str = "PeerSigProbe";

static ARGS: Mutex<Option<RunArgs>> = Mutex::new(None);
static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static HANDLE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(null_mut());

fn set_state(state: SERVICE_STATUS_CURRENT_STATE, exit: u32, wait_ms: u32) {
    let h = HANDLE.load(Ordering::SeqCst) as SERVICE_STATUS_HANDLE;
    if h.is_null() {
        return;
    }
    let accepts = if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 };
    let st = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepts,
        dwWin32ExitCode: if exit == 0 { NO_ERROR } else { ERROR_SERVICE_SPECIFIC_ERROR },
        dwServiceSpecificExitCode: exit,
        dwCheckPoint: 0,
        dwWaitHint: wait_ms,
    };
    unsafe { SetServiceStatus(h, &st) };
}

unsafe extern "system" fn handler(control: u32, _event: u32, _data: *mut core::ffi::c_void, _ctx: *mut core::ffi::c_void) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            if let Some(s) = STOP.get() {
                s.store(true, Ordering::SeqCst);
            }
            // The capture threads stop within their read timeout.
            set_state(SERVICE_STOP_PENDING, 0, 5000);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

/// Warnings go to `probe.log` beside the log directory (the service has
/// no console). Rust's stderr writes to whatever STD_ERROR_HANDLE is.
fn redirect_stderr(args: &RunArgs) {
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Console::{SetStdHandle, STD_ERROR_HANDLE};
    let Some(dir) = args.dir.as_deref() else { return };
    let Some(parent) = std::path::Path::new(dir).parent() else { return };
    let path = parent.join("probe.log");
    // Kept short: started over once it passes 1 MB.
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1 << 20) {
        let _ = std::fs::remove_file(&path);
    }
    if let Ok(f) = crate::logdir::open_private(&path, true) {
        unsafe { SetStdHandle(STD_ERROR_HANDLE, f.into_raw_handle() as _) };
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name = wide(NAME);
    let h = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), null()) };
    if h.is_null() {
        return;
    }
    HANDLE.store(h as *mut _, Ordering::SeqCst);
    set_state(SERVICE_START_PENDING, 0, 10_000);
    let Some(args) = ARGS.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        set_state(SERVICE_STOPPED, 1, 0);
        return;
    };
    redirect_stderr(&args);
    let stop = STOP.get_or_init(|| Arc::new(AtomicBool::new(false))).clone();
    set_state(SERVICE_RUNNING, 0, 0);
    eprintln!("{} peersig-probe {}: service started", crate::now_ts(), env!("CARGO_PKG_VERSION"));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::run(args, stop)));
    let code = match r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("{} error: {:#}", crate::now_ts(), e);
            1
        }
        Err(_) => 2,
    };
    // A non-zero code lets the service manager's recovery restart it.
    set_state(SERVICE_STOPPED, code, 0);
}

/// Runs `run` under the service manager. Fails at once when the process
/// was not started by it.
pub fn start(args: RunArgs) -> Result<()> {
    *ARGS.lock().unwrap_or_else(|e| e.into_inner()) = Some(args);
    let mut name = wide(NAME);
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: null_mut(), lpServiceProc: None },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        bail!(
            "not started by the Windows service manager (error {}): use `peersig-probe run` in a terminal",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}
