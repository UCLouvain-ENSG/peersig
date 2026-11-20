//! Android. An app cannot read other apps' processes, so there are no
//! process queries here: the PeerSig app asks the system which app owns
//! each connection, by uid (`attrib::Owners`, crates/android). This module
//! only says which system this is.

use super::{OsInfo, PidBasic};
use crate::net::FlowKey;

pub fn basic(_pid: i32) -> Option<PidBasic> {
    None
}
pub fn exe_path(_pid: i32) -> Option<String> {
    None
}
pub fn args(_pid: i32) -> Option<Vec<String>> {
    None
}
pub fn responsible_pid(_pid: i32) -> Option<i32> {
    None
}
pub fn mapped_files(_pid: i32) -> Vec<String> {
    Vec::new()
}
pub fn socket_owner(_key: &FlowKey) -> Option<i32> {
    None
}

/// A system property (`ro.build.version.release`), as `getprop` prints it.
pub fn property(name: &str) -> Option<String> {
    let name = std::ffi::CString::new(name).ok()?;
    let mut buf = [0 as libc::c_char; libc::PROP_VALUE_MAX as usize];
    let n = unsafe { libc::__system_property_get(name.as_ptr(), buf.as_mut_ptr()) };
    if n <= 0 {
        return None;
    }
    let bytes: Vec<u8> = buf[..n as usize].iter().map(|c| *c as u8).collect();
    let s = String::from_utf8_lossy(&bytes).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// `{"os": "android", "version": "15"}`: items carry "android 15". The
/// build, the security patch and the model stay in the local logs.
pub fn os_info() -> OsInfo {
    // uname: SELinux keeps apps out of /proc/sys/kernel.
    let kernel = unsafe {
        let mut u: libc::utsname = std::mem::zeroed();
        (libc::uname(&mut u) == 0).then(|| std::ffi::CStr::from_ptr(u.release.as_ptr()).to_string_lossy().into_owned())
    };
    OsInfo {
        os: "android".into(),
        distro: None,
        version: property("ro.build.version.release"),
        build: property("ro.build.id"),
        kernel,
        model: property("ro.product.model"),
        arch: std::env::consts::ARCH.into(),
    }
}

pub const DEFAULT_DEVICE: &str = "";
