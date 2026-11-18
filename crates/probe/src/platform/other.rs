//! Other systems (the BSDs...): not implemented. Fingerprints still work;
//! records carry no process.

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
pub fn os_info() -> OsInfo {
    OsInfo {
        os: std::env::consts::OS.into(),
        distro: None,
        version: None,
        build: None,
        kernel: None,
        model: None,
        arch: std::env::consts::ARCH.into(),
    }
}
pub const DEFAULT_DEVICE: &str = "";
