//! What an executable says about itself, without running it: Mach-O UUID,
//! code signature identifier and team, embedded Info.plist (bare daemons
//! such as nsurlsessiond carry one), linked libraries, and the Go build
//! info. ELF gets the libraries and Go build info.

use std::fs::File;
use std::path::Path;

use goblin::mach::load_command::CommandVariant;
use goblin::mach::{Mach, MachO};
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Signing {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Apple platform binary (part of the OS).
    pub platform: bool,
    /// Ad-hoc signature: no identity (local builds, Homebrew bottles).
    pub adhoc: bool,
}

#[derive(Debug, Clone, Default)]
pub struct BinInfo {
    pub uuid: Option<String>,
    pub signing: Option<Signing>,
    pub info_plist: Option<plist::Dictionary>,
    pub go_version: Option<String>,
    pub go_main: Option<String>,
    pub libs: Vec<String>,
}

pub fn inspect(path: &Path) -> Option<BinInfo> {
    let f = File::open(path).ok()?;
    let map = unsafe { memmap2::Mmap::map(&f) }.ok()?;
    let bytes: &[u8] = &map;
    if bytes.len() < 4 {
        return None;
    }
    match goblin::Object::parse(bytes).ok()? {
        goblin::Object::Mach(Mach::Binary(m)) => Some(macho_info(&m, bytes)),
        goblin::Object::Mach(Mach::Fat(fat)) => {
            let want = if cfg!(target_arch = "aarch64") {
                goblin::mach::cputype::CPU_TYPE_ARM64
            } else {
                goblin::mach::cputype::CPU_TYPE_X86_64
            };
            let arches: Vec<_> = fat.iter_arches().filter_map(Result::ok).collect();
            let arch = arches.iter().find(|a| a.cputype == want).or(arches.first())?;
            let slice = arch.slice(bytes);
            let m = MachO::parse(slice, 0).ok()?;
            Some(macho_info(&m, slice))
        }
        goblin::Object::Elf(e) => {
            let mut info = BinInfo::default();
            info.libs = e.libraries.iter().map(|s| s.to_string()).collect();
            for sh in &e.section_headers {
                if e.shdr_strtab.get_at(sh.sh_name) == Some(".go.buildinfo") {
                    let start = sh.sh_offset as usize;
                    let end = start.saturating_add(sh.sh_size as usize).min(bytes.len());
                    if let Some((v, m)) = bytes.get(start..end).and_then(go_buildinfo) {
                        info.go_version = Some(v);
                        info.go_main = m;
                    }
                }
            }
            Some(info)
        }
        _ => None,
    }
}

fn macho_info(m: &MachO, bytes: &[u8]) -> BinInfo {
    let mut info = BinInfo::default();
    info.libs = m.libs.iter().filter(|l| **l != "self").map(|s| s.to_string()).collect();
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::Uuid(u) => info.uuid = Some(uuid_string(&u.uuid)),
            CommandVariant::CodeSignature(cs) => {
                let start = cs.dataoff as usize;
                let end = start.saturating_add(cs.datasize as usize);
                if let Some(blob) = bytes.get(start..end) {
                    info.signing = code_directory(blob);
                }
            }
            _ => {}
        }
    }
    for seg in &m.segments {
        let Ok(sections) = seg.sections() else { continue };
        for (sec, data) in sections {
            match sec.name() {
                Ok("__info_plist") => {
                    if let Ok(plist::Value::Dictionary(d)) = plist::Value::from_reader(std::io::Cursor::new(data)) {
                        info.info_plist = Some(d);
                    }
                }
                Ok("__go_buildinfo") => {
                    if let Some((v, main)) = go_buildinfo(data) {
                        info.go_version = Some(v);
                        info.go_main = main;
                    }
                }
                _ => {}
            }
        }
    }
    info
}

pub fn uuid_string(u: &[u8; 16]) -> String {
    let h: String = u.iter().map(|b| format!("{:02X}", b)).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn cstr_at(b: &[u8], o: usize) -> Option<String> {
    let s = b.get(o..)?;
    let end = s.iter().position(|&c| c == 0)?;
    Some(String::from_utf8_lossy(&s[..end]).into_owned())
}

/// Embedded signature: SuperBlob (0xfade0cc0) -> CodeDirectory (0xfade0c02)
/// in slot 0. Fields from xnu osfmk/kern/cs_blobs.h. Displayed, not verified:
/// that is the kernel's job before the process could run.
fn code_directory(blob: &[u8]) -> Option<Signing> {
    if be32(blob, 0)? != 0xfade_0cc0 {
        return None;
    }
    let count = be32(blob, 8)? as usize;
    for i in 0..count.min(64) {
        let (ty, off) = (be32(blob, 12 + 8 * i)?, be32(blob, 16 + 8 * i)? as usize);
        if ty != 0 {
            continue;
        }
        let cd = blob.get(off..)?;
        if be32(cd, 0)? != 0xfade_0c02 {
            return None;
        }
        let version = be32(cd, 8)?;
        let flags = be32(cd, 12)?;
        let ident = be32(cd, 20)? as usize;
        let platform = *cd.get(38)?;
        let team = if version >= 0x20200 { be32(cd, 48)? as usize } else { 0 };
        return Some(Signing {
            identifier: if ident > 0 { cstr_at(cd, ident) } else { None },
            team_id: if team > 0 { cstr_at(cd, team).filter(|t| !t.is_empty()) } else { None },
            platform: platform != 0,
            adhoc: flags & 0x2 != 0,
        });
    }
    None
}

fn uvarint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for (i, &c) in b.iter().enumerate().take(10) {
        v |= ((c & 0x7f) as u64) << (7 * i);
        if c & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

/// Go >= 1.18 `.go.buildinfo`: 32-byte header ("\xff Go buildinf:", pointer
/// size, flags), then length-prefixed version and module info strings.
fn go_buildinfo(d: &[u8]) -> Option<(String, Option<String>)> {
    if d.len() < 32 || &d[..14] != b"\xff Go buildinf:" {
        return None;
    }
    if d[15] & 0x2 == 0 {
        return Some(("go (before 1.18)".into(), None));
    }
    let (n, k) = uvarint(&d[32..])?;
    let vs = 32 + k;
    let version = String::from_utf8_lossy(d.get(vs..vs + n as usize)?).into_owned();
    let rest = &d[vs + n as usize..];
    let main = uvarint(rest).and_then(|(m, k)| {
        let mi = String::from_utf8_lossy(rest.get(k..k + m as usize)?).into_owned();
        mi.lines().find_map(|l| l.strip_prefix("path\t").map(str::to_string))
    });
    Some((version, main))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn system_binary() {
        // A platform binary with an embedded Info.plist.
        let i = inspect(Path::new("/usr/libexec/nsurlsessiond")).unwrap();
        let s = i.signing.unwrap();
        assert!(s.platform);
        assert_eq!(s.identifier.as_deref(), Some("com.apple.nsurlsessiond"));
        assert!(i.info_plist.is_some());
        assert!(i.uuid.is_some());
    }
}
