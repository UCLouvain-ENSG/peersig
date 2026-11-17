//! What an executable says about itself, without running it: Mach-O UUID,
//! code signature identifier and team, embedded Info.plist (bare daemons
//! such as nsurlsessiond carry one), linked libraries, and the Go build
//! info. ELF gets the libraries and Go build info. PE (Windows) gets the
//! imported DLLs, the subsystem (GUI or console), the version resource
//! (product name and version), and the Go build info.

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
    /// PE version resource.
    pub version: Option<VersionInfo>,
    /// PE subsystem: gui, console, native...
    pub subsystem: Option<String>,
}

/// A PE version resource (VS_VERSIONINFO), as read from the file itself:
/// the language-neutral strings, not the translation Windows shows from a
/// .mui file. Product names stay the same on every participant's machine.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct VersionInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_filename: Option<String>,
    /// VS_FIXEDFILEINFO's product version, a.b.c.d.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_version: Option<String>,
}

impl VersionInfo {
    /// The product version as a plain dotted version: "1, 2, 3, 4" and
    /// "10.0.26100.1 (WinBuild.160101.0800)" are cleaned up.
    pub fn version(&self) -> Option<String> {
        let clean = |s: &String| -> Option<String> {
            let s = s.split(" (").next().unwrap_or("").replace(", ", ".").replace(',', ".");
            let s = s.trim().trim_start_matches(['v', 'V']).trim();
            (!s.is_empty() && s.chars().next().is_some_and(|c| c.is_ascii_digit())).then(|| s.to_string())
        };
        self.product_version.as_ref().and_then(clean).or_else(|| self.fixed_version.clone())
    }

    /// The Windows product name every system binary carries says nothing
    /// about the binary.
    pub fn is_os_component(&self) -> bool {
        self.product.as_deref().is_some_and(|p| {
            let p = p.replace(['®', '(', ')'], "").to_ascii_lowercase();
            p.contains("microsoft") && p.contains("windows") && p.contains("operating system")
        })
    }
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
        goblin::Object::PE(pe) => Some(pe_info(&pe, bytes)),
        _ => None,
    }
}

fn pe_info(pe: &goblin::pe::PE, bytes: &[u8]) -> BinInfo {
    let mut info = BinInfo::default();
    info.libs = pe.libraries.iter().map(|s| s.to_string()).collect();
    if let Some(oh) = &pe.header.optional_header {
        info.subsystem = Some(
            match oh.windows_fields.subsystem {
                2 => "gui",
                3 => "console",
                1 => "native",
                _ => "other",
            }
            .into(),
        );
        if let Some(dd) = oh.data_directories.get_resource_table() {
            info.version = version_resource(bytes, &pe.sections, dd.virtual_address, dd.size);
        }
    }
    // Go keeps its build info at a 16-byte boundary of the data section.
    for s in pe.sections.iter().filter(|s| s.name().ok() == Some(".data")) {
        let start = s.pointer_to_raw_data as usize;
        let end = start.saturating_add(s.size_of_raw_data as usize).min(bytes.len());
        let Some(data) = bytes.get(start..end) else { continue };
        let found = (0..data.len().saturating_sub(32)).step_by(16).find(|&o| data[o..].starts_with(b"\xff Go buildinf:"));
        if let Some((v, m)) = found.and_then(|o| go_buildinfo(&data[o..])) {
            info.go_version = Some(v);
            info.go_main = m;
        }
    }
    info
}

fn le16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn rva_to_offset(sections: &[goblin::pe::section_table::SectionTable], rva: u32) -> Option<usize> {
    sections.iter().find_map(|s| {
        let size = s.virtual_size.max(s.size_of_raw_data);
        (rva >= s.virtual_address && rva < s.virtual_address.saturating_add(size))
            .then(|| (rva - s.virtual_address + s.pointer_to_raw_data) as usize)
    })
}

/// RT_VERSION in the resource tree (type 16, then name, then language),
/// then its VS_VERSIONINFO.
fn version_resource(bytes: &[u8], sections: &[goblin::pe::section_table::SectionTable], rva: u32, size: u32) -> Option<VersionInfo> {
    let base = rva_to_offset(sections, rva)?;
    let tree = bytes.get(base..base.checked_add(size as usize)?.min(bytes.len()))?;
    // Entries of a directory: (id or name offset, data or subdirectory offset).
    let entries = |off: usize| -> Vec<(u32, u32)> {
        let (named, ids) = (le16(tree, off + 12).unwrap_or(0) as usize, le16(tree, off + 14).unwrap_or(0) as usize);
        (0..(named + ids).min(4096)).filter_map(|i| Some((le32(tree, off + 16 + 8 * i)?, le32(tree, off + 20 + 8 * i)?))).collect()
    };
    const SUBDIR: u32 = 0x8000_0000;
    let types = entries(0);
    let (_, t) = types.iter().find(|(id, o)| *id == 16 && o & SUBDIR != 0)?;
    let names = entries((t & !SUBDIR) as usize);
    let (_, n) = names.iter().find(|(_, o)| o & SUBDIR != 0)?;
    let langs = entries((n & !SUBDIR) as usize);
    // Neutral or US English first: what the file ships for everyone.
    let (_, leaf) = langs
        .iter()
        .find(|(l, _)| *l == 0 || *l == 0x0409)
        .or(langs.first())
        .filter(|(_, o)| o & SUBDIR == 0)?;
    let leaf = *leaf as usize;
    let (data_rva, data_size) = (le32(tree, leaf)?, le32(tree, leaf + 4)? as usize);
    let off = rva_to_offset(sections, data_rva)?;
    parse_version_info(bytes.get(off..off.checked_add(data_size)?.min(bytes.len()))?)
}

struct Block {
    end: usize,
    key: String,
    value: std::ops::Range<usize>,
    children: usize,
}

fn align4(x: usize) -> usize {
    (x + 3) & !3
}

/// One node of a version resource: length, value length, type, a
/// NUL-terminated UTF-16 key, padding, the value, padding, the children.
fn block(d: &[u8], pos: usize) -> Option<Block> {
    let len = le16(d, pos)? as usize;
    let vlen = le16(d, pos + 2)? as usize;
    let text = le16(d, pos + 4)? == 1;
    if len < 6 {
        return None;
    }
    let end = pos.checked_add(len)?.min(d.len());
    let mut p = pos + 6;
    let mut key = Vec::new();
    while p + 2 <= end {
        let c = le16(d, p)?;
        p += 2;
        if c == 0 {
            break;
        }
        key.push(c);
    }
    let vstart = align4(p).min(end);
    // A text value's length is in characters (some tools write bytes: the
    // value is read up to its NUL anyway).
    let vbytes = if text { vlen * 2 } else { vlen };
    let vend = (vstart + vbytes).min(end);
    Some(Block { end, key: String::from_utf16_lossy(&key), value: vstart..vend, children: align4(vend) })
}

fn children(d: &[u8], parent: &Block) -> Vec<Block> {
    let mut out = Vec::new();
    let mut p = parent.children;
    while p + 6 <= parent.end && out.len() < 1024 {
        let Some(b) = block(d, p) else { break };
        let next = align4(b.end);
        out.push(b);
        if next <= p {
            break;
        }
        p = next;
    }
    out
}

fn utf16(d: &[u8]) -> String {
    let w: Vec<u16> = d.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&c| c != 0).collect();
    String::from_utf16_lossy(&w).trim().to_string()
}

pub fn parse_version_info(d: &[u8]) -> Option<VersionInfo> {
    let root = block(d, 0)?;
    if root.key != "VS_VERSION_INFO" {
        return None;
    }
    let mut vi = VersionInfo::default();
    let fixed = &d[root.value.clone()];
    if fixed.len() >= 52 && le32(fixed, 0) == Some(0xFEEF_04BD) {
        let (ms, ls) = (le32(fixed, 16)?, le32(fixed, 20)?);
        vi.fixed_version = Some(format!("{}.{}.{}.{}", ms >> 16, ms & 0xffff, ls >> 16, ls & 0xffff));
    }
    let sfi = children(d, &root).into_iter().find(|b| b.key == "StringFileInfo");
    if let Some(sfi) = sfi {
        let tables = children(d, &sfi);
        let table = tables
            .iter()
            .find(|t| t.key.to_ascii_lowercase().starts_with("0409"))
            .or_else(|| tables.iter().find(|t| t.key.starts_with("0000")))
            .or(tables.first());
        if let Some(t) = table {
            for s in children(d, t) {
                let v = utf16(&d[s.value.clone()]);
                if v.is_empty() {
                    continue;
                }
                let v = Some(v);
                match s.key.as_str() {
                    "ProductName" => vi.product = v,
                    "ProductVersion" => vi.product_version = v,
                    "FileDescription" => vi.description = v,
                    "FileVersion" => vi.file_version = v,
                    "CompanyName" => vi.company = v,
                    "OriginalFilename" => vi.original_filename = v,
                    _ => {}
                }
            }
        }
    }
    Some(vi)
}

/// The version resource of a PE file on disk (a DLL such as libcef.dll).
pub fn pe_version(path: &Path) -> Option<VersionInfo> {
    let f = File::open(path).ok()?;
    let map = unsafe { memmap2::Mmap::map(&f) }.ok()?;
    match goblin::Object::parse(&map).ok()? {
        goblin::Object::PE(pe) => pe_info(&pe, &map).version,
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

    #[test]
    #[cfg(windows)]
    fn windows_binaries() {
        let sys = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let i = inspect(&Path::new(&sys).join(r"System32\svchost.exe")).unwrap();
        let v = i.version.unwrap();
        assert!(v.is_os_component(), "{:?}", v);
        // The file's own strings, not a translation.
        assert_eq!(v.description.as_deref(), Some("Host Process for Windows Services"));
        assert!(v.version().unwrap().starts_with("10.0."), "{:?}", v);
        assert!(i.libs.iter().any(|l| l.eq_ignore_ascii_case("ntdll.dll")), "{:?}", i.libs);
        let e = inspect(&Path::new(&sys).join("explorer.exe")).unwrap();
        assert_eq!(e.subsystem.as_deref(), Some("gui"));
    }

    /// A version resource built by hand: root with VS_FIXEDFILEINFO,
    /// StringFileInfo, one table, two strings.
    #[test]
    fn version_resource_layout() {
        fn node(key: &str, value: &[u8], text: bool, kids: &[Vec<u8>]) -> Vec<u8> {
            let mut b = vec![0u8; 6];
            for c in key.encode_utf16().chain(std::iter::once(0)) {
                b.extend_from_slice(&c.to_le_bytes());
            }
            while b.len() % 4 != 0 {
                b.push(0);
            }
            b.extend_from_slice(value);
            while b.len() % 4 != 0 {
                b.push(0);
            }
            for k in kids {
                b.extend_from_slice(k);
                while b.len() % 4 != 0 {
                    b.push(0);
                }
            }
            let vlen = if text { value.len() / 2 } else { value.len() };
            let len = b.len() as u16;
            b[0..2].copy_from_slice(&len.to_le_bytes());
            b[2..4].copy_from_slice(&(vlen as u16).to_le_bytes());
            b[4..6].copy_from_slice(&(text as u16).to_le_bytes());
            b
        }
        let s = |v: &str| v.encode_utf16().chain(std::iter::once(0)).flat_map(|c| c.to_le_bytes()).collect::<Vec<u8>>();
        let mut fixed = vec![0u8; 52];
        fixed[0..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
        fixed[16..20].copy_from_slice(&((131u32 << 16) | 0).to_le_bytes());
        fixed[20..24].copy_from_slice(&((6778u32 << 16) | 86).to_le_bytes());
        let table = node(
            "040904b0",
            &[],
            true,
            &[node("ProductName", &s("Google Chrome"), true, &[]), node("ProductVersion", &s("131.0.6778.86"), true, &[])],
        );
        let root = node("VS_VERSION_INFO", &fixed, false, &[node("StringFileInfo", &[], true, &[table])]);
        let v = parse_version_info(&root).unwrap();
        assert_eq!(v.product.as_deref(), Some("Google Chrome"));
        assert_eq!(v.version().as_deref(), Some("131.0.6778.86"));
        assert_eq!(v.fixed_version.as_deref(), Some("131.0.6778.86"));
        let messy = VersionInfo { product_version: Some("10.0.26100.1 (WinBuild.160101.0800)".into()), ..Default::default() };
        assert_eq!(messy.version().as_deref(), Some("10.0.26100.1"));
        let commas = VersionInfo { product_version: Some("3, 2, 1, 0".into()), ..Default::default() };
        assert_eq!(commas.version().as_deref(), Some("3.2.1.0"));
    }
}
