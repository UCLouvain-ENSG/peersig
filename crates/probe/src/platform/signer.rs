//! Windows: who published an executable, from its signature as Windows
//! verifies it (`WinVerifyTrust`): the signature embedded in the file
//! (Authenticode), or, for the system's own files, which carry none, the
//! catalog that signs them. Only a signature that Windows trusts names a
//! publisher: the organization (O) of the signing certificate, else its
//! common name. Microsoft Store apps are signed as a package instead: see
//! `bundle::msix_publisher`.
//!
//! The check uses what the computer already has: no revocation check and
//! no download of certificates (`WTD_CACHE_ONLY_URL_RETRIEVAL`), as the
//! probe never uses the network.

use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};

use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
    CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertGetNameStringW, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CERT_CONTEXT, CERT_NAME_ATTR_TYPE,
    CERT_NAME_SIMPLE_DISPLAY_TYPE, szOID_ORGANIZATION_NAME,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, DRIVER_ACTION_VERIFY,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

use super::wide;

struct File(HANDLE);

impl File {
    fn open(path: &[u16]) -> Option<File> {
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        (h != INVALID_HANDLE_VALUE && !h.is_null()).then_some(File(h))
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// The publisher of the executable at `path`, from a signature Windows
/// trusts; None when it is unsigned, or signed by no one Windows trusts.
pub fn publisher(path: &str) -> Option<String> {
    let w = wide(path);
    embedded(&w).or_else(|| catalog(&w))
}

fn embedded(path: &[u16]) -> Option<String> {
    let file = File::open(path)?;
    let mut info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.0,
        pgKnownSubject: null_mut(),
    };
    verify(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &mut info })
}

/// Catalog-signed files (most of Windows): the catalog that lists the
/// file's hash, then that catalog's signature.
fn catalog(path: &[u16]) -> Option<String> {
    [BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA1_ALGORITHM].into_iter().find_map(|alg| catalog_with(path, alg))
}

fn catalog_with(path: &[u16], alg: PCWSTR) -> Option<String> {
    let file = File::open(path)?;
    let mut admin: isize = 0;
    if unsafe { CryptCATAdminAcquireContext2(&mut admin, &DRIVER_ACTION_VERIFY, alg, null(), 0) } == 0 {
        return None;
    }
    let mut hash = [0u8; 64];
    let mut len = hash.len() as u32;
    let mut name = None;
    if unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, file.0, &mut len, hash.as_mut_ptr(), 0) } != 0 {
        let cat = unsafe { CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, null_mut()) };
        if cat != 0 {
            let mut ci = CATALOG_INFO { cbStruct: size_of::<CATALOG_INFO>() as u32, wszCatalogFile: [0; 260] };
            if unsafe { CryptCATCatalogInfoFromContext(cat, &mut ci, 0) } != 0 {
                let tag = wide(hash[..len as usize].iter().map(|b| format!("{:02X}", b)).collect::<String>());
                let mut info = WINTRUST_CATALOG_INFO {
                    cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                    dwCatalogVersion: 0,
                    pcwszCatalogFilePath: ci.wszCatalogFile.as_ptr(),
                    pcwszMemberTag: tag.as_ptr(),
                    pcwszMemberFilePath: path.as_ptr(),
                    hMemberFile: file.0,
                    pbCalculatedFileHash: hash.as_mut_ptr(),
                    cbCalculatedFileHash: len,
                    pcCatalogContext: null_mut(),
                    hCatAdmin: admin,
                };
                name = verify(WTD_CHOICE_CATALOG, WINTRUST_DATA_0 { pCatalog: &mut info });
            }
            unsafe { CryptCATAdminReleaseCatalogContext(admin, cat, 0) };
        }
    }
    unsafe { CryptCATAdminReleaseContext(admin, 0) };
    name
}

/// Verifies, reads the signer's name if the signature is trusted, and
/// releases what the verification kept.
fn verify(choice: u32, what: WINTRUST_DATA_0) -> Option<String> {
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: null_mut(),
        pSIPClientData: null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        Anonymous: what,
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: null_mut(),
        pwszURLReference: null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        dwUIContext: 0,
        pSignatureSettings: null_mut(),
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let trusted = unsafe { WinVerifyTrust(null_mut(), &mut action, &mut data as *mut _ as *mut c_void) } == 0;
    let name = if trusted { signer_name(data.hWVTStateData) } else { None };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(null_mut(), &mut action, &mut data as *mut _ as *mut c_void) };
    name
}

fn signer_name(state: HANDLE) -> Option<String> {
    let prov = unsafe { WTHelperProvDataFromStateData(state) };
    if prov.is_null() {
        return None;
    }
    let sgnr = unsafe { WTHelperGetProvSignerFromChain(prov, 0, 0, 0) };
    if sgnr.is_null() {
        return None;
    }
    let s = unsafe { &*sgnr };
    if s.csCertChain == 0 || s.pasCertChain.is_null() {
        return None;
    }
    let cert = unsafe { (*s.pasCertChain).pCert };
    if cert.is_null() {
        return None;
    }
    cert_name(cert, CERT_NAME_ATTR_TYPE, szOID_ORGANIZATION_NAME as *const c_void)
        .or_else(|| cert_name(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, null()))
}

fn cert_name(cert: *const CERT_CONTEXT, kind: u32, para: *const c_void) -> Option<String> {
    let mut buf = [0u16; 256];
    let n = unsafe { CertGetNameStringW(cert, kind, 0, para, buf.as_mut_ptr(), buf.len() as u32) } as usize;
    // The count includes the terminating NUL: 1 is an empty name.
    if n <= 1 || n > buf.len() {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..n - 1]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// svchost.exe is signed by a catalog, like most of Windows.
    #[test]
    fn windows_files() {
        let svchost = super::super::system_dir().join("svchost.exe");
        assert_eq!(publisher(&svchost.display().to_string()).as_deref(), Some("Microsoft Corporation"));
    }

    /// An unsigned executable (this test) has no publisher.
    #[test]
    fn unsigned() {
        let me = std::env::current_exe().unwrap();
        assert_eq!(publisher(&me.display().to_string()), None);
        assert_eq!(publisher(r"C:\no\such\file.exe"), None);
    }

    /// Edge carries its own signature (on GitHub's Windows runners too).
    #[test]
    fn embedded_signature() {
        let edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
        if std::path::Path::new(edge).exists() {
            assert_eq!(publisher(edge).as_deref(), Some("Microsoft Corporation"));
        }
    }
}
