// The Windows release ships the probe with nothing beside it. Rust's MSVC
// target takes the Visual C++ runtime from a DLL (VCRUNTIME140.dll) that is
// not part of Windows: link it statically, as tauri-build does for the app.
// The C library itself (the UCRT) stays a DLL: Windows 10 and 11 have it.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    // libcmt.lib asks for the static UCRT: leave that one out too.
    for lib in ["msvcrt.lib", "vcruntime.lib", "libucrt.lib"] {
        println!("cargo:rustc-link-arg=/NODEFAULTLIB:{lib}");
    }
    for lib in ["libcmt.lib", "libvcruntime.lib", "ucrt.lib"] {
        println!("cargo:rustc-link-arg=/DEFAULTLIB:{lib}");
    }
}
