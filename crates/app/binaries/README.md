Tauri bundles the capture probe from here as `peersig-probe-<target triple>`
(e.g. `peersig-probe-aarch64-apple-darwin`). Build it and copy it before
building the app:

    cargo build --release -p peersig-probe
    cp target/release/peersig-probe crates/app/binaries/peersig-probe-$(rustc -vV | sed -n 's/host: //p')

On Windows the file is `peersig-probe-x86_64-pc-windows-msvc.exe`.

On macOS the app also bundles `peersig-hint-<target triple>`, which asks
Apple's on-device model which names the review should show first
(`crates/app/hint`, `tauri.macos.conf.json`). It needs Xcode 26 or later:

    crates/app/hint/build.sh
