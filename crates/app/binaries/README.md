Tauri bundles the capture probe from here as `peersig-probe-<target triple>`
(e.g. `peersig-probe-aarch64-apple-darwin`). Build it and copy it before
building the app:

    cargo build --release -p peersig-probe
    cp target/release/peersig-probe crates/app/binaries/peersig-probe-$(rustc -vV | sed -n 's/host: //p')
