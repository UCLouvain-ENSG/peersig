#!/bin/sh
# Renders the logo into the app's icons. Needs rsvg-convert (librsvg) and npx.
set -e
cd "$(dirname "$0")"
python3 make_logo.py
APP=../../crates/app
rsvg-convert -w 1024 -h 1024 peersig.svg -o peersig-1024.png
# Menu bar: 44 px, drawn at 22 pt (macOS template images: black + alpha).
for v in "" -paused -sending; do
    rsvg-convert -w 44 -h 44 "peersig-mark$v.svg" -o "$APP/icons/tray${v}.png"
done
cp peersig.svg "$APP/ui/logo.svg"
npx --yes @tauri-apps/cli@2 icon peersig-1024.png -o "$APP/icons"
rm -rf "$APP/icons/android" "$APP/icons/ios"
