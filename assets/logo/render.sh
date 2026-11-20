#!/bin/sh
# Renders the logo into the app's icons (desktop and Android). Needs
# rsvg-convert (librsvg) and npx.
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
# Android: the launcher icons Tauri makes, and the notification's.
RES=../../android/app/src/main/res
for d in "$APP"/icons/android/*/; do
    mkdir -p "$RES/$(basename "$d")"
    cp "$d"* "$RES/$(basename "$d")/"
done
mkdir -p "$RES/drawable"
cp ic_stat_peersig.xml ic_stat_peersig_sending.xml "$RES/drawable/"
rm -rf "$APP/icons/android" "$APP/icons/ios"
