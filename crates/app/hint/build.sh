#!/bin/sh
# Builds peersig-hint (macOS only) as crates/app/binaries/peersig-hint-<target>,
# where Tauri bundles it from (tauri.macos.conf.json):
#
#   crates/app/hint/build.sh [aarch64-apple-darwin | x86_64-apple-darwin]
#
# Needs Xcode 26 or later: the Foundation Models SDK, and its Swift macros,
# which the Command Line Tools alone do not have.
set -eu
target=${1:-$(rustc -vV | sed -n 's/host: //p')}
case $target in
  aarch64-apple-darwin) arch=arm64 ;;
  x86_64-apple-darwin) arch=x86_64 ;;
  *) echo "peersig-hint is built for macOS only, not $target" >&2; exit 1 ;;
esac
# An Xcode whose macOS SDK has Foundation Models: the selected one, or the
# newest installed (CI runners have several).
fm() { [ -d "$1/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/System/Library/Frameworks/FoundationModels.framework" ]; }
dev=${DEVELOPER_DIR:-$(xcode-select -p)}
if ! fm "$dev"; then
  for x in $(ls -d /Applications/Xcode*.app 2>/dev/null | sort -r -V); do
    if fm "$x/Contents/Developer"; then dev=$x/Contents/Developer; break; fi
  done
fi
fm "$dev" || { echo "no Xcode with the Foundation Models SDK (Xcode 26 or later)" >&2; exit 1; }
export DEVELOPER_DIR=$dev
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/../binaries"
# The app runs on macOS 12 and later; the model needs 26, checked at run time.
xcrun swiftc -parse-as-library -O -target "$arch-apple-macos12" "$here/main.swift" -o "$here/../binaries/peersig-hint-$target"
