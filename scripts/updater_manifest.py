#!/usr/bin/env python3
"""Writes the desktop app's update manifest (latest.json) for a release.

The release workflow signs the packages with the updater key when the
TAURI_SIGNING_PRIVATE_KEY secret exists (docs/deploy.md): each package then
has a `.sig` next to it. This script turns those signatures into the
manifest Tauri's updater reads; the app fetches it from the latest
published release:

    https://github.com/<repo>/releases/latest/download/latest.json

    scripts/updater_manifest.py v0.1.21 UCLouvain-ENSG/peersig sigs/ [notes] > latest.json

Platform keys are `<os>-<arch>-<installer>`, and `<os>-<arch>` for the
package an install of unknown type falls back to. Without signatures, it
writes nothing and fails: no manifest, no updates.
"""

import datetime
import json
import os
import re
import sys

# (package name, platform keys). Headless packages (peersig-headless) and
# the Android app have their own updates.
RULES = [
    (r"^PeerSig_.*_x64_[A-Za-z-]+\.msi$", ["windows-x86_64-msi", "windows-x86_64"]),
    (r"^PeerSig_.*_aarch64\.app\.tar\.gz$", ["darwin-aarch64-app", "darwin-aarch64"]),
    (r"^PeerSig_.*_x64\.app\.tar\.gz$", ["darwin-x86_64-app", "darwin-x86_64"]),
    (r"^PeerSig_.*_amd64\.AppImage$", ["linux-x86_64-appimage", "linux-x86_64"]),
    (r"^PeerSig_.*_amd64\.deb$", ["linux-x86_64-deb"]),
    (r"^PeerSig-.*\.x86_64\.rpm$", ["linux-x86_64-rpm"]),
]


def manifest(tag, repo, sig_dir, notes=None, now=None):
    platforms = {}
    for name in sorted(os.listdir(sig_dir)):
        if not name.endswith(".sig"):
            continue
        package = name[: -len(".sig")]
        keys = next((k for pattern, k in RULES if re.search(pattern, package)), None)
        if keys is None:
            continue
        with open(os.path.join(sig_dir, name), encoding="utf-8") as f:
            signature = f.read().strip()
        url = f"https://github.com/{repo}/releases/download/{tag}/{package}"
        for k in keys:
            platforms[k] = {"signature": signature, "url": url}
    if not platforms:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return {
        "version": tag.removeprefix("v"),
        "notes": notes or None,
        "pub_date": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": platforms,
    }


def main():
    if len(sys.argv) not in (4, 5):
        sys.exit(__doc__)
    tag, repo, sig_dir = sys.argv[1:4]
    m = manifest(tag, repo, sig_dir, sys.argv[4] if len(sys.argv) == 5 else None)
    if m is None:
        sys.exit("no signed package: is the TAURI_SIGNING_PRIVATE_KEY secret set?")
    json.dump(m, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
