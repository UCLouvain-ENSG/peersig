#!/usr/bin/env python3
"""Mirrors a PeerSig release from GitHub into the site's download directory.

The site (crates/server/site) links to /download/<file> and reads
/download/latest.json to offer each visitor the right package. That
directory is served by the web server in front of peersig-server (see
docs/deploy.md); this script fills it:

    scripts/mirror_release.py /var/www/peersig/download            # latest release
    scripts/mirror_release.py /var/www/peersig/download --tag v0.1.3

Every package is checked against the release's SHA256SUMS, then gets a
stable name (PeerSig-windows-x64.msi) next to its versioned one, and
latest.json is replaced last, so the page never points to a missing file.
Only Python's standard library; no GitHub token (public releases).
"""

import argparse
import hashlib
import json
import os
import sys
import urllib.request

# kind (as in site.js) -> (how the release asset's name starts and ends, stable name)
KINDS = {
    "macos-arm64": ("PeerSig", "_aarch64.dmg", "PeerSig-macos-arm64.dmg"),
    "macos-x64": ("PeerSig", "_x64.dmg", "PeerSig-macos-x64.dmg"),
    "windows-x64": ("PeerSig", ".msi", "PeerSig-windows-x64.msi"),
    "linux-deb": ("PeerSig", "_amd64.deb", "PeerSig-linux-amd64.deb"),
    "linux-rpm": ("PeerSig", ".x86_64.rpm", "PeerSig-linux-x86_64.rpm"),
    "linux-appimage": ("PeerSig", "_amd64.AppImage", "PeerSig-linux-x86_64.AppImage"),
    # Without a desktop, for servers (docs/headless.md).
    "headless-deb": ("peersig-headless_", "_amd64.deb", "peersig-headless-amd64.deb"),
    "headless-rpm": ("peersig-headless-", ".x86_64.rpm", "peersig-headless-x86_64.rpm"),
    # Android 10 or newer, both ABIs in one .apk (docs/android.md).
    "android": ("PeerSig_", "_android.apk", "PeerSig-android.apk"),
}


def get(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "peersig-mirror"}), timeout=120)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dir", help="the directory served as /download")
    ap.add_argument("--tag", help="release tag (default: the latest release)")
    ap.add_argument("--repo", default="UCLouvain-ENSG/peersig")
    a = ap.parse_args()

    which = "tags/" + a.tag if a.tag else "latest"
    rel = json.load(get("https://api.github.com/repos/%s/releases/%s" % (a.repo, which)))
    version = rel["tag_name"].lstrip("v")
    assets = {x["name"]: x for x in rel["assets"]}
    if "SHA256SUMS" not in assets:
        sys.exit("release %s has no SHA256SUMS yet (still building?)" % rel["tag_name"])
    sums_text = get(assets["SHA256SUMS"]["browser_download_url"]).read().decode()
    sums = {name.lstrip("*"): digest for digest, name in (line.split() for line in sums_text.splitlines() if line.strip())}

    os.makedirs(a.dir, exist_ok=True)
    files = {}
    for kind, (prefix, suffix, stable) in KINDS.items():
        name = next((n for n in assets if n.startswith(prefix) and n.endswith(suffix)), None)
        if name is None:
            print("no %s package in %s" % (kind, rel["tag_name"]))
            continue
        path = os.path.join(a.dir, name)
        if not os.path.exists(path) or sha256(path) != sums.get(name):
            tmp = path + ".part"
            with get(assets[name]["browser_download_url"]) as r, open(tmp, "wb") as f:
                for chunk in iter(lambda: r.read(1 << 20), b""):
                    f.write(chunk)
            if sha256(tmp) != sums.get(name):
                os.remove(tmp)
                sys.exit("%s does not match SHA256SUMS" % name)
            os.replace(tmp, path)
        # A hard link: works whatever the web server thinks of symlinks.
        link = os.path.join(a.dir, stable)
        if os.path.lexists(link):
            os.remove(link)
        os.link(path, link)
        files[kind] = {"name": name, "size": os.path.getsize(path)}
        print("%-15s %s" % (kind, name))

    sums_name = "SHA256SUMS-" + version
    with open(os.path.join(a.dir, sums_name), "w") as f:
        f.write(sums_text)
    tmp = os.path.join(a.dir, "latest.json.part")
    with open(tmp, "w") as f:
        json.dump({"version": version, "files": files, "sha256sums": sums_name}, f, indent=1)
    os.replace(tmp, os.path.join(a.dir, "latest.json"))
    print("latest.json: %s, %d packages" % (version, len(files)))


if __name__ == "__main__":
    main()
