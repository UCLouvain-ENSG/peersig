#!/bin/sh
# Builds the peersig-headless packages (.deb and .rpm): PeerSig for Linux
# servers, for participants and dedicated observers alike, with the probe,
# the peersig command and their systemd units. Needs nfpm
# (https://nfpm.goreleaser.com) and patchelf.
#
#     crates/headless/packaging/build.sh <binaries dir> <output dir> <version> [arch]
#
# <binaries dir> holds peersig-probe and peersig, built for Linux.
set -eu
bin=$(cd "$1" && pwd); mkdir -p "$2"; out=$(cd "$2" && pwd); version=$3; arch=${4:-amd64}
here=$(cd "$(dirname "$0")" && pwd)
docs=$(cd "$here/../../../docs" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Fedora, RHEL and openSUSE name libpcap libpcap.so.1, Debian libpcap.so.0.8.
mkdir "$work/rpm"
cp "$bin/peersig-probe" "$work/rpm/peersig-probe"
if patchelf --print-needed "$work/rpm/peersig-probe" | grep -qx libpcap.so.0.8; then
    patchelf --replace-needed libpcap.so.0.8 libpcap.so.1 "$work/rpm/peersig-probe"
fi
patchelf --print-needed "$work/rpm/peersig-probe" | grep -qx libpcap.so.1

cat > "$work/nfpm.yaml" <<YAML
name: peersig-headless
arch: $arch
platform: linux
version: $version
section: net
priority: optional
maintainer: uclouvain
vendor: UCLouvain
homepage: https://peersig.org
license: Apache-2.0
description: |-
  PeerSig for servers without a desktop.
  Ties the TLS fingerprints (JA4) this machine sends to the applications that
  send them, and reports them to the PeerSig study: weekly as anonymous
  ballots with a participant's code, daily with a dedicated observer's.
  Set it up with: sudo peersig configure
contents:
  - src: $bin/peersig
    dst: /usr/bin/peersig
    file_info: { mode: 0755 }
  - src: $bin/peersig-probe
    dst: /usr/lib/peersig/peersig-probe
    file_info: { mode: 0755 }
    packager: deb
  - src: $work/rpm/peersig-probe
    dst: /usr/lib/peersig/peersig-probe
    file_info: { mode: 0755 }
    packager: rpm
  - src: $here/peersig-probe.service
    dst: /usr/lib/systemd/system/peersig-probe.service
  - src: $here/peersig.service
    dst: /usr/lib/systemd/system/peersig.service
  - src: $docs/headless.md
    dst: /usr/share/doc/peersig-headless/headless.md
  - src: $docs/observers.md
    dst: /usr/share/doc/peersig-headless/observers.md
  - dst: /etc/peersig
    type: dir
    file_info: { mode: 0755 }
scripts:
  postinstall: $here/postinstall.sh
  preremove: $here/preremove.sh
  postremove: $here/postremove.sh
overrides:
  deb:
    depends: [libpcap0.8, ca-certificates]
  rpm:
    depends: [libpcap, ca-certificates]
YAML

nfpm package --config "$work/nfpm.yaml" --packager deb --target "$out"
nfpm package --config "$work/nfpm.yaml" --packager rpm --target "$out"
