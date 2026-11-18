#!/bin/sh
# Builds the peersig-observer packages (.deb and .rpm): a headless dedicated
# observer for Linux servers, with the probe, peersig-observer and their
# systemd units. Needs nfpm (https://nfpm.goreleaser.com) and patchelf.
#
#     crates/observer/packaging/build.sh <binaries dir> <output dir> <version> [arch]
#
# <binaries dir> holds peersig-probe and peersig-observer, built for Linux.
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
name: peersig-observer
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
  PeerSig dedicated observer, for servers without a desktop.
  Ties the TLS fingerprints (JA4) this machine sends to the applications that
  send them, and reports them daily to the PeerSig study, which publishes
  them without threshold. Needs an observer code from the study team:
  sudo peersig-observer configure
contents:
  - src: $bin/peersig-observer
    dst: /usr/bin/peersig-observer
    file_info: { mode: 0755 }
  - src: $bin/peersig-probe
    dst: /usr/lib/peersig-observer/peersig-probe
    file_info: { mode: 0755 }
    packager: deb
  - src: $work/rpm/peersig-probe
    dst: /usr/lib/peersig-observer/peersig-probe
    file_info: { mode: 0755 }
    packager: rpm
  - src: $here/peersig-probe.service
    dst: /usr/lib/systemd/system/peersig-probe.service
  - src: $here/peersig-observer.service
    dst: /usr/lib/systemd/system/peersig-observer.service
  - src: $docs/observers.md
    dst: /usr/share/doc/peersig-observer/observers.md
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
