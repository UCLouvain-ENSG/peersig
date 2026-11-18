#!/bin/sh
# peersig-headless, before removal (deb: remove; rpm: 0), not before an upgrade.
set -e
case "$1" in
remove | 0)
    if [ -d /run/systemd/system ]; then
        systemctl disable --now peersig.service peersig-probe.service || true
    fi
    ;;
esac
