#!/bin/sh
# peersig-headless, after install or upgrade (deb: configure; rpm: 1 or 2).
set -e
getent group peersig >/dev/null || groupadd --system peersig
getent passwd peersig >/dev/null ||
    useradd --system --gid peersig --home-dir /var/lib/peersig --no-create-home --shell /usr/sbin/nologin peersig
install -d -o peersig -g peersig -m 0700 /var/lib/peersig
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    # An upgrade restarts what was running; a first install starts nothing.
    systemctl try-restart peersig-probe.service peersig.service || true
fi
if [ ! -e /etc/peersig/peersig.conf ]; then
    echo "peersig: set this machine up with: sudo peersig configure"
fi
