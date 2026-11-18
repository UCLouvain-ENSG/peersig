#!/bin/sh
# peersig-headless, after removal. A purge (deb) also deletes the settings,
# which hold the code, and the state and logs.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    rm -f /etc/peersig/peersig.conf /etc/peersig/peersig.tmp
    rmdir /etc/peersig 2>/dev/null || true
    rm -rf /var/lib/peersig
fi
