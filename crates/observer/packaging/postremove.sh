#!/bin/sh
# peersig-observer, after removal. A purge (deb) also deletes the settings,
# which hold the observer's code, and the logs.
set -e
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
if [ "$1" = purge ]; then
    rm -f /etc/peersig/observer.conf /etc/peersig/observer.tmp
    rmdir /etc/peersig 2>/dev/null || true
    rm -rf /var/lib/peersig
fi
