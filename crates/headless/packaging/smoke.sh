#!/bin/sh
# Checks an installed peersig-headless package, as root (CI, or a test
# container). Talks to no real server: the codes are made up and not
# checked.
set -eu
peersig --version
/usr/lib/peersig/peersig-probe --version
id peersig
test "$(stat -c %U:%a /var/lib/peersig)" = peersig:700

# A participant: configure writes the settings for root and the service's
# group only, with the relay.
peersig configure --code k7qf-2m9d-xw4p --server http://127.0.0.1:9 --no-check --no-start --yes </dev/null
test "$(stat -c %U:%G:%a /etc/peersig/peersig.conf)" = root:peersig:640
grep -qx PEERSIG_CODE=K7QF-2M9D-XW4P /etc/peersig/peersig.conf
grep -qx PEERSIG_RELAY=https://relay.peersig.org /etc/peersig/peersig.conf
grep -qx PEERSIG_REVIEW_HOURS=24 /etc/peersig/peersig.conf
grep -qx PEERSIG_SHARE_DOMAINS=false /etc/peersig/peersig.conf
# Not without agreeing, nor with something that is not a code.
! peersig configure --code K7QF-2M9D-XW4P --no-check --no-start </dev/null
! peersig configure --code hello --no-check --no-start --yes </dev/null
# A dedicated observer, on the same machine.
peersig configure --code obs-k7qf-2m9d-xw4p --share-domains --no-check --no-start --yes </dev/null
grep -qx PEERSIG_CODE=OBS-K7QF-2M9D-XW4P /etc/peersig/peersig.conf
grep -qx PEERSIG_SHARE_DOMAINS=true /etc/peersig/peersig.conf
! grep -q PEERSIG_RELAY /etc/peersig/peersig.conf

# The service's user reads the settings; status works without a server.
runuser -u peersig -- peersig status > /tmp/status
cat /tmp/status
grep -q "^server names   shared" /tmp/status
grep -q "^probe " /tmp/status

# The probe loads libpcap and captures (needs CAP_NET_RAW here: root): its
# daily file starts with a start record (status.json comes every 5 s).
rm -rf /tmp/peersig-smoke
timeout 20 /usr/lib/peersig/peersig-probe run --dir /tmp/peersig-smoke --quiet --duration 3
grep -q '"type":"start"' /tmp/peersig-smoke/peersig-*.jsonl

if command -v systemd-analyze >/dev/null; then
    systemd-analyze verify /usr/lib/systemd/system/peersig-probe.service /usr/lib/systemd/system/peersig.service
fi
echo "peersig-headless package: OK"
