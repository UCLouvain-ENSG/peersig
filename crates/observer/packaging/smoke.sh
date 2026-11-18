#!/bin/sh
# Checks an installed peersig-observer package, as root (CI, or a test
# container). Talks to no real server: the code is made up and not checked.
set -eu
peersig-observer --version
/usr/lib/peersig-observer/peersig-probe --version
id peersig
test "$(stat -c %U:%a /var/lib/peersig)" = peersig:700

# configure writes the settings for root and the service's group only.
peersig-observer configure --code obs-k7qf-2m9d-xw4p --server http://127.0.0.1:9 --share-domains --no-check --no-start </dev/null
test "$(stat -c %U:%G:%a /etc/peersig/observer.conf)" = root:peersig:640
grep -qx PEERSIG_CODE=OBS-K7QF-2M9D-XW4P /etc/peersig/observer.conf
grep -qx PEERSIG_SHARE_DOMAINS=true /etc/peersig/observer.conf
# A participant's code is refused, and the file is left as it was.
! peersig-observer configure --code K7QF-2M9D-XW4P --no-check --no-start </dev/null
grep -qx PEERSIG_CODE=OBS-K7QF-2M9D-XW4P /etc/peersig/observer.conf

# The service's user reads the settings; status works without a server.
runuser -u peersig -- peersig-observer status > /tmp/status
cat /tmp/status
grep -q "^server names   shared" /tmp/status
grep -q "^probe " /tmp/status

# The probe loads libpcap and captures (needs CAP_NET_RAW here: root): its
# daily file starts with a start record (status.json comes every 5 s).
rm -rf /tmp/peersig-smoke
timeout 20 /usr/lib/peersig-observer/peersig-probe run --dir /tmp/peersig-smoke --quiet --duration 3
grep -q '"type":"start"' /tmp/peersig-smoke/peersig-*.jsonl

if command -v systemd-analyze >/dev/null; then
    systemd-analyze verify /usr/lib/systemd/system/peersig-probe.service /usr/lib/systemd/system/peersig-observer.service
fi
echo "peersig-observer package: OK"
