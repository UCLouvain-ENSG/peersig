#!/bin/sh
# Lets the capture probe read packets and the process table without root.
set -e
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin,cap_dac_read_search,cap_sys_ptrace+eip /usr/bin/peersig-probe || true
fi
