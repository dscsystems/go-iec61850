#!/usr/bin/env bash
# Live MMS, control, GOOSE and SV checks in an isolated Linux network namespace.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=${OPEN_SERVER_WORK:-$root/.interop-work/open-server}
server_ref=${OPEN_SERVER_REF:-d741481736749881a476f21a27f9bcc4d9640187}
lib_ref=${OPEN_SERVER_LIB_REF:-6d231326bff8e9b6500aa1e345c076d3a329f211}
export IEC61850_OPEN_SERVER_ROOT=${IEC61850_OPEN_SERVER_ROOT:-$work/reference}
export IEC61850_OPEN_SERVER_BUILD=${IEC61850_OPEN_SERVER_BUILD:-$work/build}
lib=${OPEN_SERVER_LIB_ROOT:-$work/libiec61850}
mkdir -p "$work"
if [[ ! -d "$IEC61850_OPEN_SERVER_ROOT/.git" ]]; then
    git clone https://github.com/robidev/iec61850_open_server "$IEC61850_OPEN_SERVER_ROOT"
    git -C "$IEC61850_OPEN_SERVER_ROOT" checkout --detach "$server_ref"
fi
if [[ ! -d "$lib/.git" ]]; then
    git clone https://github.com/mz-automation/libiec61850 "$lib"
    git -C "$lib" checkout --detach "$lib_ref"
fi
printf 'Go: %s\nopen_server: %s\nlibiec61850: %s\n' \
    "$(git -C "$root" rev-parse HEAD)" \
    "$(git -C "$IEC61850_OPEN_SERVER_ROOT" rev-parse HEAD)" \
    "$(git -C "$lib" rev-parse HEAD)"
python3 "$root/interop/open-server/build.py" "$IEC61850_OPEN_SERVER_ROOT" "$lib" "$IEC61850_OPEN_SERVER_BUILD"
cd "$root"
go test -c -race -o "$work/interop.test" ./interop
# Namespace grants CAP_NET_RAW locally; no host interfaces or ports are changed.
unshare -rn sh -c 'ip link set lo up && exec "$1" -test.run OpenServer -test.v -test.timeout 3m' sh "$work/interop.test"
