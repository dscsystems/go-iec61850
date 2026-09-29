#!/usr/bin/env bash
# Runs the bidirectional interop suite against libiec61850:
#   1. our client against the C server_example_basic_io, its control
#      services against server_example_control, and its log queries
#      against server_example_logging
#   2. the C client_example1 and client_example_log against our server
#
# It builds libiec61850 from source (cached under $WORK) and drives the
# Go interop tests, which are otherwise skipped. Usable locally and inside
# the interop Dockerfile.
#
# Environment:
#   LIBIEC61850_REF  git ref to build (default v1.6)
#   WORK             build/cache directory (default ./.interop-work)
#
# The logging examples need SQLite (libsqlite3-dev), which the log storage
# of the C server is built on.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$REPO_ROOT/.interop-work}"
REF="${LIBIEC61850_REF:-v1.6}"
LIB="$WORK/libiec61850"

mkdir -p "$WORK"

if [ ! -x "$LIB/examples/server_example_basic_io/server_example_basic_io" ]; then
  echo "== building libiec61850 $REF =="
  if [ ! -d "$LIB" ]; then
    git clone --depth 1 --branch "$REF" https://github.com/mz-automation/libiec61850.git "$LIB"
  fi
  make -C "$LIB" -j"$(nproc)" examples
fi
# The logging examples are not in libiec61850's default example set.
C_LOG_SERVER="$LIB/examples/server_example_logging/server_example_logging"
C_LOG_CLIENT="$LIB/examples/iec61850_client_example_log/client_example_log"
if [ ! -x "$C_LOG_SERVER" ] || [ ! -x "$C_LOG_CLIENT" ]; then
  echo "== building libiec61850 logging examples =="
  make -C "$LIB/examples/server_example_logging"
  make -C "$LIB/examples/iec61850_client_example_log"
fi

C_SERVER="$LIB/examples/server_example_basic_io/server_example_basic_io"
C_CTL_SERVER="$LIB/examples/server_example_control/server_example_control"
C_CLIENT="$LIB/examples/iec61850_client_example1/client_example1"
PORT="${PORT:-10102}"
CTL_PORT="${CTL_PORT:-10103}"
LOG_PORT="${LOG_PORT:-10104}"

cleanup() { [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo
echo "== direction 1: our client -> C server =="
"$C_SERVER" "$PORT" >"$WORK/cserver.log" 2>&1 &
SRV_PID=$!
sleep 1
IEC61850_TEST_SERVER="127.0.0.1:$PORT" go test "$REPO_ROOT/client/..." "$REPO_ROOT/mms/..." -run 'Interop' -v
kill "$SRV_PID" 2>/dev/null || true
SRV_PID=""

echo
echo "== direction 1b: our client -> C control server =="
"$C_CTL_SERVER" "$CTL_PORT" >"$WORK/cctlserver.log" 2>&1 &
SRV_PID=$!
sleep 1
IEC61850_TEST_CONTROL_SERVER="127.0.0.1:$CTL_PORT" go test "$REPO_ROOT/client/..." -run 'ControlInterop' -v
kill "$SRV_PID" 2>/dev/null || true
SRV_PID=""

echo
echo "== direction 1c: our client -> C logging server =="
# The C server keeps its log in SQLite in its working directory; a fresh
# database gives it exactly the one entry it writes at startup.
rm -f "$WORK/log_status.db"
(cd "$WORK" && exec "$C_LOG_SERVER" "$LOG_PORT") >"$WORK/clogserver.log" 2>&1 &
SRV_PID=$!
sleep 1
IEC61850_TEST_LOG_SERVER="127.0.0.1:$LOG_PORT" go test "$REPO_ROOT/client/..." -run 'LogInterop' -v
kill "$SRV_PID" 2>/dev/null || true
SRV_PID=""

echo
echo "== direction 2: C clients -> our server =="
IEC61850_C_CLIENT="$C_CLIENT" IEC61850_C_LOG_CLIENT="$C_LOG_CLIENT" \
  go test "$REPO_ROOT/server/..." -run 'CClient|CLogClient' -v

echo
echo "== interop OK =="
