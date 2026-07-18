#!/usr/bin/env bash
# Runs the bidirectional interop suite against libiec61850:
#   1. our client against the C server_example_basic_io
#   2. the C client_example1 / control example against our server
#
# It builds libiec61850 from source (cached under $WORK) and drives the
# Go interop tests, which are otherwise skipped. Usable locally and inside
# the interop Dockerfile.
#
# Environment:
#   LIBIEC61850_REF  git ref to build (default v1.6)
#   WORK             build/cache directory (default ./.interop-work)
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

C_SERVER="$LIB/examples/server_example_basic_io/server_example_basic_io"
C_CLIENT="$LIB/examples/iec61850_client_example1/client_example1"
PORT="${PORT:-10102}"

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
echo "== direction 2: C client -> our server =="
IEC61850_C_CLIENT="$C_CLIENT" go test "$REPO_ROOT/server/..." -run 'CClient' -v

echo
echo "== interop OK =="
