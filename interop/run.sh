#!/usr/bin/env bash
# Runs the bidirectional interop suite against libiec61850:
#   1. our client against the C server_example_basic_io, its control
#      services against server_example_control, and its log queries
#      against server_example_logging
#   2. the C client_example1, client_example_log and mms_utility against
#      our server (mms_utility reads the Edition 2 and 2.1 classes)
#   3. libiec61850's own service tracking model (LTRK) loaded by our SCL
#      loader and checked against our 7-3 attribute tables, and the LTRK
#      our server keeps compared with libiec61850's service tracking
#      server; our client against its 9-2LE SV control block
#   4. security, against a second libiec61850 build with mbedtls 3.6:
#      R-GOOSE and R-SV (IEC 61850-90-5) both ways through
#      interop/c/rsession_peer.c, and MMS over TLS (IEC 62351-3) both ways
#      through the TLS client and server examples
#   5. GDOI (IEC 62351-9): a registration captured and decrypted by
#      Wireshark's IKEv1 dissector (tshark, or tshark in Docker)
#
# It builds libiec61850 from source (cached under $WORK) and drives the
# Go interop tests, which are otherwise skipped. Usable locally and inside
# the interop Dockerfile.
#
# Environment:
#   LIBIEC61850_REF  git ref to build (default v1.6)
#   WORK             build/cache directory (default ./.interop-work)
#   MBEDTLS_REF      mbedtls release for the security build (default 3.6.0,
#                    the version libiec61850 expects)
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

C_MMS_UTILITY="$LIB/examples/mms_utility/mms_utility"
if [ ! -x "$C_MMS_UTILITY" ]; then
  echo "== building libiec61850 mms_utility =="
  make -C "$LIB/examples/mms_utility"
fi
LTRK_ICD="$LIB/examples/server_example_service_tracking/simpleIO_ltrk_tests.icd"

# The security build: libiec61850 with mbedtls, whose CMake build adds
# R-GOOSE/R-SV (r_session) and the TLS examples. The plain Makefile does
# not compile r_session, so this one uses CMake.
MBEDTLS_REF="${MBEDTLS_REF:-3.6.0}"
SEC="$WORK/libiec61850-sec"
C_TLS_SERVER="$SEC/cbuild/examples/tls_server_example/tls_server_example"
C_TLS_CLIENT="$SEC/cbuild/examples/tls_client_example/tls_client_example"
if [ ! -x "$C_TLS_SERVER" ] || [ ! -f "$SEC/cbuild/src/libiec61850.a" ]; then
  echo "== building libiec61850 $REF with mbedtls $MBEDTLS_REF =="
  if [ ! -d "$SEC" ]; then
    git clone --depth 1 --branch "$REF" https://github.com/mz-automation/libiec61850.git "$SEC"
  fi
  if [ ! -d "$SEC/third_party/mbedtls/mbedtls-$MBEDTLS_REF" ]; then
    curl -sSL "https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v$MBEDTLS_REF.tar.gz" \
      | tar xz -C "$SEC/third_party/mbedtls"
  fi
  cmake -S "$SEC" -B "$SEC/cbuild" -DBUILD_EXAMPLES=ON -DCMAKE_BUILD_TYPE=Release
  cmake --build "$SEC/cbuild" -j"$(nproc)"
fi
MMS_PEER="$WORK/mms_peer"
if [ ! -x "$MMS_PEER" ] || [ "$REPO_ROOT/interop/c/mms_peer.c" -nt "$MMS_PEER" ]; then
  echo "== building the MMS services peer =="
  find "$SEC/src" "$SEC/hal" "$SEC/config" "$SEC/cbuild" -name '*.h' -printf '-I%h\n' | sort -u >"$WORK/inc.rsp"
  gcc -O1 -o "$MMS_PEER" "$REPO_ROOT/interop/c/mms_peer.c" @"$WORK/inc.rsp" \
    "$SEC/cbuild/src/libiec61850.a" "$SEC/cbuild/hal/libhal.a" -lpthread -lm
fi
PEER="$WORK/rsession_peer"
if [ ! -x "$PEER" ] || [ "$REPO_ROOT/interop/c/rsession_peer.c" -nt "$PEER" ]; then
  echo "== building the R-GOOSE/R-SV peer =="
  find "$SEC/src" "$SEC/hal" "$SEC/config" "$SEC/cbuild" -name '*.h' -printf '-I%h\n' | sort -u >"$WORK/inc.rsp"
  gcc -O1 -o "$PEER" "$REPO_ROOT/interop/c/rsession_peer.c" @"$WORK/inc.rsp" \
    "$SEC/cbuild/src/libiec61850.a" "$SEC/cbuild/hal/libhal.a" -lpthread -lm
fi

# server_example_files with MMS fileRename: libiec61850 compiles the
# service out by default (MMS_RENAME_FILE_SERVICE 0) and the example
# refuses renames, so a copy is built with both changed.
RENAME="$WORK/libiec61850-rename"
C_RENAME_SERVER="$RENAME/examples/server_example_files/server_example_files"
if [ ! -x "$C_RENAME_SERVER" ]; then
  echo "== building libiec61850's file server with fileRename =="
  rm -rf "$RENAME"
  cp -a "$LIB" "$RENAME"
  sed -i 's/^#define MMS_RENAME_FILE_SERVICE 0.*/#define MMS_RENAME_FILE_SERVICE 1/' "$RENAME/config/stack_config.h"
  sed -i '/Don.t allow client to rename files/,+2d' "$RENAME/examples/server_example_files/server_example_files.c"
  make -C "$RENAME" clean >/dev/null
  make -C "$RENAME" -j"$(nproc)" lib >/dev/null
  make -C "$RENAME/examples/server_example_files" >/dev/null
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
echo "== direction 1d: our client -> C file server (Status, SetFile, DeleteFile, fileRename, abort) =="
IEC61850_C_FILE_SERVER="$LIB/examples/server_example_files/server_example_files" \
IEC61850_C_RENAME_FILE_SERVER="$C_RENAME_SERVER" \
IEC61850_C_FILE_SERVER_STORE="$LIB/examples/server_example_files/vmd-filestore" \
  go test "$REPO_ROOT/client/..." -run 'FilesInterop|RenameInterop' -v

echo
echo "== direction 2: C clients -> our server =="
IEC61850_C_CLIENT="$C_CLIENT" IEC61850_C_LOG_CLIENT="$C_LOG_CLIENT" \
IEC61850_C_MMS_UTILITY="$C_MMS_UTILITY" IEC61850_C_MMS_PEER="$MMS_PEER" \
  go test "$REPO_ROOT/server/..." -run 'CClient|CLogClient|CMMSUtility|CMMSPeer' -v

echo
echo "== port 102: SV control blocks and service tracking, in a network namespace =="
# libiec61850's 9-2LE and service tracking examples listen on port 102,
# and the 9-2LE one publishes on a raw socket. Unprivileged, both run in a
# user and network namespace of their own (unshare -rn), with the tests,
# on its loopback; as root (the interop container) they run as they are.
go test -c -o "$WORK/client.test" "$REPO_ROOT/client"
go test -c -o "$WORK/server.test" "$REPO_ROOT/server"
NS_RUN="IEC61850_C_SV_SERVER='$LIB/examples/iec61850_9_2_LE_example/sv_9_2LE_example' \
  '$WORK/client.test' -test.run 'SVCBInterop' -test.v && \
  IEC61850_C_LTRK_SERVER='$SEC/cbuild/examples/server_example_service_tracking/server_example_service_tracking' \
  IEC61850_C_LTRK_ICD='$SEC/examples/server_example_service_tracking/simpleIO_ltrk_tests.icd' \
  '$WORK/server.test' -test.run 'LTRKAgainst' -test.v"
if [ "$(id -u)" = 0 ]; then
  sh -c "$NS_RUN"
else
  unshare -rn sh -c "ip link set lo up && $NS_RUN"
fi

echo
echo "== model: libiec61850's LTRK against our 7-3 tables =="
IEC61850_LIBIEC_LTRK_ICD="$LTRK_ICD" \
  go test "$REPO_ROOT/scl/..." -run 'LibiecServiceTracking' -v

echo
echo "== security: R-GOOSE and R-SV (IEC 61850-90-5) both ways =="
IEC61850_C_RSESSION_PEER="$PEER" \
  go test "$REPO_ROOT/rsession/..." -run 'Interop' -v

echo
echo "== security: MMS over TLS (IEC 62351-3) both ways, port 3782 =="
IEC61850_C_TLS_CERTS="$SEC/examples" IEC61850_C_TLS_SERVER="$C_TLS_SERVER" \
IEC61850_C_TLS_CLIENT="$C_TLS_CLIENT" \
  go test "$REPO_ROOT/iec62351/..." -run 'Interop' -v

echo
echo "== security: GDOI (IEC 62351-9) registrations dissected by Wireshark =="
if command -v tshark >/dev/null 2>&1; then
  IEC61850_TSHARK="$(command -v tshark)" go test "$REPO_ROOT/gdoi/..." -run 'Wireshark' -v
elif command -v docker >/dev/null 2>&1; then
  docker build -q -t go-iec61850-tshark - <<'DOCKERFILE' >/dev/null
FROM alpine:latest
RUN apk add --no-cache tshark
DOCKERFILE
  IEC61850_TSHARK_IMAGE=go-iec61850-tshark go test "$REPO_ROOT/gdoi/..." -run 'Wireshark' -v
else
  echo "no tshark and no docker: skipped"
fi

echo
echo "== interop OK =="
