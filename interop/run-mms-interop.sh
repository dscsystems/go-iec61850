#!/usr/bin/env bash
# Runs interop/mmsinterop against the otfabric/mms-interop adapter images
# (libiec61850, iec61850bean, iec61850-rust), in both directions. Needs
# Docker on Linux: the adapters run on the host network.
#
# Environment:
#   MMS_INTEROP_STACKS   comma-separated subset of the stacks (default all)
#   LIBIEC61850_IMAGE, IEC61850BEAN_IMAGE, IEC61850RUST_IMAGE
#                        replace a pinned image, e.g. a local mms-interop build
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

# The pinned images are the defaults in harness_test.go; pull them before
# the tests so the pull does not run against their timeouts.
images=$(grep -oE 'ghcr\.io/otfabric/mms-interop-[a-z0-9-]+@sha256:[0-9a-f]+' interop/mmsinterop/harness_test.go)
[ -n "${LIBIEC61850_IMAGE:-}" ] && images=$(echo "$images" | grep -v libiec61850; echo "$LIBIEC61850_IMAGE")
[ -n "${IEC61850BEAN_IMAGE:-}" ] && images=$(echo "$images" | grep -v iec61850bean; echo "$IEC61850BEAN_IMAGE")
[ -n "${IEC61850RUST_IMAGE:-}" ] && images=$(echo "$images" | grep -v iec61850-rust; echo "$IEC61850RUST_IMAGE")
for img in $images; do
    docker image inspect "$img" >/dev/null 2>&1 || docker pull -q "$img"
done

printf 'Go revision: %s\n' "$(git rev-parse HEAD)"
for img in $images; do
    printf 'image: %s\n' "$img"
done
MMS_INTEROP=1 go test -count=1 -v -timeout 15m ./interop/mmsinterop
