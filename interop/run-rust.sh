#!/usr/bin/env bash
# Bidirectional cross-implementation checks. Known reference failures stay red.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
ref=${IEC61850_RUST_REF:-d4e895217f367ed4caebf21611d2c16ee46035c0}
export IEC61850_RUST_ROOT=${IEC61850_RUST_ROOT:-$root/.interop-work/iec61850-rust}
if [[ ! -d "$IEC61850_RUST_ROOT/.git" ]]; then
    mkdir -p "$(dirname "$IEC61850_RUST_ROOT")"
    git clone https://github.com/csp0924/iec61850-rust "$IEC61850_RUST_ROOT"
    git -C "$IEC61850_RUST_ROOT" checkout --detach "$ref"
fi
export CARGO_TARGET_DIR="$IEC61850_RUST_ROOT/target"
printf 'Go revision: %s\nRust revision: %s\n' "$(git -C "$root" rev-parse HEAD)" "$(git -C "$IEC61850_RUST_ROOT" rev-parse HEAD)"
# Add our strict peers as examples; leave the reference library unmodified.
cp "$root/interop/rust/peer.rs" "$IEC61850_RUST_ROOT/crates/iec61850-client/examples/go_interop_peer.rs"
cp "$root/interop/rust/goose_codec.rs" "$IEC61850_RUST_ROOT/crates/iec61850-goose/examples/go_interop_goose.rs"
cp "$root/interop/rust/sv_codec.rs" "$IEC61850_RUST_ROOT/crates/iec61850-sv/examples/go_interop_sv.rs"
cargo build --locked --manifest-path "$IEC61850_RUST_ROOT/Cargo.toml" \
    -p iec61850-server --example server_from_scl \
    -p iec61850-client --example go_interop_peer \
    -p iec61850-goose --example go_interop_goose \
    -p iec61850-sv --example go_interop_sv
cd "$root"
go test -count=1 -v -timeout 2m ./interop
