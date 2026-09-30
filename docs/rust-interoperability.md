# Verification against iec61850-rust

Verified on 2026-09-30 against
[csp0924/iec61850-rust](https://github.com/csp0924/iec61850-rust/tree/d4e895217f367ed4caebf21611d2c16ee46035c0),
commit `d4e895217f367ed4caebf21611d2c16ee46035c0` (workspace version 0.2.0).
Go baseline: `ad9678d11864dc210c744feb85b1c208ed29276e`, plus the fixes
and tests accompanying this report. Toolchains: Go 1.27.1 and Rust 1.98.1,
Linux amd64.

## Result

The implementations interoperate for the tested discovery, data access,
static datasets, direct-normal controls, and URCB reporting services.
Rust clients also receive Go BRCB reports. Two reference-side failures
prevent a completely passing cross-implementation suite.

| Check | Go client → Rust server | Rust client → Go server |
|---|---|---|
| Associate, directory, Conclude | Pass | Pass |
| Identify, variable type specifications, retrieved nested model | Pass | Not tested separately |
| String, float, quality, timestamp, boolean, enum reads | Pass | Pass except enum |
| String write and readback, missing-object rejection | Pass | Pass |
| Static dataset directory and values | Pass | Pass |
| Dynamic dataset create/read/delete and rejection after deletion | Pass | Fail on create response decoding |
| Direct-normal control | Pass (success response) | Pass (success and status readback) |
| URCB enable and general interrogation | Pass | Pass |
| BRCB enable and general interrogation | Fail: no reports delivered | Pass |
| GOOSE BER codec | Pass both directions | Pass both directions |
| Sampled Values BER codec | Pass both directions | Pass both directions |

The harness has 16 leaf checks: 14 pass and 2 fail. Failures remain real test
failures; they are neither skipped nor accepted as expected successes.
The normal Go suite skips these external checks unless `IEC61850_RUST_ROOT`
is set.

The Rust baseline `cargo test --workspace --locked` passed. The Go suite is
checked with `go test -race -count=1 ./...`; the accompanying regressions
cover the Go issues described below.

## Go defects found and fixed

1. `client.EnableReporting` configured and enabled a URCB without first
   writing `Resv=true`. The Rust server requires explicit reservation and
   refused `OptFlds` with `object-access-denied`. The client now reserves
   before configuration. A strict MMS peer regression fails without this fix.
2. Report decoding discarded optional wire DataRefs and depended entirely
   on dataset-directory lookup. The Rust example returns an unqualified
   DatSet (`LLN0$dsMeas`), so the lookup fails and previously delivered entries
   had empty Ref/FC. The decoder now uses wire DataRefs when directory members
   are unavailable. A sparse-member regression and the live URCB test verify
   reference, FC, value and inclusion reason.
3. Repeated race-detector validation exposed an intermittent send/close race
   on `mms.ServerConn`'s unconfirmed-PDU queue during shutdown. Queue closure
   and enqueue now share a mutex; enqueue after closure returns `net.ErrClosed`.
   A concurrent closure/report-producer regression exercises the race.

## Reference-side failures

### Dynamic dataset response tag

Rust's
[`DefineNamedVariableListResponse`](https://github.com/csp0924/iec61850-rust/blob/d4e895217f367ed4caebf21611d2c16ee46035c0/crates/iec61850-mms/src/mms/pdu/define_named_variable_list.rs)
encodes and expects `ab 00`, treating the response as an empty constructed
SEQUENCE. Go sends `8b 00`: the response is an implicitly tagged NULL.
The Rust peer fails with:

```text
Mms("mms pdu parse error: ber tag mismatch: expected=0xAB, actual=0x8B")
```

The local libiec61850 reference independently confirms this mapping:
`DefineNamedVariableListResponse.h` typedefs the response to `NULL_t`, and
`createDefineNamedVariableListResponse` emits `0x8b`. No nonstandard response
was added to the Go server to accommodate this parser.

The Rust-server direction passes because Go tolerates the constructed
success response. The Rust-client direction confirms static dataset reads
separately before testing dynamic creation.

### BRCB receiving association is never assigned

The Rust server acknowledges configuration, `RptEna=true`, and `GI=true`,
but sends no BRCB report within five seconds, including while its example
updates the dataset every second. URCBs on the same association work.

Inspection identifies the missing connection binding:

- [`service/mod.rs`](https://github.com/csp0924/iec61850-rust/blob/d4e895217f367ed4caebf21611d2c16ee46035c0/crates/iec61850-server/src/service/mod.rs)
  calls `handle_set_brcb_field` without passing its available `conn_id`.
- [`reporting/service.rs`](https://github.com/csp0924/iec61850-rust/blob/d4e895217f367ed4caebf21611d2c16ee46035c0/crates/iec61850-server/src/reporting/service.rs)
  sets `rpt_ena` but never sets `client_conn_id`.
- [`reporting/brcb.rs`](https://github.com/csp0924/iec61850-rust/blob/d4e895217f367ed4caebf21611d2c16ee46035c0/crates/iec61850-server/src/reporting/brcb.rs)
  initializes `client_conn_id` to `None`.
- [`reporting/engine.rs`](https://github.com/csp0924/iec61850-rust/blob/d4e895217f367ed4caebf21611d2c16ee46035c0/crates/iec61850-server/src/reporting/engine.rs)
  flushes buffered reports only when that field is `Some`.

This source path explains the observed timeout. The reference libraries
remain unmodified by the harness.

## Reproduction

```sh
bash interop/run-rust.sh
```

Requires Go, Cargo/Rust, Git and dependency-download access on the first run.
The script clones the pinned reference into `.interop-work/iec61850-rust`,
adds the three strict test examples, builds them and runs the live checks.
It exits nonzero for the two failures above.

To use an existing checkout (its actual revision is printed):

```sh
IEC61850_RUST_ROOT=/absolute/path/to/iec61850-rust bash interop/run-rust.sh
```

To run checks after building:

```sh
IEC61850_RUST_ROOT=/absolute/path/to/iec61850-rust go test -count=1 -v ./interop
```

The Go tests own their server processes and use ephemeral loopback TCP
ports. Rust peers assert results and exit nonzero on errors; upstream examples
that merely print service errors are not used as evidence of client success.
Both servers load Rust's unchanged `demo.cid`.

GOOSE checks include mixed MMS data types, nested structures, signed values,
high unsigned counters, timestamp quality and alternate valid BER boolean
encodings. SV checks include two ASDUs, counter wrap, a high configuration
revision, long BER lengths, refresh time, sample rate/mode and grandmaster
identity. Rust independently constructs matching fixtures, validates Go
encodings and emits encodings that Go parses and compares semantically.
The eight-byte APDU header is supplied by the Go test: these are BER codec
checks, not raw Ethernet transport tests.

## Limits

This is interoperability verification, not IEC conformance certification.
It does not verify cross-stack TLS, raw Ethernet transmission, report
segmentation, BRCB reconnect/replay/overflow, integrity/data-change triggers,
SBO or enhanced-security control, logs, setting groups or GoCB management.
The reference does not implement MMS file services, SVCB management, R-GOOSE
or R-SV, so those were not tested against it. See its
[coverage and gaps](https://github.com/csp0924/iec61850-rust/blob/d4e895217f367ed4caebf21611d2c16ee46035c0/README.md).
