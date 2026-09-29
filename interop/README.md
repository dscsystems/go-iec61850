# Interop harness

Bidirectional interoperability tests against
[libiec61850](https://github.com/mz-automation/libiec61850):

1. our `client` against the C `server_example_basic_io`, the control
   example and the logging example
2. the C `client_example1`, `client_example_log`, `mms_utility` and
   `interop/c/mms_peer.c` (authentication, Status, SetFile, DeleteFile,
   release, abort) against our `server`; and our client against the C
   `server_example_files`
3. libiec61850's service tracking model (`simpleIO_ltrk_tests.icd`, the
   LTRK of `server_example_service_tracking`) loaded by our SCL loader and
   compared with our IEC 61850-7-3 attribute tables
4. security, against a second libiec61850 build with mbedtls 3.6: R-GOOSE
   and R-SV (IEC 61850-90-5) both ways through `interop/c/rsession_peer.c`,
   a small driver of libiec61850's session layer, and MMS over TLS
   (IEC 62351-3) both ways through its TLS client and server examples

5. GDOI (IEC 62351-9): no open implementation exists to register with, so
   a registration between our key server and member is captured and handed
   to Wireshark's IKEv1 dissector, which decrypts every message with its
   own IV derivation from the session key and dissects the GDOI payloads
   (`tshark` on the path, or `tshark` in a Docker image the script builds)

The logging examples need SQLite (`libsqlite3-dev`), which the C server's
log storage is built on.

The Go interop tests are guarded by environment variables and skipped in
the normal `go test ./...` run, so a checkout without a C toolchain stays
green. This harness builds libiec61850 and supplies those variables.

## Run locally

```sh
bash interop/run.sh          # clones + builds libiec61850 v1.6, runs both directions
LIBIEC61850_REF=v1.5 bash interop/run.sh
```

The build is cached under `.interop-work/` (git-ignored).

## Run in Docker

```sh
docker build -f interop/Dockerfile -t go-iec61850-interop .
docker run --rm go-iec61850-interop
```

## CI

`.github/workflows/interop.yml` runs `interop/run.sh` on every push and
pull request.

## Coverage

| Feature | our client -> C server | C client -> our server |
|---------|:----------------------:|:----------------------:|
| Associate / Identify | ✓ | ✓ |
| Browse (getNameList) | ✓ | ✓ |
| Read / Write | ✓ | ✓ |
| GetVariableAccessAttributes | ✓ | ✓ |
| Datasets | ✓ | ✓ |
| Reporting (URCB, GI/dchg/integrity) | ✓ | ✓ |
| Control (direct-normal, direct-enhanced) | ✓ | ✓ |
| Control: SBO-enhanced, CommandTermination±, LastApplError | ✓ | |
| Logs: browse (ACSILog/LCB), LCB read, ReadJournal by time and after entry | ✓ | ✓ |
| Logs: LogEna write, entries with data reference, value and ReasonCode | | ✓ |
| Association: password authentication and rejection | | ✓ |
| MMS Status | ✓ | ✓ |
| SetFile (MMS obtainFile, the server reading back from the client) | ✓ | ✓ |
| DeleteFile, including the server's refusal | ✓ | ✓ |
| Release (Conclude), Abort | ✓ | ✓ |
| Ed 2/2.1 classes (HST, BAC, ORG, TSG, CUG, VSG, CSG): directory, read, arrays of structures | | ✓ |
| Service tracking (CTS, GTS) under FC SR, PhyComAddr structure | | ✓ |
| R-GOOSE, R-SV: unsecured (C publishes) | ✓ | |
| R-GOOSE, R-SV: HMAC-SHA256-128 | ✓ | ✓ |
| R-GOOSE, R-SV: HMAC-SHA256-256 (libiec61850's own encoding is malformed) | | ✓ |
| R-GOOSE, R-SV: AES-128-GCM, AES-256-GCM | ✓ | ✓ |
| MMS over TLS, IEC 62351-3 profile, mutual authentication | ✓ | ✓ |
| GDOI registration (ECDSA, RSA, PSK) decrypted and dissected by Wireshark | n/a | n/a |

For R-GOOSE/R-SV the first column is libiec61850 publishing to us, the
second us publishing to libiec61850. libiec61850 refuses an unsecured
version 2 SPDU, so that mode is tested one way. The TLS tests use port
3782, the MMS-over-TLS port both examples are fixed to.

The service tracking model of libiec61850 (CTS for a boolean, an INT32 and
a Tcmd control, UTS, BTS, GTS, STS and LTS) is also checked, attribute by
attribute and in order within each functional constraint, against the
templates of `model.NewDataObject`. `server_example_service_tracking`
itself listens on port 102 only, so it is not run.

SBO with normal security is implemented on the server (`server/select.go`)
and covered by the unit tests; it has no interop assertion yet.

## Edition 2.1

This suite exercises the Edition 2 wire formats against libiec61850 v1.6,
which implements Edition 2 and the R-GOOSE/R-SV profiles. It is not an
Edition 2.1 conformance suite: it tests that the two stacks interoperate,
not that either is conformant.

That distinction matters for reading the Edition 2.1 work. Most of it is
*loader* changes — the SCL parser, the diagnostics, the control-block
objects the server now materialises — which interop cannot exercise at all,
because there is only one stack involved. Those are covered by
`scl/edition_test.go` and `server/cb_test.go` against the synthetic
`2007B4` fixture. The wire-format changes interop *can* cover — `smpMod`,
GOOSE state and timing semantics, time quality — are covered by
`goose/ed21_test.go` and `sv/ed21_test.go`.

Adding interop assertions for the wire-format changes is the obvious next
step and needs no harness change.
