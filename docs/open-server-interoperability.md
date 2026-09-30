# open_server interoperability verification

Verified on 2026-09-30 against
[robidev/iec61850_open_server](https://github.com/robidev/iec61850_open_server),
revision `d741481736749881a476f21a27f9bcc4d9640187`, with libiec61850 revision
`6d231326bff8e9b6500aa1e345c076d3a329f211` (MMS identity reports 1.6.2).
This application uses libiec61850 for its protocol stack, with its own logical
node handlers and simulation plugins. It provides additional application-level
coverage rather than an independent implementation of MMS.

## Results

The reproducible harness passes **23 of 25 checks**. Two SV checks fail because
the reference publisher disagrees with its MMS control block. The harness exits
nonzero and retains these assertions so the inconsistencies remain visible.
The full default Go suite passes with `go test -race -count=1 ./...`; external
interop tests are skipped there unless their environment variables are supplied.

| Checks | Result |
| --- | --- |
| Association, identity, status, device/LN directories, type attributes and model retrieval | Pass |
| Typed and asynchronous reads, missing-object rejection | Pass |
| CF/ST write rejection without changing the value | Pass |
| Static/dynamic datasets, create/read/delete | Pass |
| File directory/read, upload with ObtainFile, deletion refusal and missing-file rejection | Pass |
| BRCB GI/integrity, data references, entry IDs and reasons | Pass |
| SBO-enhanced select/cancel, command termination, simulated switching and CILO interlocking | Pass |
| Go GOOSE trip into reference; reference GOOSE, MMS state and data-change report back to Go | Pass |
| Conclude and Abort | Pass |
| SV 9-2LE payload decoding and consecutive sample counters | Pass |
| SV reservation and explicit enable/disable, including stopping received frames | Pass |
| SV wire stream ID agrees with advertised SVCB | **Fail (reference)** |
| Initial SV transmission agrees with advertised SvEna | **Fail (reference)** |
| FEED1 protection setting write/readback, range rejection and unchanged value after refusal | Pass |
| SCL loading: four IEDs from open_substation.scd, six from model_substation.scd, one from protection_relay.scd | 11 pass |

Live tests use upstream IED1_XCBR, IED3_SMV and FEED1 configurations, unchanged.
The breaker simulation plugin is built from upstream and run with its original
configuration. Files and process working directories are private per test.

## Go fix

`ControlObject.Cancel` sent the six-field Oper structure, including Check.
The reference rejected this with MMS `type-inconsistent`. Cancel now sends the
five fields ctlVal, origin, ctlNum, T and Test. A regression test checks that
shape, and live select/cancel succeeds without moving the breaker. The full
race suite and the reference's subsequent switching/interlocking checks pass.

## Reference inconsistencies

1. MMS advertises `svID="xxxxMUnn01"`, but Ethernet frames carry
   `svID="PhsMeas1"`. The upstream publisher
   [passes the dataset name as the ASDU stream ID](https://github.com/robidev/iec61850_open_server/blob/d741481736749881a476f21a27f9bcc4d9640187/LNs/SMVPublisher.c#L51).
2. Frames arrive immediately while MMS reports `SvEna=false`. The publisher
   [initializes its internal enable flag to 1](https://github.com/robidev/iec61850_open_server/blob/d741481736749881a476f21a27f9bcc4d9640187/LNs/SMVPublisher.c#L77).
   Explicitly enabling and then disabling through MMS updates the advertised
   state and stops the stream, which the harness verifies separately.

No upstream source patches or expected-failure suppression are applied.

## Reproduce

```sh
bash interop/run-open-server.sh
```

Requires Linux, Git, Go, GCC, Make, Python 3, `unshare` and `ip` (iproute2).
Unprivileged user/network namespaces must be enabled. The script builds the
upstream CMake source list directly and the breaker plugin, installs the static
library into a private directory, and runs race-enabled Go tests in a fresh
network namespace with loopback enabled. Raw GOOSE/SV frames stay within that
namespace; no host interface changes or global library installs are needed.
No CMake, Docker, Python simulation dependencies or port 102 privilege is required.

Builds/checkouts are cached under `.interop-work/open-server/`. New clones use
the pinned revisions above. Existing checkouts are used as supplied, with their
actual revisions printed. Override paths with absolute paths:

```sh
IEC61850_OPEN_SERVER_ROOT=/path/to/iec61850_open_server \
OPEN_SERVER_LIB_ROOT=/path/to/libiec61850 \
IEC61850_OPEN_SERVER_BUILD=/tmp/open-server-build \
OPEN_SERVER_WORK=/tmp/open-server-interop \
bash interop/run-open-server.sh
```

`OPEN_SERVER_REF` and `OPEN_SERVER_LIB_REF` select revisions for new clones.
The test binary prints each check and includes reference process logs on failure.

## Scope

This verifies the Go client against a running reference server, bidirectional
GOOSE over raw Ethernet, SV reception/control, and SCL model loading. It is not
an IEC 61850 conformance assessment. It does not exercise the Go server against
a client from this project, the complete Docker/PySpice substation simulation,
all logical nodes, TLS, URCBs, report segmentation/replay, logs or SV publishing
from Go into the reference application.
