# go-iec61850

A pure-Go implementation of the IEC 61850 protocol family:

- **MMS client and server** (IEC 61850-8-1 over TPKT/COTP/Session/Presentation/ACSE)
- **GOOSE** publisher and subscriber (raw Ethernet, Linux AF_PACKET)
- **Sampled Values** (IEC 61850-9-2 / 9-2LE) publisher and subscriber
- **SCL** (ICD/CID/SCD) parsing and runtime model instantiation

No cgo. GPLv3 licensed.

## Quick start

Run the example server and explore it with the TUI client:

```sh
go run ./cmd/ied-server -scl testdata/simpleIO_direct_control.cid -addr :10102
go run ./cmd/iedx 127.0.0.1:10102        # or run with no address for a connect form
```

`iedx` is a full mouse-driven terminal client: a Browse tab (model tree,
live read, type-aware write, auto-refresh, filter), plus Reports, Datasets,
Controls, Setting Groups, Files and Logs tabs. Click tabs and rows, scroll
with the wheel, `?` for keys.

`ied-server` simulates live data (measurand drift, toggling status points
with quality and timestamps) so configured reports fire, accepts controls,
and can serve files with `-files DIR`. `ied-client test` exercises every
feature the server exposes and prints a PASS/FAIL/SKIP report:

```sh
go run ./cmd/ied-server -scl testdata/simpleIO_direct_control.cid -addr :10102 -files /tmp/comtrade
go run ./cmd/ied-client -addr 127.0.0.1:10102 test
```

Read a value programmatically:

```go
c, err := client.Dial(ctx, "192.168.10.5:102")
if err != nil { ... }
defer c.Close()

v, err := c.Read(ctx, "simpleIOGenericIO/GGIO1.AnIn1.mag.f", model.MX)
```

## Documentation

- [docs/api.md](docs/api.md) — full API reference with examples for every package
- [docs/developer-guide.md](docs/developer-guide.md) — architecture and how to extend the stack
- [SKILL.md](SKILL.md) — task-oriented guide for building apps (agent-friendly)
- [examples/](examples) — runnable programs: `read`, `server`, `report-monitor`, `goose-subscribe`, `control`
- godoc: `go doc github.com/dscsystems/go-iec61850/client` (etc.)

## Packages

| Package | Purpose |
|---------|---------|
| `client` | High-level ACSI client (browse, read/write, datasets, reports, controls, files) |
| `server` | High-level ACSI server driven by an SCL or programmatic model |
| `goose`, `sv` | GOOSE and Sampled Values publish/subscribe over `ethernet` |
| `scl` | SCL file parsing and model building |
| `model` | IEC 61850 object model, functional constraints, Quality/Timestamp types |
| `mms` | Low-level MMS (ISO 9506) values, codecs and client connection |
| `asn1` | Minimal BER runtime used by all codecs |

## Interop

Verified in both directions against
[libiec61850](https://github.com/mz-automation/libiec61850) 1.6:

- our `client` drives the C `server_example_basic_io`: browse, read,
  write, model retrieval, datasets, reporting (GI), control
- the C `client_example1` and control example drive our `server`:
  association, read/write, datasets, reporting (data-change and integrity
  reports), and control (direct-normal and direct-enhanced)

Run it with `bash interop/run.sh` (see [interop/](interop/)).

The interop tests are guarded by environment variables so CI without a C
toolchain stays green:

```sh
# our client against a running C server on :10102
IEC61850_TEST_SERVER=127.0.0.1:10102 go test ./client/ ./mms/
# the C client against our in-process server
IEC61850_C_CLIENT=/path/to/client_example1 go test ./server/ -run CClient
```

## Status

Initial-release; the API may change until v1. All packages build without cgo
and cross-compile to Linux, Windows and macOS. GOOSE and SV raw-socket
transport is Linux-only (AF_PACKET); other platforms need a capture
backend.

Implemented: MMS client/server, browse/read/write, datasets, reporting
(URCB and buffered BRCB with EntryID resync, GI/integrity/data-change),
control (all four models: direct/SBO, normal/enhanced), setting groups
(SGCB), file services (directory and streamed read), log queries
(readJournal by time and after-entry), GOOSE and SV pub/sub, SCL parsing,
TLS transport.
