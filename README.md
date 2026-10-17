# go-iec61850

A pure-Go implementation of the IEC 61850 protocol family:

- **MMS client and server** (IEC 61850-8-1 over TPKT/COTP/Session/Presentation/ACSE)
- **GOOSE** publisher and subscriber (raw Ethernet, Linux AF_PACKET)
- **Sampled Values** (IEC 61850-9-2 / 9-2LE) publisher and subscriber
- **R-GOOSE and R-SV** (IEC 61850-90-5) over UDP, signed (HMAC-SHA256) or
  encrypted (AES-GCM), with their keys distributed by **GDOI** (IEC
  62351-9, RFC 6407/8052), MMS over TLS under the IEC 62351-3 profile, and
  IEC 62351-4 end-to-end MMS security (native mode)
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

Over TLS (IEC 62351-3), `ied-client` takes its certificate and the
server's CA; the server certificate must name the host of `-addr`
(`-tls-server-name` or `-tls-no-server-name` to change that):

```sh
go run ./cmd/ied-client -addr 192.168.10.5:3782 \
  -tls-cert client.pem -tls-key client.key -tls-ca ca.pem -tls-crl ca.crl scan
```

The IEC 62351-4 native-mode profile (`-tls-native`) mandates
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, which Go's crypto/tls does not
implement. Package `iec62351/ossltls` runs TLS on OpenSSL 3 instead. It
needs cgo, libssl-dev and the build tag `openssl`; in `ied-client` it is
the `-tls-openssl` option:

```sh
go build -tags openssl -o ied-client ./cmd/ied-client
./ied-client -addr 192.168.10.5:3782 -tls-openssl -tls-native \
  -tls-cert client.pem -tls-key client.key -tls-ca ca.pem scan
```

The static-DH suites of the same table (TLS_DH_RSA_*, 0x00A0 mandatory,
0x00A1, 0x0031) exist only in OpenSSL 1.0.2, which has been out of support
since 2019. A separate build links it statically, with the build tags
`openssl,openssl_v1`: it offers them in native mode, has no TLS 1.3, and a
server serves them with a certificate holding a PKCS #3 Diffie-Hellman key
(`ossltls.Context.SetStaticDH`). `iec62351/ossltls/openssl-v1.sh` builds
OpenSSL 1.0.2u (checksum-verified) for it, on Linux or in an MSYS2 MINGW64
shell on Windows; on Linux, `OPENSSL_V1_CROSS=x86_64-w64-mingw32-`
cross-compiles it for Windows with MinGW-w64:

```sh
iec62351/ossltls/openssl-v1.sh ~/.cache/openssl-1.0.2u
PKG_CONFIG_LIBDIR=~/.cache/openssl-1.0.2u/pkgconfig \
  go build -tags openssl,openssl_v1 -o ied-client ./cmd/ied-client
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
- [docs/iec62351-4-implementation-guide.md](docs/iec62351-4-implementation-guide.md) — IEC 62351-4 implementation plan, wire contract, interpretations and status
- [docs/pics.md](docs/pics.md) — Protocol Implementation Conformance Statement (ACSI models and services, MMS, GOOSE, SV, security)
- [docs/edition-2.1.md](docs/edition-2.1.md) — the detailed IEC 61850 Edition 2.1 conformance record
- [docs/open-server-interoperability.md](docs/open-server-interoperability.md) — verification against iec61850_open_server (`interop/run-open-server.sh`)
- [docs/rust-interoperability.md](docs/rust-interoperability.md) — verification against iec61850-rust (`interop/run-rust.sh`)
- [SKILL.md](SKILL.md) — task-oriented guide for building apps (agent-friendly)
- [examples/](examples) — runnable programs: `read`, `server`, `report-monitor`, `goose-subscribe`, `control`
- godoc: `go doc github.com/dscsystems/go-iec61850/client` (etc.)

## Packages

| Package | Purpose |
|---------|---------|
| `client` | High-level ACSI client (browse, read/write, datasets, reports, controls, files) |
| `server` | High-level ACSI server driven by an SCL or programmatic model |
| `goose`, `sv` | GOOSE and Sampled Values publish/subscribe over `ethernet` |
| `rsession` | R-GOOSE / R-SV session protocol (IEC 61850-90-5) with its message security; an `ethernet.Interface` over UDP |
| `iec62351` | IEC 62351-3 TLS profile for the MMS client and server; `iec62351/ossltls` is its optional OpenSSL engine (cgo, build tag `openssl`) |
| `iec62351/e2e`, `iec62351/e2e/osi`, `iec62351/pki` | IEC 62351-4 end-to-end security (native mode) for MMS, its OSI mapping, and the E2E certificate handling; `iec62351/e2e/e2efile` loads credentials and trust from files |
| `iec62351/aprofile` | IEC 62351-4 A-profile (compatibility mode): certificate-based ACSE authentication |
| `gdoi` | IEC 62351-9 group key distribution: GDOI key server and group member |
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
transport is Linux-only (AF_PACKET); no capture backend for other platforms
is implemented. R-GOOSE/R-SV over UDP (`rsession`) is portable.

Implemented: MMS client/server, browse/read/write, datasets, reporting
(URCB and buffered BRCB with EntryID resync, GI/integrity/data-change),
control (all four models: direct/SBO, normal/enhanced), setting groups
(SGCB), file services (directory and streamed read), log queries
(readJournal by time and after-entry), GOOSE and SV pub/sub, SCL parsing,
R-GOOSE/R-SV with HMAC or AES-GCM message security, TLS transport under
the IEC 62351-3 profile.
