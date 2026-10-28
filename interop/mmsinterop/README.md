# mms-interop suite

IEC 61850 interoperability tests against the adapter images of
[otfabric/mms-interop](https://github.com/otfabric/mms-interop) v0.4.0:
[libiec61850](https://github.com/mz-automation/libiec61850),
[iec61850bean](https://www.beanit.com/iec-61850/) and
[iec61850-rust](https://github.com/csp0924/iec61850-rust), each in its own
container, all serving or driving the same fixture.

mms-interop supplies the adapters, the fixture and the adapter contract
(JSON Lines on stdout, a `ready` event, exit codes); the assertions live
here, against this library's API. Its fourth stack, `dscsystems`, is this
library at a pinned commit, so it is not tested against.

```sh
bash interop/run-mms-interop.sh                      # all stacks
MMS_INTEROP_STACKS=iec61850bean bash interop/run-mms-interop.sh
```

The tests are skipped unless `MMS_INTEROP=1`, which the script sets. With
it set, a missing Docker daemon or image fails the run instead of skipping
it. They need Docker on Linux: the adapters run on the host network so
that they and the test reach each other on the loopback.

| Variable | Meaning |
|---|---|
| `MMS_INTEROP=1` | run the suite |
| `MMS_INTEROP_STACKS` | comma-separated subset: `libiec61850`, `iec61850bean`, `iec61850-rust` |
| `LIBIEC61850_IMAGE`, `IEC61850BEAN_IMAGE`, `IEC61850RUST_IMAGE` | replace a pinned image (digests in `harness_test.go`), e.g. `mms-interop-libiec61850:local` from mms-interop's `make build` |

## Coverage

| Test | Direction | What it checks |
|---|---|---|
| `TestClient_Directory` | our client → `*-ied-server` | server, LD and LN directories |
| `TestClient_RetrieveModel` | our client → `*-ied-server` | every fixture attribute in the retrieved model under its FC |
| `TestClient_ReadFixtureValues` | our client → `*-ied-server` | every `values.json` entry, typed |
| `TestClient_WriteSetting` | our client → `*-ied-server` | write and read back of `SetInt1.setVal[SP]` |
| `TestClient_WriteStatusRefused` | our client → `*-ied-server` | a write of FC ST answered with a DataAccessError |
| `TestClient_ReadDataSet` | our client → `*-ied-server` | `dsInterop`, with and without `specificationWithResult` |
| `TestClient_URCB_GI` | our client → `*-ied-server` | `urcb01` configuration, enable, GI report |
| `TestClient_Control` | our client → `*-ied-server` | direct, SBO normal, SBO enhanced, stVal following |
| `TestClient_MSVCB` | our client → `*-ied-server` | `MSVCB02` over MMS, where the stack serves it |
| `TestServer_IEDClient` | `*-ied-client` → our server | the adapter's browse/read/write/dataset sequence |
| `TestServer_IEDController` | `*-ied-controller` → our server | the three control models, as the peer runs them |
| `TestServer_IEDReporter` | `*-ied-reporter` → our server | `urcb01` enable, dchg report, disable |

## Fixture

`testdata/` is a copy of mms-interop v0.4.0 `fixtures/iec61850/`
(`interop.icd`, `values.json`, revision `iec61850-v3`) and
`fixtures/capabilities.json`; see `testdata/NOTICE`. Update it together
with the image digests.

Third-party servers name the logical device after the IED
(`InteropIEDInteropLD`) and index report instances (`urcb0101`, the
IEC 61850-6 default), so the client tests resolve both names. The client
adapters address `InteropLD/LLN0.RP.urcb01` as given, which is what the
contract expects a Go server to serve. This server is therefore built
from the fixture with `LDevice@ldName="InteropLD"` and
`ReportControl@indexed="false"`, applied to the parsed SCL
(`scl.UseLDName`), not by editing the file.

## Known gaps

Peer behaviour these tests skip or waive is listed in one of two places,
and every skip gives its reason:

- `testdata/capabilities.json` `knownLimitations`, mms-interop's register
  (for example, iec61850bean's server does not expose `SBOw`).
- `gaps` in `harness_test.go`, for gaps found here that the register does
  not have yet:
  - libiec61850 and iec61850bean: the IED server adapters do not apply
    the `values.json` entries `GGIO1.DPS1.stVal` and `MMTR1.TotVAh.actVal`.
  - iec61850bean: a Read of a named variable list with
    `specificationWithResult` FALSE, the ISO 9506 default and what
    `client.ReadDataSet` sends, is answered with a service error (others).
  - iec61850-rust: the URCB's `DatSet` has no logical device
    (`LLN0$dsInterop`).

  These belong in mms-interop's register.

The FC ST writes of the IED client and reporter adapters
(`Mod.stVal`, `SPS1.stVal`) are refused by this server by design:
IEC 61850-7-2 makes status read-only (`server.WithWritableFCs`). The
client test expects that one refusal. The reporter test makes the change
on the server instead, once the adapter has enabled the URCB.

## Not covered yet

- GOOSE and Sampled Values (mms-interop `*-goose-*`, `*-sv-*`, raw
  Ethernet on a Docker bridge).
- The generic MMS layer (`*-mms-server`, `*-mms-client` with
  `fixtures/mms/interop.json`).
- `brcb01`.
