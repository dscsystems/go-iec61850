# IEC 61850 Edition 2.1 conformance

This records what this library implements of IEC 61850 **Edition 2** plus
**Amendment 1** — "Edition 2.1" — and what it does not, part by part. It is
written to be checkable: every "implemented" line below is covered by a
test, and the gaps are named rather than left to be discovered in the field.

## What Edition 2.1 is

Ed 2.1 is not a new data model. It is Edition 2 (2010–2013) plus Amendment 1
to each of parts 6, 7-2, 7-3, 7-4, 8-1 and 9-2, and it is overwhelmingly
the accumulated TISSUE fixes plus the SCL schema deltas. Its code
components are:

| Part | Code component | Ed 2.1 namespace |
|---|---|---|
| 6 (SCL) | IEC 61850-6:2009+AMD1:2018 CSV | `2007B4` |
| 7-2 (ACSI) | IEC 61850-7-2:2010+AMD1:2020 CSV | `2007B5` |
| 7-3 (data) | IEC 61850-7-3:2010+AMD1 | — |
| 7-4 (nodes) | IEC 61850-7-4:2010+AMD1 | — |
| 8-1 (SCSM) | IEC 61850-8-1:2011+AMD1 | — |
| 9-2 (SV) | IEC 61850-9-2:2011+AMD1 | — |

`scl.Edition` reports what a file declares, and `scl.Edition.Known` says
whether it is one of the published code components. Loading is permissive:
an unknown version or a vendor namespace is a diagnostic, not an error,
because elements are matched by local name.

Note that **Edition 2.2** (`2007C5`, AMD2:2024) is a different thing again,
and is not claimed here. It adds UUID identification and client-side control
binding to the SCL.

## How a file that is not fully understood loads

Permissiveness is a deliberate choice with a cost, so it is worth being
precise about it.

A construct the library does not recognise is recorded as a
`model.Diagnostic` on `model.Model.Diagnostics` and the load continues.
This is right for a vendor extension or a construct only the data model
does not need, and wrong for a genuine schema change that would change the
meaning of a value. The compromise:

```go
m, err := scl.LoadModel("device.cid", scl.Strict(true))   // fail on any diagnostic
for _, d := range m.Diagnostics {                         // or inspect them
    log.Printf("%s", d)
}
s, _ := scl.ParseFile("device.cid")
for name, paths := range s.Dropped() {                    // elements not decoded
    log.Printf("%s at %v", name, paths)
}
```

`Dropped` reports elements the *parser* does not decode, with the paths
they occur at. The path matters: dropping an element drops its subtree, so
`SubNetworks` is a curiosity while `/SCL/Communication/SubNetwork` means
every IED's GOOSE addressing is missing.

## IEC 61850-6 — SCL

### Implemented

- The element and attribute set of `2007B4` that affects the runtime model:
  IEDs, access points, servers, logical devices and nodes, data type
  templates, datasets, and the report, GOOSE, sampled-value, log and
  setting-group control blocks with their initial values.
- `Substation`, `Line`, `Process`, `Header/History`, `KDC`,
  `GOOSESecurity`/`SMVSecurity`, `ServerAt`, `Server/Authentication` and
  `Association`, `PhysConn`, `AccessControl`, `LN/Log`, `ProtNs` — decoded
  so they are known-and-ignored rather than reported as unknown.
- The full `Services` capability set, of which `ConfReportControl@maxBuf`
  changes the model (it becomes the report-buffer depth).
- Array addressing: `SDO@count` produces `phsA(1)`..`phsA(n)`, and
  `DOI@ix`, `SDI@ix`, `DAI@ix`, `DAI@sAddr` and `FCDA@ix` select elements
  of them. `FCDA` members spelled `AnIn3.phsA(2).mag.f` resolve and are
  readable and reportable.
- `Val@sGroup` per setting group, exposed as `model.SettingGroups`, with
  `SettingControl@actSG` selecting the group the objects serve.
- `SmvOpts`, `smpMod`, `GSEControl@type`, `Protocol` (R-GOOSE/R-SV),
  `FixedOffs`, `RptEnabled/ClientLN`, `dbprefix`, `bufDepth`, the log
  control block's logical-node attributes, `resvTms`.
- `LNodeType` identified by `(id, lnClass)`, so a document reusing an id
  across node classes resolves each to its own template.
- `OptFields@bufOvfl` defaults to true, as the schema says.
- The whole `tPredefinedBasicTypeEnum`, including `PhyComAddr`,
  `SvOptFlds` and `LogOptFlds`, which previously failed the load outright.

### Not implemented, and reported

| Construct | Why | Diagnostic |
|---|---|---|
| R-GOOSE, R-SV | Need the IEC 61850-90-5 session and security profile | yes |
| `RptEnabled/ClientLN` reservations | Pre-reserved instances are not created | yes |
| `Substation` topology | Decoded, not instantiated into the model | no (known) |
| `Inputs`/`ExtRef` | Decoded, not resolved to their publisher | no (known) |
| `Services` other than `maxBuf` | Decoded, not derived into the model | partly |
| `Services@nameLength` | Not enforced on references or item IDs | yes |
| `Subscription supervision` | Not implemented | yes |
| Private / foreign-namespace elements | By design | no (known) |

## IEC 61850-7-2 — ACSI

### Implemented

- Read, write, browse (`getNameList`), `GetVariableAccessAttributes`.
- Reporting: URCB and BRCB with reservation, general interrogation, data
  and quality change, integrity, buffer time, the report buffer, purge,
  resync on `EntryID`, and `BufOvfl`. `EntryID` is unique within the
  server, as 7-2 requires, and does not collide across a restart.
- `BRCB.Owner`, kept in step with the block's holder.
- Control: all four control models, select-before-operate at both security
  levels, `CommandTermination` with positive and negative outcome, and
  `LastApplError`.
- The AddCause table 0..29, including `test-not-allowed` and
  `blocked-by-test`, which 7-2 names and an earlier version of this library
  did not.
- Setting groups: `SGCB` with edit and confirm, and per-group values. A
  device that declares its groups in SCL gets them without configuration.
- Log, file and dataset services (see below).
- Control-block objects: `GoCB`, `GsCB`, `MSVCB`, `USVCB`, `LCB` and `SGCB`
  are all materialised and browsable.

### Not implemented

- **R-GOOSE and R-SV** (with 8-1/9-2). These are the routable profiles of
  IEC 61850-90-5 and require a session layer and IEC 62351 key management
  that this library does not have. An SCL file that asks for them loads,
  and the control blocks are reported as plain GOOSE and SV.
- **Server-side journal storage.** `mms` implements the client side of log
  query (`ReadJournalByTime`, `ReadJournalAfter`); the server has no
  storage, so a server cannot answer a log query. The `LCB` object exists
  and is browsable, but it fronts nothing.
- **The ACSI directory services** (`GetDirectory`, `DirectoryObject`,
  `GetDataObjectDefinition`) as services. `client.Browse` is a filter over
  `getNameList`, which is a faithful derivation of the class of each object
  from its functional constraint, but it is not the standard's service.

## IEC 61850-7-3 and 7-4 — data model

### Implemented

- The common data classes listed in `model/cdc.go`: the Ed 1 and Ed 2
  status, measurand, controllable, settings and description classes, plus
  `SEC` and `ORG`.
- The substitution group (FC SV) on every class with a substitutable
  value, as 7-2 requires.
- `Quality` bit positions, `Dbpos`, trigger options and reason codes per
  7-3.
- An unknown class no longer panics: `NewDataObjectOr` returns a
  diagnostic and an empty object, and the SCL loader takes the attributes
  from the file.

### Not implemented

The Edition 2.1 classes whose attribute sets are not implemented here:
`HST`, `SEQ`, `HMV`, `HWYE`, `HDEL`, `BAC`, `TSG`, `CUG`, `VSG`, `CSG`,
`CURVE`, `ISC`, `CSD`, `CST`, `BTS`, `UTS`, `LTS`, `GTS`, `MTS`, `NTS`,
`STS`, `CTS`, `OTS`, `VSD`, `ORS`, `TCS`.

This is a deliberate limit, not an oversight. A class is added to
`cdcTable` only with its attribute list from 7-3, because a plausible but
wrong attribute table is worse than none: it produces a model that lies
about the device rather than one that admits it does not know. A document
using one of these classes **loads** — the SCL supplies the attributes, and
the class is reported as unknown to this library.

## IEC 61850-8-1 — GOOSE and the SCSM

### Implemented

- `goosePdu` encoding and decoding, including the optional `goID` and the
  trailing fields of the Edition 2 message.
- The retransmission state machine, with `Publish` for a state change and
  `Refresh` for re-advertising the same state. `stNum` starts at 1 and
  skips 0, which 8-1 reserves.
- `test` and `ndsCom` are settable and reach the wire.
- The time quality of the message stamp is settable, so a publisher whose
  clock has lost synchronisation can say so.
- `RetransFromSCL` builds the retransmission schedule from a control
  block's `MinTime` and `MaxTime`, and `NewPublisherFromModel` builds a
  publisher from a model. This is how 100 ms GOOSE is configured.
- Report `OptFlds` bit assignments and the report field order.
- Presentation context negotiation, by identifier rather than by position.

### Not implemented

- **GOOSE TLV encoding** (`allData` as a tagged list). Some protection
  functions use it; the data set is encoded as a flat `SEQUENCE OF Data`.
- **62351-6 message signing.** A trailing security field is parsed past and
  discarded; nothing is ever signed or verified.
- **IPv6.** The COTP/TPKT/transport layer is not address-family specific,
  but nothing has been tested on IPv6 and it is not claimed.

## IEC 61850-9-2 — Sampled Values

### Implemented

- `savPdu` and ASDU encoding and decoding, including the Edition 2
  `smpMod [8]` field, which says whether `SmpRate` counts samples per
  period, per second, or seconds per sample.
- The optional ASDU fields (`smpRate`, `refrTm`, `datSet`, `smpMod`) are
  emitted only when the publisher's configuration asks for them, and
  `SmvOpts` from the SCL becomes the `SmvOptFlds` bit string.
- The 9-2LE `PhsMeas1` dataset, with `SetQuality` alongside `Quality`.
- Multi-ASDU APDUs.

### Not implemented

- **R-SV**, for the reasons given under 7-2.
- **9-2 (non-LE) dataset shapes.** Only the 9-2LE 8-channel layout is
  decodable; a wider channel set is carried as raw bytes.
- **Sampled value control blocks on the server** exist as browsable
  objects with their configuration, but the server does not publish SV.

## Verification

- `go test -race ./...` covers every "implemented" claim in this document.
- `testdata/ed21_diverse.cid` is a synthetic `2007B4` CID exercising the
  Edition 2.1 constructs: `PhyComAddr`, `SvOptFlds`/`LogOptFlds`, an
  unknown basic type and an unknown functional constraint, an `SDO@count`
  array with `ix` and `sAddr` selection, per-group `Val`s, `SmvOpts`,
  `smpMod`, a GSSE and an R-GOOSE control block, and the full `Services`
  set. `scl/edition_test.go` is its conformance test.
- `interop/run.sh` runs both directions against
  [libiec61850](https://github.com/mz-automation/libiec61850) v1.6, which
  implements Edition 2 and the R-GOOSE/R-SV profiles. The coverage table is
  in `interop/README.md`.
- `goose/ed21_test.go` and `sv/ed21_test.go` cover the 8-1 and 9-2
  conformance claims, including the 9-2LE quality-word orientation.

## A note on the 9-2LE quality word

The 32-bit quality word of a 9-2LE sample holds 13 bits of
IEC 61850-7-3 `Quality` and 19 reserved. Reading them from the wrong end
produces plausible nonsense rather than an error, so the orientation is
pinned by the masks the 9-2LE conformance test procedures name: validity
`Invalid` is `0x0001`, test is `0x0800`, and the `derived` bit that 9-2LE
adds is `0x2000` — which is bit 13, outside the 13. `sv/le.go` documents
this and `sv/ed21_test.go` asserts it.
