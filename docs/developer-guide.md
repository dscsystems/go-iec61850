# Developer's guide

This guide is for people working **on** go-iec61850 (extending the stack,
fixing protocol bugs, adding services). For using the library, see
[api.md](api.md).

## Architecture

The stack is layered strictly, dependencies pointing downward only:

```
client   server            <- ACSI: object references, FCs, reports, control
   \       /
    v     v
      mms                   <- ISO 9506 values, PDUs, Conn/ServerConn
       |
  internal/osi             <- acse -> presentation -> session -> cotp -> tpkt
       |
     asn1                   <- BER runtime (tag/length/value)

goose  sv  -> ethernet + asn1 + mms(values)   <- process bus, independent of MMS
scl        -> model                            <- configuration -> runtime model
model      -> mms(values)                      <- object model + 7-3 data types
```

Rules:

- `asn1` and `model` have no internal dependencies (model imports only `mms`
  for `Value`).
- Nothing imports `cmd/` or `examples/`.
- `internal/osi/*` is private; the OSI plumbing is an implementation detail
  of `mms`.
- The GOOSE/SV/process-bus side never touches the MMS/OSI stack — it shares
  only the BER runtime and the `mms.Value` model.

### Why these boundaries

MMS needs a full OSI upper stack (TPKT/COTP/Session/Presentation/ACSE); that
complexity is quarantined under `internal/osi` so `mms` reads as a clean
ISO 9506 implementation. GOOSE and SV are layer-2 and share nothing with
MMS except value encoding, so they live in sibling packages over a small
raw-ethernet abstraction.

## The BER runtime (`asn1`)

Everything is TLV. Two encoding styles:

- **Builder** (`asn1.Element`, `Cons`/`Prim`/`IntElem`/…) for control-plane
  PDUs where clarity beats allocations. `RawContent(tag, bytes)` wraps
  pre-encoded content as an element's body; `RawTLV(bytes)` splices a
  complete pre-encoded element in as a child. These let one layer embed
  another's already-encoded PDU without re-parsing (e.g. an ACSE APDU
  inside a presentation single-ASN1-type).
- **Append helpers** (`AppendTag`, `AppendLength`, `AppendInt`, …) for the
  GOOSE/SV hot paths.

Decoding is via `asn1.Decoder`: `ReadTLV`, `Expect(tag)`, `Optional(tag)`,
`Peek`, `More`, `Skip`. It is bounds-checked and depth-limited — decoders
must never panic on hostile input (enforced by fuzzing).

Context tags: `ContextPrimitive(n)`, `ContextConstructed(n)`,
`ApplicationConstructed(n)`. High tag numbers (≥ 31, e.g. MMS file services
[72]) are handled automatically.

## MMS specifics that bite

These were all found by interop testing against a reference C stack and
are the things most likely to trip up a new service:

- **`variableAccessSpecification` tagging is asymmetric.** In `ReadRequest`
  it is `[1] EXPLICIT`; in `WriteRequest` it is untagged (the CHOICE tags
  show through). See `mms/services.go`.
- **`GetVariableAccessAttributes-Response`** puts the type specification at
  `[2] EXPLICIT` (with an optional `address [1]`), not `[1]`.
- **Floating-point type specifications** are a constructed SEQUENCE of two
  INTEGERs (format-width, exponent-width) — unlike float *values*, which are
  the primitive MMS FloatingPoint octet string. See `mms/typespec.go`.
- **`identify` is a primitive `[2] NULL`** (`0x82`), not a constructed
  element.
- **Confirmed responses** carry the invokeID as a universal INTEGER, but
  **ConfirmedErrorPDU and RejectPDU** carry it context-tagged `[0]`.
  `splitInvoke` accepts either.
- **ISO session GIVE-TOKENS and DATA-TRANSFER share SI `0x01`** and cannot
  be told apart by value; the data-phase prefix strips two SPDUs. See
  `internal/osi/session`.

When adding a service, the reliable method is: read the observable wire
behaviour of a reference stack (ASN.1-compiler-generated member tables, where
a stack ships them, show exact tag numbers and implicit/explicit modes),
encode to match, then verify against a live server. Never
copy code — see [licensing](#licensing).

## Reporting engine (`server`)

Report control blocks are **materialised into the model** at `New` time
(`server/rcb.go`): each SCL `ReportControl` becomes a `DataObject` under FC
`RP`/`BR` with the standard attributes, so they read/write through the
normal path. Indexed instances (`Name01…NameNN`) match IEC 61850-6.

The engine (`server/reporting.go`) follows IEC 61850-7-2 clause 17. RCB writes
go through two steps:

- `checkRCBWrite` runs **before** anything is stored. It enforces the
  reservation: the first client to write a block owns it, and anyone else gets
  temporarily-unavailable. It also locks the settings while the block is
  enabled, and validates `DatSet` and `EntryID`.
- `onRCBWrite` applies the effect afterwards: enable/disable, GI, PurgeBuf,
  resync point, and the `ConfRev` increment when `DatSet` changes.

Changes arrive as a `changeSet` from `Update`, from client writes and from
operated controls. The changeSet records, per leaf and FC, the trigger reasons
the write raised: the attribute's dchg or qchg when its value changed, and its
dupd on any write. The attribute's trigger options come from the SCL DA (or
the 7-3 conventions in `model/cdc.go`), and its components inherit them. A
dataset member is included for those reasons ANDed with the block's `TrgOps`.
Events then wait in a `BufTm` window before becoming a `reportEntry`.

Everything about the moment of sending is added at transmission: SqNum
(INT8U for URCB, INT16U for BRCB, wrapping), BufOvfl and segmentation. A BRCB
keeps its entries in a buffer with a `next` index, so re-enabling resumes
where delivery stopped instead of replaying the buffer.

The report wire format is the IEC 61850-8-1 layout: a `variableListName` of
`"RPT"` plus a flat `listOfAccessResult`. The `OptFlds` bit string drives which
fields it holds: RptID, OptFlds, [SqNum], [TimeOfEntry], [DatSet], [BufOvfl],
[EntryID], [ConfRev], [SubSeqNum, MoreSegmentsFollow], the inclusion
bitstring, [data references], values, and [reasons]. A report longer than the
association's `MaxPDU` is split into segments. The decoder
(`client/report.go`) walks the same layout, driven by the OptFlds present in
the report itself.

## Control (`server`)

Writes to `…$CO$…$Oper`/`$SBOw`/`$Cancel` and reads of `…$SBO` are
intercepted in the handler and routed to `server/control.go` and
`server/select.go`. The rules:

- A refusal sends a VMD-specific `LastApplError` InformationReport through
  `SendUnconfirmedFirst`, so it precedes the negative response.
- `status-only` objects refuse all controls.
- SBO models require a select reservation, per connection, lasting the
  object's `sboTimeout`.
- Enhanced models owe a CommandTermination (`termination`). The server sends
  it when the handler accepts, unless the handler called `DeferTermination`.
  In that case the handler's callback sends it, positive or negative. If the
  callback never comes, `operTimeout` sends CommandTermination- with
  time-limit-over.

`mms.ServerConn` holds the unconfirmed PDUs produced while a request is being
handled. The ones that must precede the request's response go out first, then
the response, then the rest. That's how a CommandTermination, or a report a
write provokes, follows the response it belongs to.

## Adding a new MMS service

1. Add the confirmed-service CHOICE tag number as a constant in `mms/pdu.go`
   (client) and/or `server/handler.go` (server).
2. Client: add a method on `mms.Conn` that builds the request element and
   calls `c.call(ctx, element)`, then decodes the response after
   `dec.Expect(ContextConstructed(tag))`.
3. Server: add a `case` in `handler.Handle` returning the response element,
   or an error (`*mms.ServiceError` / `mms.DataAccessError`).
4. Add the high-level wrapper in `client`/`server` that maps object
   references and FCs to MMS names via `ObjectReference.ToMMS`.
5. Add a codec round-trip test and, if it faces the network, a fuzz target.
6. Add an interop assertion (see below).

## Testing

- `go test ./...` runs unit + codec tests with no external dependencies.
- `go test -race ./...` — always run this; the client, server and pub/sub
  paths are concurrent.
- Fuzz targets exist for every network-facing decoder (`asn1`, `mms`,
  `goose`, `sv`). Run one with
  `go test -run=NONE -fuzz=FuzzParse -fuzztime=30s ./goose`.
- **Interop** is the primary correctness oracle. `interop/run.sh` builds
  the reference C stack and runs the two-direction suite (our client ↔ C
  server, C client ↔ our server). The Go interop tests are guarded by env
  vars (`IEC61850_TEST_SERVER`, `IEC61850_TEST_CONTROL_SERVER`,
  `IEC61850_C_CLIENT`) and skipped otherwise, so
  `go test ./...` stays green without a C toolchain. See [interop](../interop).

Golden byte vectors live inline in the `*_test.go` files; layer-2 codecs are
tested with `ethernet.Pipe()` (an in-memory interface) so no NIC is needed.

## Concurrency model

- **Client**: one reader goroutine demultiplexes responses by invokeID to
  per-call channels and routes unconfirmed InformationReports to the report
  handler. Requests are context-cancellable. `Conn` is safe for concurrent
  use.
- **Server**: one goroutine per association. The model is guarded by an
  `sync.RWMutex`; `Update` is the only writer entry point and holds the
  write lock for the whole batch.
- **GOOSE publisher**: a dedicated goroutine owns the retransmission state
  machine; `Publish` hands off via the lock and guarantees monotonic
  stNum/sqNum.
- Callbacks (reports, GOOSE/SV subscribers) run on an internal goroutine and
  **must not block**.

## Platform notes

- Pure Go, no cgo. Cross-compiles to linux/windows/darwin.
- GOOSE/SV raw sockets are Linux-only (`AF_PACKET`). Other platforms return
  an error from `ethernet.Open`; a `pcap` build tag is the intended
  extension point.

## Code style

British English in comments, no em-dashes, concise doc comments on every
exported symbol in complete sentences. Match the surrounding package.
`gofmt` (and ideally `golangci-lint`) before committing.

## Licensing

Apache-2.0. **Never copy or mechanically translate code** from GPL-licensed
IEC 61850 implementations, including the C stack the interop harness builds
and wendy512/iec61850. They may be run as interop peers and read to understand
*observable protocol behaviour* only. IEC standard text must not be reproduced
beyond short factual references. See `PLAN.md` §12.

## Repository map

| Path | Contents |
|------|----------|
| `asn1/` | BER runtime |
| `mms/` | MMS values, PDUs, client `Conn`, server `ServerConn` |
| `internal/osi/` | TPKT, COTP, Session, Presentation, ACSE |
| `model/` | object model, FCs, Quality/Timestamp, control enums |
| `scl/` | SCL parser and model instantiation |
| `client/` | ACSI client |
| `server/` | ACSI server (reporting, control, setting groups, files) |
| `ethernet/` | raw L2 + AF_PACKET + `Pipe` |
| `goose/`, `sv/` | process-bus pub/sub |
| `cmd/` | `ied-client`, `ied-server`, `goose-sniff`, `iedx` |
| `examples/` | runnable snippets |
| `interop/` | bidirectional interop harness |
| `testdata/` | SCL files and fixtures |
