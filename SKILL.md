---
name: go-iec61850
description: >
  Build IEC 61850 apps (MMS client/server, GOOSE/SV monitors, gateways) in
  Go with the github.com/dscsystems/go-iec61850 library. Use when writing code
  that talks to IEDs or substation equipment: reading/writing data,
  reporting, control, GOOSE/SV, SCL, or serving a data model. Pure Go, no
  cgo.
---

# Building apps with go-iec61850

This library is a pure-Go IEC 61850 stack. Prefer the high-level `client`
and `server` packages; drop to `mms` only for services they do not wrap.
Full reference: `docs/api.md`. Internals: `docs/developer-guide.md`.

## Orientation (read this first)

- Address data by **object reference + functional constraint**:
  `model.ObjectReference("LD/LN.DO.DA")` and an `model.FC` (`ST`, `MX`,
  `CO`, `CF`, `SP`, `SG`, `SE`, `DC`, `RP`, `BR`). The same object reads
  differently under different FCs. `MX` = measurands, `ST` = status,
  `CF` = configuration, `CO` = control.
- Values are `*mms.Value` (a tagged union). Build with `mms.New*`, read with
  `.Bool()/.Int64()/.Float64()/.Text()/.Time()`, inspect structures with
  `.Len()/.Index(i)`.
- Every network call takes a `context.Context`. `client.Client` and
  `mms.Conn` are safe for concurrent use.
- The LD in a reference is the **MMS domain** = IED name + LD instance
  (e.g. `simpleIOGenericIO`), discovered via `LogicalDevices`.

## Recipe: monitoring / SCADA client

```go
c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second))
if err != nil { return err }
defer c.Close()

// Discover.
lds, _ := c.LogicalDevices(ctx)
m, _   := c.RetrieveModel(ctx)   // full typed tree for a UI

// Poll a value.
v, err := c.Read(ctx, "LD0/MMXU1.TotW.mag.f", model.MX)

// Or subscribe to reports (push, not poll) — the right choice for SCADA.
rcb, _ := c.GetRCB(ctx, "LD0/LLN0.RP.EventsRCB01")
rcb.TrgOps = model.TrgDataChange | model.TrgQualityChange | model.TrgGI
rcb.OptFlds = model.OptFldsDefault | model.OptReasonCode
sub, _ := c.EnableReporting(ctx, rcb, func(r *client.Report) {
    for _, e := range r.Entries { handle(e.Ref, e.Value, e.Reason) }
})
defer sub.Disable(context.Background())
c.TriggerGI(ctx, rcb)            // immediate full snapshot
```

## Recipe: operating a control point

```go
co, _ := c.ControlFor(ctx, "LD0/CSWI1.Pos")   // control model auto-detected
err := co.Operate(ctx, mms.NewBool(true),
    client.WithOriginator(model.OrCatStationControl, "operator-id"),
    client.WithInterlockCheck(true))
var ce *client.ControlError
if errors.As(err, &ce) { /* ce.Stage, ce.AddCause */ }
```
`Operate` performs select-then-operate and waits appropriately for the
detected model — do not hand-code the sequence.

## Recipe: server / simulator / gateway

```go
m, _ := scl.LoadModel("device.cid", scl.ForIED("IED1"))
srv := server.New(m, server.WithIdentity(server.Identity{Vendor:"X", Model:"Y", Revision:"1"}))

srv.OnControl("IED1LD0/CSWI1.Pos", func(cc *server.ControlCtx) model.AddCause {
    if blocked() { return model.AddCauseBlockedByInterlocking }
    return model.AddCauseNone     // accept; stVal updates automatically
})

go srv.ListenAndServe(":102")
defer srv.Close()

// Feed live data from the process side; this also drives reports/GOOSE.
srv.Update(func(tx *server.Tx) {
    tx.SetFloat32("IED1LD0/MMXU1.TotW.mag.f", power)
    tx.SetQuality("IED1LD0/MMXU1.TotW.q", model.MX, model.QualityGood)
    tx.SetTimestampNow("IED1LD0/MMXU1.TotW.t", model.MX)
})
```
Reporting, SBO select, CommandTermination and setting groups are handled by
the server once the model is loaded — you only supply data via `Update` and
policy via `OnControl`/`OnWrite`.

## Recipe: GOOSE / SV monitor (Linux, needs CAP_NET_RAW)

```go
eth, err := ethernet.Open("eth0", ethernet.EtherTypeGOOSE)
if err != nil { return err }          // errors on non-Linux
defer eth.Close()

sub := goose.NewSubscriber(eth)
stop, _ := sub.Subscribe(goose.Filter{}, func(m *goose.Message) {
    // m.StNum, m.SqNum, m.Values, m.Anomalies for IDS-style checks
})
defer stop()
```
For SV use `sv.NewSubscriber(eth)` + `SubscribeLE` (9-2LE, zero-alloc).
**One `Subscribe` per interface** — multiple subscribers race for frames;
demultiplex in the callback if you need several filters.

## Critical rules (get these wrong and it silently misbehaves)

1. **Pick the right FC.** Reading `MMXU1.TotW.mag.f` under `ST` returns
   nothing; measurands are `MX`, config is `CF`, controllable status is
   `ST`. If a read returns an access error, the FC is usually wrong.
2. **Report and subscriber callbacks must not block.** They run on an
   internal goroutine; a blocking callback stalls the whole connection.
   Hand work to your own goroutine/channel.
3. **`Update` is the only way to change server values**, and it is atomic.
   Never mutate the model tree directly; changes made outside `Update` are
   not reported and race with readers.
4. **GOOSE/SV are Linux-only** via AF_PACKET. Guard `ethernet.Open` errors
   and document the requirement. Use `ethernet.Pipe()` for tests.
5. **Buffered reports (BRCB)** need `rcb.ResyncEntryID` (from a prior
   `Report.EntryID`) set before `EnableReporting` to resume gap-free.
6. **Values are pointers; `Clone()` before mutating** one you did not just
   create, and before sharing across goroutines that write.
7. **Dataset/RCB/log references use `.` in the API** (`LD/LN.Measurements`,
   `LD/LN.RP.rcb01`), not MMS `$` notation — the library converts.

## Testing your app

- Unit-test against an in-process server: `server.New(model)` +
  `net.Listen("tcp","127.0.0.1:0")` + `go srv.Serve(ln)`, then dial with the
  client. No external process needed. See `server/server_test.go`.
- Build a model programmatically (construct `model.Model`) or from an SCL
  file (`testdata/simpleIO_direct_control.cid` is a ready fixture).
- GOOSE/SV: `a, b := ethernet.Pipe()` gives two connected in-memory
  interfaces — publish on one, subscribe on the other.
- Always `go test -race ./...`.

## Verifying a new app end to end

For a client app, run the bundled example server (it simulates live data
and sends reports when configured) and point your app at it:
```sh
go run ./cmd/ied-server -scl testdata/simpleIO_direct_control.cid -addr :10102 &
# exercise every server feature with the built-in self-test:
go run ./cmd/ied-client -addr 127.0.0.1:10102 test
```
Or interop against the reference C stack via `bash interop/run.sh`.

## What exists vs. what does not

Implemented: browse, read/write, datasets, reporting (URCB + buffered BRCB
with resync), control (all four models), setting groups, file services,
log queries, GOOSE/SV pub-sub, SCL parsing, TLS.
Not yet: server-side journal storage, R-GOOSE/R-SV, 62351-6 message
signing. If a task needs one of these, say so rather than faking it.

## Where to look

- `docs/api.md` — every public call with an example.
- `examples/` — runnable programs (`read`, `server`, `report-monitor`,
  `goose-subscribe`, `control`).
- `cmd/` — full apps to copy patterns from (`ied-client`, `ied-server`,
  `iedx` TUI, `goose-sniff`).
- `docs/developer-guide.md` — only if extending the library itself.
