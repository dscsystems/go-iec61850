# API reference

This is a practical, example-driven reference for the public API. Every
symbol here also carries godoc; run `go doc github.com/dscsystems/go-iec61850/<pkg>`
for the authoritative signatures.

Contents:

- [Core concepts](#core-concepts) — object references, functional constraints, values
- [`client`](#client) — the ACSI client
- [`server`](#server) — the ACSI server
- [`model`](#model) — the object model and common data types
- [`mms`](#mms) — the low-level MMS layer
- [`scl`](#scl) — SCL parsing
- [`goose`](#goose) — GOOSE publish/subscribe
- [`sv`](#sv) — Sampled Values publish/subscribe
- [`ethernet`](#ethernet) — raw layer-2 access

---

## Core concepts

### Object references

An `model.ObjectReference` is the string `"LD/LN.DO[.DA...]"`, where `LD` is
the full MMS domain (IED name + logical-device instance), for example
`"ied1LD0/GGIO1.AnIn1.mag.f"`.

```go
ref := model.ObjectReference("ied1LD0/GGIO1.AnIn1.mag.f")
ref.LD()      // "ied1LD0"
ref.LN()      // "GGIO1"
ref.Path()    // ["GGIO1","AnIn1","mag","f"]
ref.Parent()  // "ied1LD0/GGIO1.AnIn1.mag"
ref.Child("q")
```

### Functional constraints

Data attributes are addressed by reference **and** functional constraint
(`model.FC`): the same object exposes different views under different FCs.
Common values: `ST` (status), `MX` (measurands), `CO` (control), `SP`/`SG`/`SE`
(set points / setting groups), `CF` (configuration), `DC` (description),
`RP`/`BR` (unbuffered / buffered report control). `model.ALL` is a wildcard
for lookups.

### Values (`mms.Value`)

`mms.Value` is a tagged union covering every MMS data type. Construct with
the `New*` functions; read with the typed accessors.

```go
mms.NewBool(true)
mms.NewInt32(-5)
mms.NewUint32(230)
mms.NewFloat32(230.4)
mms.NewVisibleString("text")
mms.NewOctetString([]byte{1,2,3})
mms.NewUTCTime(time.Now(), mms.TimeAccuracy(10))
mms.NewStructure(a, b, c)   // members
mms.NewArray(a, b, c)       // elements

v.Type()      // mms.Type
v.Bool(); v.Int64(); v.Int32(); v.Uint64(); v.Float64(); v.Float32()
v.Text()      // string content of string types
v.Bytes()     // raw octets (octet strings, bit strings, time types)
v.Bit(i); v.BitLen()          // bit strings
v.Len(); v.Index(i); v.Children()  // arrays and structures
v.Time()      // UTCTime / BinaryTime -> time.Time
v.Clone(); v.Equal(other); v.String()
```

Quality and timestamp helpers live in `model`:

```go
q := model.QualityGood.WithValidity(model.ValidityQuestionable) | model.QualityOldData
q.Value()                     // -> *mms.Value (13-bit bit string)
model.QualityFromValue(v)     // *mms.Value -> model.Quality
```

---

## client

High-level ACSI client. Safe for concurrent use; every call takes a
`context.Context`.

### Connecting

```go
c, err := client.Dial(ctx, "192.168.10.5:102",
    client.WithTimeout(5*time.Second),
    client.WithPassword("secret"),   // ACSE authentication
    client.WithTLS(tlsCfg),          // IEC 62351-3
    client.WithLogger(slog.Default()),
)
defer c.Close()
```

### Browsing and reading

```go
lds, _ := c.LogicalDevices(ctx)                 // []string of MMS domains
lns, _ := c.LogicalNodes(ctx, "ied1LD0")        // []string of LN names
m,   _ := c.RetrieveModel(ctx)                  // *model.Model, full typed tree

v, _ := c.Read(ctx, "ied1LD0/GGIO1.AnIn1.mag.f", model.MX)
vs, _ := c.ReadValues(ctx, model.MX,            // batch read, one LD
    "ied1LD0/GGIO1.AnIn1.mag.f",
    "ied1LD0/GGIO1.AnIn2.mag.f")
```

### Writing

```go
err := c.Write(ctx, "ied1LD0/GGIO1.SPCSO1.ctlModel", model.CF, mms.NewInt32(1))
```

### Datasets

```go
ds, _ := c.ReadDataSet(ctx, "ied1LD0/LLN0.Measurements")
for _, m := range ds.Members {
    fmt.Println(m.Ref, m.FC, m.Value)
}

_ = c.CreateDataSet(ctx, "ied1LD0/LLN0.MyDS", []client.DataSetEntry{
    {Ref: "ied1LD0/GGIO1.AnIn1", FC: model.MX},
})
_ = c.DeleteDataSet(ctx, "ied1LD0/LLN0.MyDS")
```

### Reporting

```go
rcb, _ := c.GetRCB(ctx, "ied1LD0/LLN0.RP.EventsRCB01")   // BR works too
rcb.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptDataSetName | model.OptConfRev
rcb.TrgOps  = model.TrgDataChange | model.TrgQualityChange | model.TrgGI
rcb.IntgPd  = 60 * time.Second

sub, _ := c.EnableReporting(ctx, rcb, func(r *client.Report) {
    for _, e := range r.Entries {           // decoded per inclusion bitstring
        fmt.Println(e.Ref, e.Reason, e.Value)
    }
})
defer sub.Disable(context.Background())

_ = c.TriggerGI(ctx, rcb)                    // general interrogation
```

Buffered reports (BRCB) resume gap-free after a disconnect: set
`rcb.ResyncEntryID = lastSeen` (from `Report.EntryID`) before
`EnableReporting`.

The report callback runs on the connection's reader goroutine and **must
not block** — hand heavy work to your own goroutine.

### Control

The control model is read from `ctlModel`; `Operate` performs the correct
select/operate sequence automatically.

```go
co, _ := c.ControlFor(ctx, "ied1LD0/GGIO1.SPCSO1")
fmt.Println(co.Model())                       // e.g. sbo-with-enhanced-security

err := co.Operate(ctx, mms.NewBool(true),
    client.WithOriginator(model.OrCatStationControl, "scada-1"),
    client.WithInterlockCheck(true),
    client.WithTest(false))

var ce *client.ControlError
if errors.As(err, &ce) {
    fmt.Println(ce.Stage, ce.AddCause)        // "operate", "blocked-by-interlocking"
}
```

Lower-level steps are also exposed: `Select`, `SelectWithValue`, `Cancel`,
and `WithModel(...)` to override the model.

### Setting groups

```go
sg, _ := c.SettingGroups(ctx, "DEMOPROT/LLN0.SP.SGCB")
fmt.Println(sg.NumOfSG, sg.ActSG, sg.EditSG)

_ = sg.SelectActiveSG(ctx, 2)                 // activate group 2
_ = sg.SelectEditSG(ctx, 1)                   // edit group 1
_ = sg.SetEditValue(ctx, "DEMOPROT/PTOC1.OpDlTmms.setVal", mms.NewInt32(4200))
_ = sg.ConfirmEdit(ctx)                       // commit
```

### Files

```go
entries, _ := c.FileDirectory(ctx, "")        // filestore root
rc, _ := c.OpenFile(ctx, "COMTRADE/rec001.cfg")  // io.ReadCloser, streamed
defer rc.Close()
data, _ := c.ReadFile(ctx, "COMTRADE/rec001.dat")
```

### Logs

```go
entries, _ := c.QueryLogByTime(ctx, "ied1LD0/LLN0.LG.EventLog",
    time.Now().Add(-time.Hour), time.Now())
for _, e := range entries {
    fmt.Println(e.EntryID, e.OccurrenceTime, e.Variables)
}
more, _ := c.QueryLogAfter(ctx, "ied1LD0/LLN0.LG.EventLog", t, lastEntryID)
```

### Escape hatch

`c.MMS()` returns the underlying `*mms.Conn` for services not wrapped by
the ACSI layer (`Identify`, raw `GetNameList`, etc.).

---

## server

High-level ACSI server driven by a `model.Model`.

```go
m, _ := scl.LoadModel("substation.cid", scl.ForIED("IED1"))

srv := server.New(m,
    server.WithIdentity(server.Identity{Vendor: "ACME", Model: "GW", Revision: "1.0"}),
    server.WithTLS(tlsCfg),
    server.WithFileStore(os.DirFS("/var/comtrade")),
    server.WithSettingGroups(4),
    server.WithLogger(slog.Default()),
)
go srv.ListenAndServe(":102")
defer srv.Close()
```

### Pushing values (process side)

`Update` applies a batch atomically with respect to client reads and drives
any reports whose dataset includes the changed attributes.

```go
srv.Update(func(tx *server.Tx) {
    tx.SetFloat32("IED1LD0/GGIO1.AnIn1.mag.f", 230.4)
    tx.SetQuality ("IED1LD0/GGIO1.AnIn1.q", model.MX, model.QualityGood)
    tx.SetTimestampNow("IED1LD0/GGIO1.AnIn1.t", model.MX)
    tx.SetBool("IED1LD0/GGIO1.Ind1.stVal", true)
})

v := srv.Read("IED1LD0/GGIO1.AnIn1.mag.f", model.MX)   // server-local snapshot
```

### Write access control

```go
srv.OnWrite(func(da *model.DataAttribute, v *mms.Value) error {
    if da.Name == "ctlModel" {
        return server.ErrAccessDenied     // -> MMS object-access-denied
    }
    return nil                            // allow (value is then applied)
})
```

### Control handlers

```go
srv.OnControl("IED1LD0/GGIO1.SPCSO1", func(cc *server.ControlCtx) model.AddCause {
    if cc.Select { /* select phase */ }
    log.Printf("operate %s = %s by %s (test=%v)", cc.Ref, cc.Value, cc.OrIdent, cc.Test)
    if interlocked() {
        return model.AddCauseBlockedByInterlocking
    }
    return model.AddCauseNone             // accept; stVal is set automatically
})
```

Reporting (URCB/BRCB, materialised from the model), SBO select reservation,
and CommandTermination for enhanced control models are handled internally.

---

## model

The object model plus the IEC 61850-7-3 common data types.

- `Model` → `LogicalDevice` → `LogicalNode` → `DataObject` → `DataAttribute`.
- Lookups: `m.Device(name)`, `ld.Node(name)`, `ln.Object(name)`,
  `m.Attribute(ref, fc)`, `m.Lookup(ref, fc)`.
- `FC`, `ParseFC`, `ObjectReference`, `ToMMS`/`FromMMS`.
- `Quality`, `Validity`, `Dbpos`, `TrgOps`, `OptFlds`, `ReasonCode` — each
  with `.Value()` (to `*mms.Value`) and a `…FromValue` decoder.
- `CtlModel`, `OrCat`, `AddCause` for control.

```go
da := m.Attribute("IED1LD0/GGIO1.AnIn1.mag.f", model.MX)
fmt.Println(da.FC, da.Kind, da.Value)
```

---

## mms

The low-level layer. Most applications only touch `mms.Value` (above) and
`mms.Conn` via `client`. Direct use is for tooling and unusual services.

```go
mc, _ := mms.Dial(ctx, "host:102", mms.Options{Password: "p"})
vendor, modelName, rev, _ := mc.Identify(ctx)
names, _ := mc.GetNameList(ctx, mms.ClassDomain, "")
vals, _ := mc.Read(ctx, "domain", "LN$MX$AnIn1$mag$f")
```

Errors surface as typed values usable with `errors.As`: `*mms.ServiceError`
(confirmed error / reject) and `mms.DataAccessError` (per-item, also
returned inline inside read results as a value — check `v.AccessError()`).

The server transport primitive is `mms.AcceptConn(net.Conn) (*ServerConn, error)`
with a `Handler`; `server` builds on it.

---

## scl

```go
doc, _ := scl.ParseFile("substation.scd")       // full typed SCL document
m,   _ := scl.LoadModel("ied.cid",              // instantiate one IED
    scl.ForIED("IED1"), scl.WithAccessPoint("S1"))
```

`LoadModel`/`BuildModel` expand the DataTypeTemplates into the runtime
model, apply DOI/DAI initial values, and resolve datasets and control
blocks (including GSE/SMV MAC/APPID/VLAN from the Communication section).

---

## goose

Layer-2 GOOSE over an `ethernet.Interface`.

```go
eth, _ := ethernet.Open("eth0", ethernet.EtherTypeGOOSE)   // Linux, CAP_NET_RAW

// Publisher: the retransmission state machine runs in the background.
pub, _ := goose.NewPublisher(eth, goose.PublisherConfig{
    DstMAC:  [6]byte{0x01,0x0C,0xCD,0x01,0x00,0x01},
    AppID:   0x1000,
    GoCbRef: "IED1LD0/LLN0$GO$gcb01",
    DatSet:  "IED1LD0/LLN0$Events",
    GoID:    "events",
    ConfRev: 1,
    VLAN:    &ethernet.VLANTag{Priority: 4},
    Retrans: goose.DefaultRetrans,   // 4ms..1s, then stable
})
pub.Publish([]*mms.Value{mms.NewBool(true), model.QualityGood.Value()})  // stNum++
defer pub.Close()

// Subscriber.
sub := goose.NewSubscriber(eth)
stop, _ := sub.Subscribe(goose.Filter{AppID: 0x1000}, func(m *goose.Message) {
    // m.StNum, m.SqNum, m.Values, m.Anomalies (StNumRegressed, SqNumGap, Stale)
})
defer stop()
```

Use `ethernet.Pipe()` for an in-memory interface in tests.

---

## sv

Sampled Values, generic and the 9-2LE fast path.

```go
// 9-2LE publisher: 80 samples/cycle at 50 Hz = 4000 samples/s.
pub, _ := sv.NewLEPublisher(eth, sv.LEConfig{
    AppID: 0x4000, SvID: "MU01", ConfRev: 1,
    DstMAC: sv.DefaultMAC(1), SamplesPerCycle: 80, NominalHz: 50,
})
pub.Run(ctx, func(smpCnt uint16, out *sv.LESample) {
    out.I[0] = current; out.V[0] = voltage
})

// Subscriber (zero-alloc 9-2LE decode; the sample is reused, copy to retain).
sub := sv.NewSubscriber(eth)
stop, _ := sub.SubscribeLE(sv.Filter{AppID: 0x4000}, func(s *sv.LESample) {
    _ = s.SmpCnt; _ = s.I; _ = s.V; _ = s.Q
})
defer stop()
```

`Subscribe` (not `SubscribeLE`) delivers generic `*sv.ASDU` with the raw
`Sample` payload for non-9-2LE datasets.

---

## ethernet

```go
eth, err := ethernet.Open("eth0", ethernet.EtherTypeGOOSE, ethernet.EtherTypeSV)
```

Linux AF_PACKET backend; requires `CAP_NET_RAW` (or root). On non-Linux
platforms `Open` returns an error — build with the `pcap` tag for a capture
backend, or use `ethernet.Pipe()` for tests and simulation.

---

## Runnable examples

See [`examples/`](../examples): `read`, `server`, `report-monitor`,
`goose-subscribe`, `control`. Each is a `go run`-able program, for example:

```sh
go run ./examples/read 127.0.0.1:10102
```
