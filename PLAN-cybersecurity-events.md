# Plan — cyber-security awareness for go-iec61850

- **Date:** 2026-11-21
- **Base:** `f642d40` (main)
- **Origin:** adapted from the go-iecp5 plan of the same date. The event model,
  delivery, MAC lookup and phasing carry over. The findings, the catalogue and
  the hook points are rewritten for IEC 61850 (MMS over the OSI stack, GOOSE,
  SV, R-GOOSE/R-SV, GDOI, IEC 62351-3/-4).
- **Scope:** `server`, `client`, `mms`, `internal/osi/*`, `goose`, `sv`,
  `ethernet`, `rsession`, `gdoi`, `iec62351` (TLS, `e2e`, `aprofile`,
  `ossltls`), `cmd/ied-server`, `cmd/ied-client`, `docs`, `examples`
- **Status:** P0 decisions taken (§12). P1 done on branch `cyber-events-p1`
  (accept/read retry, explicit TLS handshake, frame and idle timeouts).
  P2 done on branch `cyber-events-p2`: `secevent` core (Event, Kinds,
  Dispatcher, sinks, JSON, Emitter, Reporter/Report, Policy skeleton,
  Stats) and the MMS server's connection and association events. Every
  Kind's `Std62351` is still its `x-go-iec61850.` extension identifier;
  mapping the standard IEC 62351-14 identifiers needs the published text.

## 0. Goals and non-goals

### Goals

1. **Peer identity in the API.** Every TCP endpoint (MMS server association,
   MMS client) reports its peer's MAC address together with IP, port, TLS
   identity, ACSE identity (AP-title, AE-qualifier, A-profile certificate, E2E
   peer) and connect time. Every layer-2 subscriber (GOOSE, SV) reports the
   source MAC and VLAN of each stream. The library notices when the MAC behind
   a known IP, or behind a known GOOSE/SV stream, changes.
2. **A cyber-event channel.** One structured callback (a "sink") receives
   typed security events from every layer: transport, TLS, OSI upper layers,
   ACSE and authentication, MMS, ACSI services (data access, control, setting
   groups, control blocks, files, journals), GOOSE, SV, R-GOOSE/R-SV and GDOI.
   It replaces nothing: the per-package hooks that exist today
   (`iec62351.Options.OnEvent`, `e2e.*Config.OnEvent`, `rsession.Config.OnReject`,
   `gdoi.ServerConfig.OnRegister/OnReject`, `server.OnConnection`) keep working
   and are bridged into the sink.
3. **Detection of the requested event classes.** Each one maps to concrete
   code locations (catalogue in §4):
   unexpected connections · rejected certificates · failed authentication ·
   invalid object references, domains and datasets · oversized requests ·
   unrecognised services · rejected controls · invalid PDUs at every OSI layer
   · GOOSE/SV sequence errors, replay and injection · mode, simulation,
   setting-group, configuration, journal and file operations · MAC change for
   an IP or a multicast stream · unsolicited responses, reports and command
   terminations · request flooding · DoS and connection or resource exhaustion.
4. **Optional hardening hooks.** Allowlists, limits and service policies the
   application can turn on. Every enforcement is opt-in. The default stays
   "observe and report".
5. **Zero cost and zero behaviour change when unused.** With no sink and no
   policy, wire behaviour and performance stay as they are today. The only
   exceptions are the robustness fixes in §7, which are called out
   explicitly.
6. **IEC 62351-14 alignment.** Kinds carry, where one exists, the matching
   IEC 62351-14 event identifier, so a consumer can produce the standard's
   log records without its own mapping table (§3.7).

### Non-goals

- New security protocols. IEC 62351-3/-4/-6/-9 are already implemented here;
  this plan only *reports* what they decide.
- Kernel-level DoS mitigation (SYN floods, half-open TCP, multicast storms
  on the switch). User space cannot see these. Document the limitation and
  recommend SYN cookies, a firewall, and switch storm control / VLAN
  isolation for the process bus.
- Being an IDS for the whole substation. A GOOSE/SV subscriber sees only the
  streams delivered to its interface, and an MMS endpoint only its own
  associations. Correlation across devices belongs to the consumer (SIEM,
  IEC 62351-7 NSM agent).
- Authenticating GOOSE/SV on layer 2 (IEC 62351-6 L2 signatures). Detection
  here is behavioural; authenticated multicast is R-GOOSE/R-SV (`rsession`).

---

## 1. Findings from the current code that shape the design

| # | Location | Observation | Consequence for the plan |
|---|----------|-------------|--------------------------|
| F1 | `server/server.go:367-371` | `ln.Accept()` error **returns from `Serve`**. One `EMFILE`/`ENFILE` (fd exhaustion) or transient error stops the IED's MMS server for good. Same pattern in `gdoi/server.go:184-189` (any non-close `ReadFrom` error ends the key server). The opposite in `rsession/session.go:271-281`: a persistent read error spins with no backoff. | Real DoS hole. Fix: retry with backoff on temporary errors and emit `conn.accept_error` (§7.1). |
| F2 | `server/server.go:196-202,416-423,514-524` | `WithMaxConnections` caps the total only (default unlimited). No per-IP cap and no accept rate. One client can take every slot; a refused connection is reported as `ConnectionRefused` with no reason. Each association costs at least two goroutines and a 512-entry report queue (`mms/server_conn.go:329`). | Connection-exhaustion detection and optional per-IP limits and rates (§4.1, §5.3). |
| F3 | `server/server.go:351-352`, `iec62351/ossltls/openssl.go:526-532` | `tls.Listen` and the OpenSSL listener hand out lazy connections. The handshake runs inside `cotp.Accept` under the handshake deadline (`mms/server_conn.go:209-225`), which is good. But every failure surfaces as one `"association setup failed"` log line (`server/server.go:433-436`) with the error text. `iec62351.Options.OnEvent` (`iec62351/tls.go:186-196`) reports verification failures only, with the leaf and the error but **no peer address**. Missing client certificate, version or cipher mismatch, plaintext on the TLS port and scanner probes are not reported at all. | Do the handshake explicitly in `serveConn`, classify it, and bridge `Options.OnEvent` with the connection context (§4.2). |
| F4 | `mms/server_conn.go:209-215`, `mms/server_conn.go:457-483` | A read deadline exists only during the handshake. After the association the server reads with **no deadline**: an idle association holds its slot for ever, and a peer that sends a TPKT header and stalls holds a partial frame for ever (slowloris after association). MMS has no keep-alive of its own. Combined with `WithMaxConnections`, a handful of idle associations lock out every real client. | Opt-in idle timeout plus a frame-assembly deadline, with events (§4.11, §7.3). |
| F5 | `mms/server_conn.go:439-452,712-749` | The write deadline exists (default 30 s, `server/server.go:301`) and closes the transport on timeout. That is right, but **silent**. A full report queue returns `ErrReportQueueFull` (used for BufOvfl) and nothing else. | `dos.write_stall` and `dos.report_queue_full` events. No behaviour change (§4.11). |
| F6 | `mms/server_conn.go:222-339`, `server/server.go:433-436` | Failures at each setup stage (COTP CR, session CONNECT, presentation CP, AARQ, no MMS presentation context, Initiate) collapse into one wrapped error. A port scanner, a non-MMS client, a fuzzer and a misconfigured client look the same. | `assoc.setup_failed` with a stable `Stage` field, and `conn.no_data` for a connection that never sent one valid TPKT (§4.4). |
| F7 | `mms/server_conn.go:246-282,346-383`, `server/services_ext.go:40-55` | Password rejection (`WithPassword`, constant-time compare), A-profile failures, and `E2ERequired` refusals answer the client correctly but produce no structured signal. Nothing counts repeated failures, so password guessing over many associations goes unnoticed. | `assoc.auth_failed` and the related kinds, plus a per-IP brute-force detector (§4.4). |
| F8 | `mms/server_conn.go:485-558`, `server/handler.go:102-106` | Undecodable PDUs, unknown PDU types, bad invoke IDs and unrecognised services get the right RejectPDU, but are not reported. | `proto.mms_reject` and `access.unrecognized_service` (§4.5, §4.6). |
| F9 | `server/handler.go:215-470` | Read and write answer each item with a `DataAccessError` (object-non-existent, access-denied, type-inconsistent, temporarily-unavailable, …). These are the 61850 equivalent of IEC 104's COT 44–47. The handler already knows every result. | **Observe the results**: every per-item failure becomes an event with no change to user code, and a run of non-existent names from one association becomes `access.scan` (§3.6, §4.6). |
| F10 | `server/control.go:90-244` | Every refused control goes through `refuse(cause)` with an `AddCause` and a LastApplError. Good. But `ControlCtx.T` (`control.go:438-441`) **is never compared with the clock**, and nothing compares one Oper with an earlier one. A captured Oper (same ctlVal, origin, ctlNum and T) replayed over a new association is executed again. `orCat`/`orIdent` are whatever the client claims. | `cmd.*` audit trail, stale-T and duplicate-Oper detection, optional orIdent binding (§4.7). |
| F11 | `mms/conn.go:719-731` | The MMS client logs a response for an unknown invoke ID and drops it. Reports for a RptID no RCB is enabled for, and CommandTerminations with no operate outstanding, are not reported either. | Unsolicited events on the client side (§4.9). |
| F12 | `goose/subscriber.go:129-160,218-257` | Parse errors are dropped silently (`:147-150`). `Anomalies` (stNum regressed, sqNum gap, stale, entries mismatch) are computed but only set on the delivered message, so an application that ignores them loses them. **The source MAC is never looked at** (`ethernet.Frame.Src`, `ethernet/ethernet.go:32`). ConfRev, DatSet and GoID are never compared with what the subscriber expects. Simulated frames are dropped without a trace (`:30`). Streams past `MaxStreams` are delivered untracked without a signal (`:241-254`). A changed value with no stNum increment (the classic GOOSE-poisoning signature) is not detected. | GOOSE stream monitor with `goose.*` events (§4.8, §5.6). |
| F13 | `sv/subscriber.go:117-155` | SV has **no sequence tracking at all**: no smpCnt gap, duplicate or regression check, no ConfRev or smpSynch check, no source MAC. Parse and 9-2LE decode errors are dropped silently (`:135-138,148-150`). | SV stream monitor with `sv.*` events, cheap enough for 4 kHz × streams (§4.8, §9). |
| F14 | `rsession/session.go:63-75,323-374,376-397` | R-GOOSE/R-SV already refuse unknown keys, failed MACs/tags, unsecured SPDUs and replays, count them in `Stats`, and call `Config.OnReject`. The replay key is the source IP (`:126-135`), which the comment says can be spoofed. `AllowUnsecured` accepts unsecured SPDUs with no trace. | Bridge `OnReject` into the sink as `rsession.*`. Add `rsession.unsecured_accepted`. Nothing else to build (§4.8). |
| F15 | `gdoi/server.go:217-268,270-291` | GDOI has `OnRegister`/`OnReject`, a good base. But a message 1 with a new initiator cookie from any address creates phase-1 state (`:226-232`). It is bounded at 4096, and eviction is an O(n) scan under the server mutex (`expire`). A flood of message 1 from spoofed sources evicts legitimate exchanges in progress. A known cookie from a different address and a wrong responder cookie are dropped silently (`:233-241`): a hijack or confusion attempt with no trace. | `gdoi.*` events, a phase-1 flood detector, and the evicted-state counter (§4.10). |
| F16 | `iec62351/e2e/events.go`, `iec62351/e2e/config.go:240,256,275` | IEC 62351-4 E2E already has a typed event model (`EventCode`, `EventClass`, AssoID, PeerAE, CertSHA, Diag) aligned with IEC 62351-14. | Bridge: `e2e.Event` → `secevent.Event` with `Kind = "e2e." + Code`. The e2e codes become part of the catalogue unchanged (§4.4). |
| F17 | `server/server.go:26,157`, `mms/conn.go` (`Options.Logger`) | Logging is `log/slog`, discarded by default. The event channel is separate from it, and a `SlogSink` adapter is provided. | §3.4. |
| F18 | `server/file.go:79-121`, `server/handler.go:96-101` | File names are validated (`fsName`) and each association holds at most 8 open files (`maxOpenFiles`). FileDelete, FileRename and ObtainFile (a **download to the IED**) change the device's file system. FileDirectory and FileRead are how disturbance records are taken. None of it is audited. | `file.*` audit and rejection events; an invalid name containing `..` or an absolute path is reported as a traversal attempt (§4.10). |
| F19 | `server/handler.go:586-660` | Dynamic datasets are capped (256 sets, 1024 entries). Reaching a cap is refused without a signal. | `dos.dataset_limit` (§4.11). |
| F20 | `server/server.go:102-144,476-497` | `OnConnection` already gives opened/closed/refused with the peer address and the association. | Keep it. `conn.*` events are emitted at the same points, so both stay consistent (§4.1). |
| F21 | `server/handler.go:96-101,367-412`, `server/journal.go`, `server/settinggroup.go` | The security-relevant ACSI operations all pass through `handler.write` and the service switch: setting-group selection and editing (`ActSG`, `EditSG`, `CnfEdit`, SE writes), CF/DC/BL writes when enabled, RCB/LCB/GoCB/SVCB enables and resets, InitializeJournal (**log deletion**, only with `WithDeletableLogs`), and controls on `Mod`, `Beh`-related objects and `LPHD.Sim` (simulation mode). | `ctrl.*` audit events, raised from one place each (§4.7). |
| F22 | `mms/server_conn.go:542-592` | Requests are handled one at a time per association, so `MaxServOutstanding` is never exceeded on the server. A client that pipelines far beyond its negotiated value is still a signal. | `proto.outstanding_exceeded`, report only (§4.5). |

---

## 2. Architecture overview

```
           ┌──────────────────────────────────────────────────────────────┐
           │                        application                           │
           │   sink := secevent.SinkFunc(func(e secevent.Event){…})       │
           └──────────────▲───────────────────────────────────▲───────────┘
                          │ async, bounded, never blocks       │ PeerInfo(), Stats()
                 ┌────────┴──────────┐               ┌─────────┴────────┐
                 │ secevent.Dispatcher│              │ netpeer (MAC)    │
                 │ (queue, aggregate, │              │ resolver + cache │
                 │  drop accounting)  │              └─────────▲────────┘
                 └────────▲──────────┘                         │
       ┌──────────────────┼──────────────┬──────────────┬──────┴──────────┐
  internal/secmon detectors (token buckets, scan window, conn tracker, auth-failure tracker,
                          duplicate-command window, L2 stream monitor)
       │                  │              │              │                 │
  server.Server      mms.ServerConn   client/mms.Conn  goose/sv          rsession, gdoi
  (ACSI services,    (OSI stack,      (unsolicited,    Subscriber        (bridged OnReject,
   control, files)    ACSE, TLS)       TLS client)     (stream monitor)   OnRegister)
       │                                                                  │
  iec62351 TLS Options.OnEvent ─── bridged ───  iec62351/e2e OnEvent ─── bridged
```

### New packages

| Package | Visibility | Contents |
|---------|-----------|----------|
| `secevent` | public | `Event`, `Kind`, `Category`, `Severity`, `Action`, `PeerInfo`, `StreamInfo`, `Sink`/`SinkFunc`, `Dispatcher`, ready-made sinks, `Reporter` and `Report(r, e)`, `Policy`/`Limits`, `Stats`, and the bridges `FromTLSEvent`, `FromE2EEvent`, `FromRSessionReject`, `FromGDOI*`. Depends on `mms`/`model` only for typed fields; protocol packages depend on it through a small internal emitter. |
| `netpeer` | public | `LookupMAC(ip)`, `Resolver` interface, OS backends (Linux netlink + `/proc/net/arp`, Windows `GetIpNetTable2`, Darwin/BSD route sysctl), `Cache` (IP↔MAC history, change detection), `OnLink(ip)`. Usable on its own with any `net.Conn`. |
| `internal/secmon` | internal | Token bucket, sliding-window distinct counter (scan detector), connection tracker (per-IP counts and rates), auth-failure tracker, duplicate-command window, GOOSE/SV stream state, aggregator, time-tag checker. Shared by `server`, `mms`, `client`, `goose`, `sv`, `gdoi`. |

Import-cycle note: `secevent` must not import `server`, `goose` or `sv`. The
protocol packages import `secevent`. The `e2e`, `iec62351`, `rsession` and
`gdoi` packages do **not** import it: their existing hooks stay as they are,
and `secevent` provides the bridge functions, which the higher-level wiring
(`server.WithSecurityPolicy`, `client.WithSecurityPolicy`, the `cmd`s) installs.

Names were settled in the iec104 plan (split packages, §12 Q1) and are kept
for consistency across the two libraries.

---

## 3. Event model and delivery

### 3.1 `secevent.Event`

```
Event {
    Time        time.Time
    Kind        Kind        // stable dotted code, e.g. "goose.sqnum_duplicate" (string type, constants)
    Category    Category    // Connection | Peer | TLS | Association | Protocol | Access |
                            //   Control | Configuration | Sequence | Unsolicited | Flood |
                            //   Resource | File | KeyManagement | Meta
    Severity    Severity    // Info | Notice | Warning | Alert | Critical   (RFC 5424 aligned)
    Action      Action      // Observed | Ignored | Rejected | Throttled | Disconnected | Blocked
    Protocol    string      // "mms" | "goose" | "sv" | "r-goose" | "r-sv" | "gdoi" | "tls" | "e2e"
    Role        string      // "server" | "client" | "publisher" | "subscriber" | "keyserver" | "member"
    SessionID   uint64      // monotonically increasing per process; correlates events of one association
    Peer        PeerInfo    // TCP/UDP peers (3.2); zero for layer-2 events
    Stream      *StreamInfo // GOOSE/SV/R-* stream (3.2); nil otherwise
    Local       string      // local address or interface name

    // Protocol context — zero when not applicable; Fields says which are set
    Fields      FieldMask
    Service     int         // MMS confirmed service tag (mms.Service*)
    InvokeID    uint32
    ObjectRef   string      // ACSI reference "LD/LN.DO.DA" (or MMS domain/item when unresolvable)
    FC          string
    AccessError int         // mms.DataAccessError, when the event is a per-item result
    AddCause    int         // model.AddCause, for controls
    CtlNum      uint8
    OrCat       int; OrIdent string   // as claimed by the client
    Test        bool
    StNum, SqNum uint32               // GOOSE
    SmpCnt      uint16                // SV
    ConfRev     uint32
    Value       string      // human-readable value (bounded length)

    Count       int         // >1 when aggregated (3.3)
    FirstSeen   time.Time
    Detail      string      // one-line English explanation, no secrets
    Err         error       // underlying error (errors.Is-able sentinel where one exists)
    Raw         []byte      // copy of the offending PDU/frame, truncated to MaxRaw (default 64 B)
    Technique   string      // optional MITRE ATT&CK for ICS hint (§3.7)
    Std62351    string      // optional IEC 62351-14 event identifier (§3.7)
}
```

Rules:

- `Kind` values are public API and **must never be renamed**. Add new ones
  and deprecate old ones only. Each `Kind` has a fixed default `Category`,
  `Severity`, `Technique` and `Std62351`, set in one table (`kinds.go`).
- `Raw` is always a copy. Under IEC 62351-4 E2E encryption it holds the
  *decrypted* MMS PDU only when `Policy.RawDecrypted` is set (default off),
  because the plaintext may be confidential.
- `Detail` never contains passwords, the ACSE authentication value, key
  material, GDOI TEKs or full certificates (only fingerprint and subject).
  `OrIdent` is bounded to 64 octets (the type's maximum) and hex-escaped
  when not printable.
- `Event.String()` gives a one-line text form. `MarshalJSON` gives a stable
  JSON form (field names fixed, `omitempty`).

### 3.2 `secevent.PeerInfo` and `StreamInfo`

```
PeerInfo {
    Network     string           // "tcp", "udp"
    RemoteAddr  netip.AddrPort
    LocalAddr   netip.AddrPort
    MAC         net.HardwareAddr // nil when unknown
    MACSource   MACSource        // None | Neighbor | Gateway | Static | Custom
    OnLink      bool
    Interface   string
    TLS         *TLSPeer         // nil when plaintext
    ACSE        *ACSEPeer        // nil before the association
    ConnectedAt time.Time
}
TLSPeer  { Version, CipherSuite uint16; ServerName string; Subject, Issuer, SerialHex string;
           NotAfter time.Time; FingerprintSHA256 string; Verified bool; Engine string /* "go" | "openssl" */ }
ACSEPeer { CallingAPTitle string; CallingAEQualifier *int32; CalledAPTitle string;
           PasswordPresented bool;               // never the password itself
           AProfileSubject, AProfileFingerprint string;
           E2E bool; E2EPeerAE string; E2EAssoID string }

StreamInfo {
    Kind      string            // "goose" | "sv"
    AppID     uint16
    SrcMAC, DstMAC net.HardwareAddr
    VLAN      *ethernet.VLANTag
    ControlRef string           // goCbRef or svID
    DatSet, GoID string
    Simulation bool
    Via       string            // "l2" or the R-session source address
}
```

Accessors:

- `(*mms.ServerConn).PeerInfo() secevent.PeerInfo` and
  `(*client.Client).PeerInfo()`. `mms.ServerConn` already has `Peer`,
  `Called`, `Calling`, `AProfilePeer` and `PeerSecurity()`; `PeerInfo`
  assembles them with TLS state and the MAC.
- `ControlCtx.Conn` already carries the association, so a control handler
  gets `ctx.Conn.PeerInfo()` with no new parameter.
- `netpeer.LookupMAC(addr net.Addr)` for users with their own `net.Conn`.
- `PeerInfo` is computed once at connect time and cached on the connection.
  MAC re-checks (§5.2) update it under a mutex. The accessor returns a copy.

### 3.3 Delivery: `secevent.Dispatcher`

Unchanged from the iec104 plan:

- **Never block a protocol goroutine.** Call sites do `emitter.emit(e)`, one
  `atomic.Pointer[Dispatcher]` load. Nil returns at once: no allocation, no
  time read. This matters most on the SV reader, which runs at 4 000–14 400
  frames/s per stream.
- Bounded channel (default 1024), one goroutine calling the sink. Overflow is
  counted and announced by `meta.events_dropped{Count}`. Never silent.
- **Aggregation** per `(SessionID or stream key, Kind, key)` with key =
  ObjectRef / AppID+ControlRef / Service where relevant. First event at once,
  repeats inside `AggregateWindow` (default 1 s) flushed as one with `Count`
  and `FirstSeen`. *Always-deliver* kinds (`peer.mac_changed`,
  `goose.source_mac_changed`, `tls.cert_rejected`, `ctrl.simulation_mode`,
  `ctrl.journal_initialized`, `file.obtain`) bypass it. Bounded LRU (4096 keys).
- `Dispatcher.Close()` flushes. A dispatcher can be shared between a Server,
  its GOOSE subscriber, its SV subscriber and its R-sessions: the normal
  set-up for one IED process.
- Sink panics are recovered, counted, and reported once as `meta.sink_panic`.
- `secevent.SyncSink(s)` for tests only.

### 3.4 Ready-made sinks

| Sink | Purpose |
|------|---------|
| `SinkFunc(func(Event))` | adapter |
| `ChannelSink(chan<- Event)` | non-blocking send, counts drops |
| `SlogSink(*slog.Logger)` | Severity → `slog.Level` (Critical/Alert → Error+4/Error, Warning → Warn, Notice/Info → Info), attributes from the fields, message prefix `cyber:` |
| `JSONLinesSink(io.Writer)` | one JSON object per line (file, stdout, socket) |
| `MultiSink(...Sink)` | fan-out |
| `FilterSink(min Severity, s Sink, cats ...Category)` | filtering (the categories last, as Go variadics require) |

Output formats stop at JSON lines (iec104 §12 Q5: answer JSON). A syslog/CEF
formatter can be added later without API change.

### 3.5 Reporting from outside the library: `secevent.Reporter`

```
type Reporter interface { ReportCyberEvent(Event) }
func Report(r any, e Event) bool   // type-asserts Reporter, fills Peer/Session/Protocol/Role/Time
```

Implemented by `*mms.ServerConn`, `*client.Client`, `*goose.Subscriber`,
`*sv.Subscriber`. Used by:

- **Control handlers**: `secevent.Report(ctx.Conn, secevent.ControlRefused(ctx, cause, "interlock"))`.
  The library already reports every refusal it sees (§4.7), so this is only
  for reasons the handler wants to add.
- **Write handlers**: `OnWrite` receives `(da, v)` and **no connection**, so it
  cannot report with peer identity. Add the additive
  `Server.OnWriteCtx(func(*WriteCtx) error)` with `WriteCtx{DA, Value, Ref,
  Conn, Peer}`; `OnWrite` stays and is implemented on top of it (§12 Q2).
- **Applications driving GOOSE/SV** that know more than the library (e.g. a
  value outside the physically plausible range).

### 3.6 Automatic detection from outbound results

The MMS server already decides every result; the event comes from the same
point, only when a dispatcher is attached:

| Result sent | Where | Event |
|-------------|-------|-------|
| Read/write item `object-non-existent` | `handler.go:245,270,291,348,425,429` | `access.object_nonexistent` (feeds `access.scan`) |
| Item `object-access-denied` | `handler.go:449,466`, `control.go:100,137` | `access.denied` |
| Item `object-access-unsupported` / `type-inconsistent` | `handler.go:433,441`, `control.go:109,145` | `access.invalid_value` |
| Item `temporarily-unavailable` on SE | `handler.go:470` | `access.setting_not_editing` |
| `AccessObjectNonExistent` service error on GetVariableAccessAttributes / GetNVLAttributes / DefineNVL | `handler.go:540-566,660-664` | `access.object_nonexistent` |
| RejectPDU / unrecognized-service | `server_conn.go:489,514,546,550,557`, `handler.go:106` | `proto.mms_reject` / `access.unrecognized_service` |
| LastApplError + negative Oper/SBOw/Cancel | `control.go:134-138` | `cmd.rejected` with `AddCause` |
| Negative CommandTermination | `control.go:296-330` | `cmd.terminated_negative` |
| File error (`fileNonExistent`, `fileBusy`, …) | `server/file.go` | `file.rejected` |

Correlation: the event carries the request's `InvokeID`, `Service` and the
object reference, so a SIEM can join request and result.

Client side, mirrored: a ConfirmedError or RejectPDU *received* from a server
is `remote.rejected` (Notice). It is a weak cyber signal (mostly
misconfiguration), but it lets an operator spot an HMI or gateway that is
being steered to unusual requests.

### 3.7 MITRE ATT&CK for ICS and IEC 62351-14 hints

`Technique` is a hint for SIEM routing, not an attribution. Starting mapping
(**check IDs against the current ATT&CK for ICS matrix when implementing**):
T0814 Denial of Service · T0855 Unauthorized Command Message · T0846 Remote
System Discovery · T0888 Remote System Information Discovery · T0861 Point & Tag
Identification · T0830 Adversary-in-the-Middle · T0836 Modify Parameter ·
T0816 Device Restart/Shutdown · T0843 Program Download · T0845 Program
Upload · T0806 Brute Force I/O · T0849 Masquerading · T0856 Spoof Reporting
Message · T0858 Change Operating Mode · T0815 Denial of View · T0878 Alarm
Suppression · T0872 Indicator Removal on Host · T0866 Exploitation of Remote
Services · T0859 Valid Accounts.

`Std62351` carries the IEC 62351-14 event identifier where the standard
defines one, and a library extension identifier otherwise (§12 Q10). The e2e package already follows IEC 62351-14 for its codes
(`iec62351/e2e/events.go:8`); **check the identifiers against the published
IEC 62351-14 when implementing**. Kinds with no standard match get an
extension identifier, documented as such and never mistaken for a standard one.

---

## 4. Event catalogue

Columns: **Kind** · default **Sev** · trigger · where. Roles: S = MMS server,
C = MMS client, Sub = GOOSE/SV subscriber, KS = GDOI key server, M = GDOI member.

### 4.1 Connection (`conn.*`) — MMS over TCP/TLS

| Kind | Sev | Trigger | Where |
|------|-----|---------|-------|
| `conn.accepted` | Info | Every accepted TCP connection, with PeerInfo incl. MAC. The "log every connection" baseline. | `server.go:368` after Accept |
| `conn.unexpected` | Warning | Peer IP not in `Policy.AllowedPeers` (CIDR). Action `Rejected` (closed before any byte is read and before the TLS handshake) or `Observed`. | conn tracker, before `serveConn` |
| `conn.unexpected_mac` | Alert | IP allowed but MAC not the pinned binding `Policy.PeerBindings[ip]` | same |
| `conn.rejected_limit` | Warning | `WithMaxConnections` (existing, `server.go:418-423`) or new `MaxConnectionsPerIP` reached. Emitted next to the existing `ConnectionRefused`. | `takeSlot` |
| `conn.rate` | Alert | New connections from one IP exceed `AcceptRate` (default 10 / 10 s), or distinct-IP bursts exceed `GlobalAcceptRate`. Connection storm or scan. | conn tracker |
| `conn.no_data` | Notice | Closed by the peer before one valid TPKT. TCP-connect scan or banner grab on port 102/3782. | `serveConn` |
| `conn.never_associated` | Warning | Handshake deadline hit before the AARE (`HandshakeTimeout`, default 10 s). Holds a slot without associating. Action `Disconnected`. | `AcceptConnOpts` error classification |
| `conn.idle_timeout` | Notice | Association idle beyond `Policy.IdleTimeout` (opt-in, §7.3). Action `Disconnected`. | `Serve` read deadline |
| `conn.closed` | Info | Association end, with `Detail` = reason (conclude, release, peer abort, local abort, write stall, idle, policy, transport error), duration, requests, octets in and out. | `serveConn` defer (`server.go:450-463`) |
| `conn.dial_failed` | Notice | Client dial or association failure; Warning after N consecutive failures. | `mms.Dial` |
| `conn.accept_error` | Critical | Listener Accept error (EMFILE, ENFILE, ENOBUFS…). See §7.1. | `server.go:368` |

### 4.2 TLS (`tls.*`) — IEC 62351-3

Handshake done explicitly in `serveConn` (Go: `HandshakeContext`, OpenSSL:
the `Conn`'s handshake op) under the existing handshake deadline, before
`cotp.Accept`. Errors classified with `errors.As`; the existing
`iec62351.Options.OnEvent` callback is wrapped per connection so its
`Event{Peer, Err}` gains the address and session.

| Kind | Sev | Trigger / classification |
|------|-----|--------------------------|
| `tls.cert_rejected` | Alert | `Options.verify` failed (`iec62351/tls.go:186-196,235-292`): unknown authority, expired, wrong key usage, weak key (`checkKey`), name mismatch on the client side. Carries the unverified leaf's subject, issuer, serial, NotAfter and fingerprint. |
| `tls.cert_revoked` | Alert | Leaf or intermediate listed by a CRL (`checkRevoked`, `tls.go:352-386`). Always delivered. |
| `tls.crl_stale` | Warning | `ErrStaleCRL` / `ErrCRLSignature`: revocation could not be checked. The operator's problem, but it silently weakens the link if `AllowStaleCRL` is set; with it set, the event is still raised as `Observed`. |
| `tls.no_client_cert` | Alert | Server requires a client certificate and none was sent. |
| `tls.local_cert_rejected` | Warning | Peer sent alert `bad_certificate`/`unknown_ca`/`certificate_expired`/`certificate_revoked`: **it** does not trust **us**. Misconfiguration or a MITM presenting a different chain. |
| `tls.plaintext_on_tls_port` | Warning | `tls.RecordHeaderError` whose first octets are `03 00` (a TPKT header): an MMS client speaking plaintext to the TLS port. |
| `tls.non_tls_probe` | Notice | `RecordHeaderError` with any other leading octets (`GET `, `SSH-`, null probe): a scanner. |
| `tls.handshake_failed` | Warning | Version, no shared cipher or group, protocol error. `Detail` = engine error text. |
| `tls.handshake_timeout` | Warning | Deadline exceeded during the handshake. Slow-handshake DoS. |
| `tls.weak_params` | Notice | Negotiated TLS < 1.2, or a suite outside the IEC 62351-3/-4 profile tables (`iec62351` already lists them), e.g. a legacy-OpenSSL static-DH suite where native mode was not requested. |
| `tls.renegotiation_attempt` | Warning | Peer attempted renegotiation (`RenegotiateNever`, `tls.go:124`). IEC 62351-3 has rules on renegotiation; a refusal is worth reporting. |
| `tls.cert_expiring` | Notice | Peer leaf `NotAfter` within `CertExpiryWarning` (default 30 days). |
| `tls.cert_changed` | Notice | Peer IP presents a different leaf fingerprint than last time (TOFU history in the MAC cache, §5.2). |

### 4.3 Peer identity (`peer.*`)

| Kind | Sev | Trigger |
|------|-----|---------|
| `peer.mac_changed` | Alert | Connection from IP X with MAC M2 while the cache last saw M1 (within `MACHistoryTTL`, default 30 days). ARP spoofing / MITM, or a legitimate device swap. Always delivered. |
| `peer.mac_changed_midsession` | Critical | Periodic re-check (`MACRecheckInterval`, opt-in) finds a live association's MAC changed. Optional action `Disconnected`. |
| `peer.mac_pinning_violation` | Critical | Pinned binding mismatch (also `conn.unexpected_mac` when rejected at accept). |
| `peer.ip_changed` | Info | Known MAC with a new IP. |
| `peer.mac_shared` | Notice | One MAC behind several on-link IPs at once. Suppressed for `MACSource=Gateway`. |
| `peer.mac_unavailable` | Info | On-link peer, no neighbour entry. Once per IP. |
| `peer.identity_changed` | Warning | Same IP and MAC, but a different Calling AP-title, A-profile certificate or E2E AE-title than last time (history in the same cache). An HMI that suddenly claims to be another application entity. |

The layer-2 counterpart for GOOSE/SV streams is in §4.8 (`goose.source_mac_changed`, `sv.source_mac_changed`).

### 4.4 Association and authentication (`assoc.*`, `e2e.*`)

| Kind | Sev | Trigger | Where |
|------|-----|---------|-------|
| `assoc.established` | Info | Association accepted. Carries ACSE identity, auth mechanism (none / password / A-profile / E2E), negotiated MaxPDU, outstanding, and services. | `server.go:465` |
| `assoc.setup_failed` | Warning | Setup error, with `Stage` = `cotp` / `session` / `presentation` / `acse` / `initiate` / `context` and the sentinel error. A malformed CR, CONNECT or CP from a non-MMS client, scanner or fuzzer. | `mms/server_conn.go:222-339` |
| `assoc.auth_failed` | Warning | `Authenticate` refused (wrong password with `WithPassword`, or the user's authenticator). `PasswordPresented` only, never the value. | `server_conn.go:268-282`, `784-787` |
| `assoc.auth_required` | Notice | No credentials where they are required (`ErrAuthenticationRequired`, A-profile without a value). | `server_conn.go:276-279,358-363` |
| `assoc.aprofile_failed` | Alert | A-profile value did not verify (signature, certificate, time, replay of the authentication value). P-ABORT sent. | `server_conn.go:365-374` |
| `assoc.aprofile_without_tls` | Warning | A-profile attempted over plain TCP and refused. | `server_conn.go:353-356` |
| `assoc.e2e_required` | Warning | Plain association refused because `E2ERequired`. | `server_conn.go:246-253` |
| `assoc.no_mms_context` | Warning | No usable MMS presentation context. | `server_conn.go:305-311` |
| `assoc.called_mismatch` | Notice | Client's Called AP-title / AE-qualifier is not this server's `WithAEIdentity`: the client thinks it reached another IED (MITM, DNS/ARP redirection, or a wrong configuration). Report only. | after `ParseAARQFull` |
| `assoc.brute_force` | Alert | ≥ `AuthFailureThreshold` failures (default 5 in 60 s) from one IP or one Calling AP-title. Optional `AuthFailureAction = Block` refuses that IP for `AuthBlockTime` (opt-in). T0859. | auth-failure tracker |
| `assoc.aborted_by_peer` | Notice | Peer A-ABORT / P-ABORT during data transfer (`mms/transport.go:137-165`). Detail has the source and, under E2E, the abort reason. | `framing.peerAborted` |
| `assoc.release_unverified` | Warning | E2E release request whose signature did not verify; association aborted. | `server_conn.go:461-468` |
| `e2e.*` | e2e table | Every `e2e.Event` (`iec62351/e2e/events.go:27-51`) passes through with `Kind = "e2e." + Code` and its `EventClass` mapped (Info→Info, Warning→Warning, Incident→Alert, Alarm→Critical). Includes `e2e.replay`, `e2e.invalid-icv`, `e2e.invalid-signature`, `e2e.certificate-revoked`, `e2e.clock-regression`, `e2e.resource-limit`. | bridge |

### 4.5 Protocol validity (`proto.*`)

| Kind | Sev | Trigger | Where |
|------|-----|---------|-------|
| `proto.tpkt_bad` | Warning | TPKT length < 4 or > 65535 (`internal/osi/tpkt/tpkt.go:43-46`). Version field ignored per IEC 62351-4 H.3.2, but a non-3 version is counted (Notice) as a fingerprint of a non-conformant peer. | tpkt |
| `proto.cotp_bad` | Warning | Unknown TPDU type, bad LI, CR with an unsupported class, a DR/ER from the client, parameter errors. | `internal/osi/cotp` |
| `proto.tsdu_oversized` | Warning | Reassembled TSDU exceeds the limit (`cotp.go:240-246`). Memory-exhaustion attempt. Action `Disconnected`. | cotp |
| `proto.session_bad` / `proto.presentation_bad` / `proto.acse_bad` | Warning | Parse errors in the upper layers after the association (SPDU type, PPDU context, ACSE APDU). | `mms/transport.go:83-134` |
| `proto.presentation_context` | Warning | Data on a presentation context other than the negotiated MMS (or E2E) one. | `recvMMS` |
| `proto.mms_reject` | Warning | Server answered a RejectPDU: undecodable PDU, unknown PDU type, invalid invoke ID. | `server_conn.go:485-558` |
| `proto.mms_decode` | Warning | A confirmed request whose service content does not decode (the handler returns an ASN.1 error, e.g. `handler.go:125-131,226-229,303-310`). Sub-reason from the asn1 sentinel. | handler |
| `proto.unsupported_access_spec` | Notice | Read with an access specification the server does not support (`handler.go:262`), alternate access misuse. | handler |
| `proto.outstanding_exceeded` | Notice | Client has more confirmed requests in flight than the negotiated `MaxServOutstandingCalling` (F22). | ServerConn read loop |
| `proto.pdu_exceeds_negotiated` | Warning | Request PDU larger than the negotiated `localDetail` (MaxPDU). | `handleConfirmed` |
| `proto.unexpected_pdu` | Notice | A ConfirmedResponse/Error/Reject from the client to a request the server never sent (`deliverCall`, `server_conn.go:494-497`), or a Cancel for an unknown invoke ID. | ServerConn |

### 4.6 Data access and discovery (`access.*`)

| Kind | Sev | Trigger | Where |
|------|-----|---------|-------|
| `access.object_nonexistent` | Notice | Per-item object-non-existent (§3.6). Notice individually; the scan detector escalates. | handler |
| `access.domain_unknown` | Warning | Request for a logical device (MMS domain) the model does not have. Guessing LD names is the first step of an IED scan. | handler, `model.Device(...) == nil` |
| `access.denied` | Warning | Per-item access-denied: FC not writable (`WithWritableFCs`), `OnWrite` refusal, SBO written instead of read. | handler, control |
| `access.invalid_value` | Notice | Type-inconsistent or unsupported write; ctlVal of the wrong type. | handler, control |
| `access.setting_not_editing` | Notice | SE written with no setting group being edited. | `handler.go:468-471` |
| `access.unrecognized_service` | Warning | Confirmed service the server does not implement (`handler.go:106`), e.g. DownloadSegment, DeleteDomain, Start/Stop/Kill program invocation: **non-existent or unusual functions**. Detail names the service. | handler |
| `access.scan` | Alert | One association, or one IP across associations, hits ≥ `ScanThreshold` distinct non-existent references / domains / datasets within `ScanWindow` (default 20 in 60 s). Point and tag discovery (T0861). | `internal/secmon` |
| `access.enumeration` | Info → Notice | Full model enumeration: Identify + GetNameList over every domain and class + GetVariableAccessAttributes on many LNs. Normal for an HMI or engineering tool at connect; Notice when the peer is not in `Policy.KnownClients`. T0846 / T0888. | handler counters per association |
| `access.service_blocked` | Warning | Service denied by `Policy.Services` (§6.3). The library answers access-denied or a RejectPDU, and no handler runs. | handler |
| `access.oversized_request` | Warning | Read or write with more than `MaxItemsPerRequest` variables (default 1000), GetNameList continuation loops, DefineNVL beyond the dataset limits (`handler.go:586-660`), FileRead with a huge size. | handler |

The library knows the model, unlike IEC 104, so it needs no `AddressSpace`
interface: object existence comes from `model.Model`.

### 4.7 Controls and configuration as an audit trail (`cmd.*`, `ctrl.*`)

Not errors: security-relevant operations an operator wants on record (IEC
62351-7 / -14 style). All are opt-out with `Policy.AuditControl=false`.

| Kind | Sev | Trigger | Where |
|------|-----|---------|-------|
| `cmd.received` | Notice | Every Oper / SBOw / Cancel / SBO-read: reference, ctlVal, orCat, orIdent, ctlNum, T and its quality, Test, Check, ctlModel, and the observed peer. **The command audit trail.** | `controlWrite` (`control.go:90-244`), `readOne` SBO (`handler.go:274-288`) |
| `cmd.rejected` | Notice | Any `refuse(cause)` (§3.6) with the AddCause. Repeated rejections from one association in a window → `cmd.brute_force` (Alert, T0806). | `control.go:134-138` |
| `cmd.operate_without_select` | Warning | Oper on an SBO object with no live selection, the wrong ctlNum, or another association's selection (`checkSelection`). | `control.go:184-188` |
| `cmd.test_on_enhanced` | Warning | Test-flagged operate on an enhanced-security object (refused, `control.go:157-163`). | |
| `cmd.orident_invalid` | Warning | orIdent longer than 64 octets (`control.go:164-167`). | |
| `cmd.origin_mismatch` | Warning | `Policy.OriginBindings` maps peer IP or Calling AP-title → allowed orCat / orIdent, and the command claims another. An HMI claiming `orCat=station-control` from a remote address, or a spoofed orIdent. Report only, or `Rejected` with `RejectOriginMismatch`. | before the handler |
| `cmd.stale_time` | Alert | Oper/SBOw whose `T` is older than `MaxCommandAge` (opt-in, e.g. 10 s) or more than `MaxCommandFuture` ahead. **Replay of a captured command.** Only applies when T is set and its quality says the client clock is synchronised (`TQuality`); many clients send T = 0, which is reported once per association as `cmd.no_time` (Info) and never rejected. Action `Rejected` with `RejectStaleCommands`, AddCause `inconsistent-parameters` (**check the AddCause choice against IEC 61850-7-2 when implementing**). | before the handler |
| `cmd.duplicate` | Warning | Byte-identical Oper (ctlVal, origin, ctlNum, T) seen again within `DuplicateWindow` on any association of the Server. A replay over a new association. | duplicate-command window |
| `cmd.terminated_negative` | Notice | Negative CommandTermination (timeout `TimeLimitOver`, handler failure). | `termination.finish` |
| `ctrl.mode_change` | Alert | Control on `Mod` of any LN, or of `LLN0.Mod` (whole LD), to off / blocked / test / test-blocked. T0858. Always delivered. | `controlWrite` by DO name |
| `ctrl.simulation_mode` | Critical | `LPHD.Sim` set true: the IED will now accept simulated GOOSE/SV instead of live ones. The precondition for a process-bus injection attack. Always delivered. | `controlWrite`/write by reference |
| `ctrl.setting_group_change` | Alert | `SGCB.ActSG` written (protection settings switched). T0836. | `onSGCBWrite` |
| `ctrl.setting_edit` | Alert | `EditSG` selected, SE written, `CnfEdit` confirmed (one event per edit session with the changed references). | sgManager |
| `ctrl.config_write` | Alert | Write to a CF, DC or BL attribute when `WithWritableFCs` allows them: configuration, descriptions, **blocking** (BL can suppress values, T0878). | `writeOne` |
| `ctrl.report_disabled` | Notice | RptEna set false on an RCB enabled by **another** association, or a buffered RCB's PurgeBuf/EntryID reset. Denial of view (T0815). | `onRCBWrite` |
| `ctrl.log_disabled` | Warning | `LogEna` false. Evidence suppression. | `onLCBWrite` |
| `ctrl.journal_initialized` | Alert | InitializeJournal (only possible with `WithDeletableLogs`): **log entries deleted**. T0872. Always delivered. | `handler.go:94-95` |
| `ctrl.goose_cb_change` | Warning | Write to a GoCB (`GoEna`, `DatSet`, …) or SVCB (`SvEna`, `Resv`). Disabling a publisher stops protection signalling. | write path |
| `ctrl.dataset_defined` / `ctrl.dataset_deleted` | Info | DefineNVL / DeleteNVL. | handler |

The library identifies these from the model reference and the FC, so a
handler needs no changes. Names (`Mod`, `Sim`, `ActSG`, …) come from
IEC 61850-7-4 and are matched by DO/DA name on any LN class that carries
them.

### 4.8 Process bus and routable sessions (`goose.*`, `sv.*`, `rsession.*`)

These replace the `seq.*` table of the iec104 plan: MMS runs over TCP and
has no application sequence numbers, while GOOSE and SV do.

**GOOSE** (per subscription and goCbRef; §5.6):

| Kind | Sev | Trigger |
|------|-----|---------|
| `goose.parse_error` | Notice | `goose.Parse` failed (`subscriber.go:147-150`). Aggregated per source MAC. |
| `goose.stnum_regressed` | Alert | `Anomalies.StNumRegressed` (existing check). Replay of old state, or a restarted publisher (then also `sqNum` 0 and a stNum of 1, which is reported as `goose.publisher_restart`, Notice). |
| `goose.sqnum_gap` | Notice | `Anomalies.SqNumGap` (existing). Loss on the bus; Warning above `GooseGapRate`. |
| `goose.duplicate` | Alert | Same stNum and sqNum as the previous message, with the same or different payload. **Replay or injection.** |
| `goose.stnum_jump` | Warning | stNum advances by more than 1. Missed state changes, or an injected message that "wins" by using a higher stNum (the published GOOSE-poisoning technique). |
| `goose.data_change_without_stnum` | Alert | allData differs from the previous message but stNum did not advance. Not legal for a conformant publisher. **Injection.** |
| `goose.stnum_without_data_change` | Notice | stNum advances with identical allData. Legal but rare; with `goose.stnum_jump` it is an injection pattern. |
| `goose.time_regressed` | Warning | New stNum with `T` earlier than the previous state's `T`. |
| `goose.stale` / `goose.tal_expired` | Warning | `Anomalies.Stale` (existing) and supervision expiry (`SubscribeSupervised`). Publisher lost, or a DoS on the path (T0814, T0815). |
| `goose.confrev_mismatch` | Warning | ConfRev differs from `Expect.ConfRev` (from SCL `GSEControl` / `goose/scl.go`). |
| `goose.dataset_mismatch` | Warning | DatSet, GoID or NumDatSetEntries differ from the expectation, or `Anomalies.EntriesMismatch` (existing). |
| `goose.source_mac_changed` | Alert | Source MAC of a known goCbRef/APPID changes. Spoofed publisher on the bus. Always delivered. |
| `goose.unexpected_source` | Warning | Source MAC not `Expect.SrcMAC`, or VLAN/priority not as configured. |
| `goose.unexpected_stream` | Notice | goCbRef/APPID matched by an unfiltered subscription but not in the expected set (`Policy.ExpectedStreams`). A new publisher on the bus. |
| `goose.test_flag` | Notice | `Test=true` on a live stream. |
| `goose.simulated_dropped` | Notice | Simulated message dropped because the subscription is live (`subscriber.go:30`); aggregated. A test set — or an attacker — publishing with the simulation bit. Warning when the goCbRef also exists as a live stream (shadowing attempt). |
| `goose.ndscom` | Notice | NdsCom set (publisher needs commissioning). |
| `goose.untracked_stream` | Warning | Stream beyond `MaxStreams` delivered untracked (`subscriber.go:241-254`). Flooding with distinct goCbRefs. |
| `goose.flood` | Warning | A stream's rate exceeds its retransmission curve (a burst of `MinTime` steps after each state change, then `MaxTime`), or the subscriber's total frame rate exceeds `MaxL2FrameRate`. |

**SV** (per subscription and svID; §5.6):

| Kind | Sev | Trigger |
|------|-----|---------|
| `sv.parse_error` / `sv.le_decode_error` | Notice | `sv.Parse` / `decodeLEInto` failed (`subscriber.go:135-138,148-150`). Aggregated. |
| `sv.smpcnt_gap` | Notice | smpCnt skipped values (modulo the wrap at smpRate or 65536). Loss; Warning above `SVGapRate`. |
| `sv.smpcnt_duplicate` | Alert | Same smpCnt again within one wrap. Replay or injection. |
| `sv.smpcnt_regressed` | Warning | smpCnt went back other than at the wrap. |
| `sv.confrev_mismatch` / `sv.dataset_mismatch` | Warning | ConfRev, DatSet or sample count differ from the expectation. |
| `sv.sync_lost` | Warning | smpSynch drops from global/local to none. Time-sync attack (PTP) or GPS loss; protection relying on synchronised samples is degraded. |
| `sv.source_mac_changed` | Alert | As for GOOSE. Always delivered. |
| `sv.simulated_dropped` | Notice | As for GOOSE. |
| `sv.stream_lost` | Warning | No frame for `SVSupervision` (default 10 ms ≈ 40 samples at 4 kHz). Opt-in: one timer per stream. |
| `sv.rate_anomaly` | Warning | Observed rate differs from smpRate by more than 10 % over a second, or the total rate exceeds `MaxL2FrameRate`. |

**R-GOOSE / R-SV** — bridge of `rsession.Config.OnReject` (`session.go:63-75`):

| Kind | Sev | Trigger |
|------|-----|---------|
| `rsession.malformed` | Notice | `ErrMalformed`, `ErrVersion`. |
| `rsession.unknown_key` | Warning | `ErrUnknownKey`. A sender using a retired key, or a forger. |
| `rsession.unauthentic` | Alert | `ErrAuthentication`, `ErrAlgorithm`: MAC/tag failed. Forgery or corruption. |
| `rsession.unsecured` | Warning | Unsecured SPDU refused (`ErrUnsecured`). |
| `rsession.unsecured_accepted` | Notice | Unsecured SPDU accepted because `AllowUnsecured` (new emit point, `session.go:362-368`); once per source and aggregated. |
| `rsession.replay` | Alert | `ErrReplay`. |
| `rsession.no_active_key` | Warning | Publisher has no active key and sends nothing (`ErrNoActiveKey`). Key distribution failure = denial of service. |

The GOOSE/SV monitors run on top of R-sessions too (a `Session` is an
`ethernet.Interface`), with `StreamInfo.Via` set to the source address.

### 4.9 Unsolicited (`unsol.*`) — MMS client

| Kind | Sev | Trigger |
|------|-----|---------|
| `unsol.response` | Warning | Response, error or reject for an invoke ID with nothing outstanding (`mms/conn.go:719-731`), or after it timed out. |
| `unsol.report` | Notice | InformationReport with a RptID that no RCB enabled by this client carries, or for an RCB the client disabled. Spoofed reporting (T0856) when the association is not E2E-protected. |
| `unsol.command_termination` | Warning | CommandTermination (positive or negative) with no enhanced-security operate outstanding for that object. |
| `unsol.last_appl_error` | Notice | LastApplError for an object with no control in progress. |
| `unsol.server_request` | Notice | A confirmed request from the server (MMS allows it; IEC 61850 servers do not send one except in proxies). |

### 4.10 Files and key management (`file.*`, `gdoi.*`)

| Kind | Sev | Trigger | Where |
|------|-----|---------|-------|
| `file.directory` | Info | FileDirectory. Discovery of disturbance records and configuration. | `server/file.go:285` |
| `file.read` | Notice | FileOpen + FileRead to the end: an **upload from the IED** (COMTRADE, logs, configuration; T0845 for configuration files). Name and size. | `file.go:216-283` |
| `file.obtain` | Alert | ObtainFile: a **download to the IED** (firmware or configuration, T0843). Always delivered. | `handler.go:100-101` |
| `file.delete` / `file.rename` | Alert / Warning | FileDelete / FileRename. Evidence removal (T0872). | `handler.go:96-99` |
| `file.invalid_name` | Notice → Alert | `fsName` rejected the name (`file.go:80-83`). Alert when it contains `..`, a leading `/`, a drive letter or NUL: a **path-traversal attempt**. | |
| `file.rejected` | Notice | Non-existent file, directory opened as a file, seek beyond the end. Feeds `access.scan`. | |
| `file.busy` | Notice | `maxOpenFiles` reached (`file.go:85,112`). | |
| `gdoi.registered` | Info | `OnRegister`: member, group, TEK SPIs (never the keys). | `gdoi/server.go:110-113` |
| `gdoi.rejected` | Warning | `OnReject`: authentication failed, unauthorised group (`Authorize`), suite not accepted. Alert for authentication failures. | `server.go:210-214` |
| `gdoi.cookie_mismatch` | Warning | Known initiator cookie from another address, or wrong responder cookie (`server.go:233-241`, dropped silently today). Hijack or confusion attempt. | new emit point |
| `gdoi.phase1_flood` | Alert | New phase-1 states above `GDOIPhase1Rate` (default 20/s), or states evicted before completing (`expire`, `server.go:270-291`). | |
| `gdoi.pull_failed` / `gdoi.rekey_failed` | Warning | Member side: registration or refresh failed; the member's KeyStore will expire and R-GOOSE/R-SV will stop. | `gdoi/member.go`, `keeper.go` |
| `gdoi.key_expiring` | Notice | Active TEK within `KeyExpiryWarning` of its lifetime with no successor. | keeper |

### 4.11 Flooding and resource (`flood.*`, `dos.*`)

Token buckets per association per class, with defaults chosen so that normal
traffic never trips them (tune in §9):

| Kind | Class / default threshold | Notes |
|------|---------------------------|-------|
| `flood.requests` | confirmed requests > 200/s burst 400 | generic |
| `flood.controls` | Oper/SBOw/Cancel > 10/s burst 20 | T0806 |
| `flood.writes` | Write requests > 50/s | |
| `flood.reads` | Read requests > 200/s | polling HMIs stay well below |
| `flood.gi` | RCB `GI` writes > 6/min per RCB | amplification: one write, a report of the whole dataset |
| `flood.discovery` | GetNameList / GetVariableAccessAttributes > 50/s after the first minute of the association | enumeration storm |
| `flood.file` | FileOpen > 10/s, or FileRead octets > `MaxFileReadRate` | |
| `flood.associations` | see `conn.rate` | |
| `dos.report_queue_full` | `ErrReportQueueFull` (`server_conn.go:712-727`) more than N times in a window | slow-reader attack or overloaded client; BufOvfl handling unchanged |
| `dos.write_stall` | write deadline hit (`server_conn.go:738-749`) | Action `Disconnected` (already the behaviour) |
| `dos.slow_frame` | partial TPKT not completed within `FrameAssemblyTimeout` (§7.3) | slowloris; Action `Disconnected` |
| `dos.dataset_limit` | dynamic dataset caps reached (`handler.go:648-660`) | |
| `dos.selection_hold` | one association holds SBO selections on more than `MaxSelections` objects, or re-selects the same object repeatedly to keep it reserved | blocks operators from controlling |
| `dos.rcb_reservation` | one association reserves or enables more than `MaxRCBsPerAssoc` RCBs, or reserves RCBs it never enables | starves other clients of report blocks (Denial of View) |

Action per class, from `Policy.FloodAction`:

- `Report` (default).
- `Throttle`. Excess requests are answered with a service error
  (`resource` class, "temporarily unavailable"); controls are refused with
  LastApplError so the client is not left hanging; the handler is not called.
- `Disconnect` (abort the association).

Never throttle Conclude, Cancel, release, or the reads an E2E rekey needs.
They are report-only.

---

## 5. Key mechanisms in detail

### 5.1 MAC lookup (`netpeer`)

Unchanged from the iec104 plan:

- `Resolver` interface: `Lookup(ctx, netip.Addr) (Neighbor, error)`,
  `Neighbor{MAC, Interface, State, Source}`. Default per GOOS via build tags;
  `netpeer.SetDefaultResolver` and `Policy.Resolver` for injection.
- **On-link decision first** (interfaces and prefixes, cached 60 s). Off-link
  peers get `MACSource=Gateway` or `None`.
- Loopback: `MACSource=None`, `OnLink=true`, `Interface="lo"` (all current tests).
- **Linux:** netlink `RTM_GETNEIGH` via `golang.org/x/sys/unix` (already a
  direct dependency, `go.mod`). Fallback `/proc/net/arp`.
- **Windows:** `GetIpNetTable2` / `ResolveIpNetEntry2` via
  `golang.org/x/sys/windows` (same module).
- **Darwin/FreeBSD:** `sysctl(NET_RT_FLAGS, RTF_LLINFO)` parsed with
  `golang.org/x/net/route` (new dependency; iec104 §12 Q4 answer: new dep).
- Lookup runs in the per-connection goroutine, bounded by `MACLookupTimeout`
  (default 200 ms), never in the accept loop. A failure never rejects unless
  pinning is configured.
- Client side: after dial.

GOOSE and SV need no resolver: the source MAC is in the frame
(`ethernet.Frame.Src`). R-GOOSE/R-SV use the resolver on the UDP source
address when it is on-link.

### 5.2 MAC/IP history cache (`netpeer.Cache`)

As in the iec104 plan (bounded LRU, TTL, optional `Save`/`Load`), with two
additions:

- the TLS leaf fingerprint and the ACSE identity per IP, for
  `tls.cert_changed` and `peer.identity_changed`;
- a second table keyed by (APPID, control reference) → source MAC and VLAN,
  for the layer-2 streams. Same bounds.

### 5.3 Connection tracker (server level)

`internal/secmon.ConnTracker` sits between `ln.Accept()` and `go
s.serveConn(raw)` (`server.go:367-373`), before the TLS handshake and before
`takeSlot`:

1. Allowlist (CIDR) → `conn.unexpected`.
2. Auth-failure block list (only with `AuthFailureAction=Block`) → `assoc.brute_force` (Action `Blocked`).
3. Per-IP and global accept-rate buckets → `conn.rate`.
4. Per-IP concurrent count → `conn.rejected_limit`. The total cap stays in
   `takeSlot`, which also emits it.
5. Then the goroutine: TLS handshake (§4.2) → MAC lookup and pinning (§5.1)
   → `mms.AcceptConnOpts`.

Counts are released in `serveConn`'s defer. `OpenConnections`, `MaxConnections`
and `OnConnection` keep their meaning.

### 5.4 Outstanding-request tracker (client)

`mms.Conn` already keeps `pending` by invoke ID, which gives `unsol.response`
for free. `client` adds a small tracker of enhanced-security operates in
progress (it already waits for the CommandTermination, `client/control.go`)
and of the RCBs this client enabled with their RptIDs (`client/report.go`),
which feed `unsol.command_termination` and `unsol.report`.

### 5.5 Control replay checks

- `internal/secmon.CheckCommandAge(T, quality, now, maxAge, maxFuture)` is
  called in `controlWrite` after `decodeOper` and before the handler. It
  ignores T = epoch (not set) and T whose quality says the clock is not
  synchronised or has failed.
- The duplicate window keys on a hash of the whole Oper/SBOw structure (as
  encoded, including T and ctlNum) and the object reference, kept for
  `DuplicateWindow` (default 60 s), bounded.
- Document that both clocks must be synchronised, and that a successful
  time-sync attack (PTP/SNTP) defeats the age check. That is one reason
  `sv.sync_lost` exists.

### 5.6 GOOSE and SV stream monitors

- Built into the existing per-subscription state: GOOSE already keeps
  `seqState` per goCbRef (`goose/subscriber.go:163-172`); it gains the source
  MAC, VLAN, ConfRev, a 64-bit hash of the last allData (FNV-1a over the
  encoded values — no decoding), and the last T. SV gains an equivalent
  per-svID state (smpCnt, ConfRev, smpSynch, source MAC). Both stay bounded
  by `MaxStreams`.
- `goose.SubscribeOptions`/`sv.SubscribeOptions` (new, additive) carry an
  optional `Expect` (ConfRev, DatSet, GoID, NumDatSetEntries, SrcMAC, VLAN)
  filled from SCL by the existing helpers (`goose/scl.go`, `sv/scl.go`) and
  `ExpectedStreams` for unfiltered subscriptions.
- Parse errors are counted per source MAC on the reader goroutine before any
  subscription matching, so `goose.parse_error` costs nothing when no
  dispatcher is attached.
- Events are emitted from the reader goroutine through the non-blocking
  emitter, never from the callback. `Anomalies` stays as it is (API), so
  applications that use it keep working.
- **Performance:** the SV path adds one map lookup (already done for
  matching), two integer compares and an atomic load per ASDU. No allocation
  per frame. Benchmark target in §9.

---

## 6. Policy / configuration surface

### 6.1 Shared struct

```
secevent.Policy {
    // Delivery
    Sink                Sink
    AggregateWindow     time.Duration
    MaxRaw              int
    RawDecrypted        bool           // include E2E-decrypted PDUs in Raw (default false)
    AuditControl        bool           // §4.7 audit events, default true when a sink is set

    // Connection
    AllowedPeers        []netip.Prefix // nil = any
    RejectUnlisted      bool
    PeerBindings        map[netip.Addr]net.HardwareAddr
    RejectBindingMismatch bool
    MaxConnectionsPerIP int            // total stays WithMaxConnections
    AcceptRate, GlobalAcceptRate Rate  // {N, Per}
    IdleTimeout         time.Duration  // 0 = off (§7.3)
    FrameAssemblyTimeout time.Duration

    // Identity and authentication
    Resolver            netpeer.Resolver
    MACCache            *netpeer.Cache
    MACLookupTimeout, MACRecheckInterval, MACHistoryTTL time.Duration
    CertExpiryWarning   time.Duration
    KnownClients        []ClientIdentity   // IP prefix and/or Calling AP-title, for access.enumeration
    AuthFailureThreshold int; AuthFailureWindow time.Duration
    AuthFailureAction   Action             // Report | Block
    AuthBlockTime       time.Duration

    // ACSI
    Services            ServicePolicy      // §6.3
    OriginBindings      []OriginBinding    // peer → allowed orCat/orIdent
    RejectOriginMismatch bool
    MaxCommandAge, MaxCommandFuture time.Duration
    RejectStaleCommands bool
    DuplicateWindow     time.Duration
    MaxItemsPerRequest  int
    MaxSelections, MaxRCBsPerAssoc int

    // Flooding
    Limits              Limits             // per-class Rate, §4.11
    FloodAction         Action             // Report | Throttle | Disconnect
    ScanThreshold       int; ScanWindow time.Duration

    // Process bus
    ExpectedStreams     []StreamExpectation
    GooseGapRate, SVGapRate Rate
    SVSupervision       time.Duration      // 0 = off
    MaxL2FrameRate      int

    // GDOI
    GDOIPhase1Rate      Rate
    KeyExpiryWarning    time.Duration
}
```

- `secevent.DefaultPolicy()` is report-only, with the thresholds of §4.11.
- `Policy.Valid()` follows the validate-then-defaults convention used by
  `e2e.Policy` (`iec62351/e2e/config.go:179-215`).

### 6.2 Setters (additive, in each package's option style)

- `server.WithSecurityPolicy(p secevent.Policy) Option`,
  `server.WithCyberEventSink(s secevent.Sink) Option` (shortcut),
  `(*Server).SecurityStats() secevent.Stats`,
  `(*Server).OnWriteCtx(...)` (§3.5). `WithSecurityPolicy` also installs the
  bridges into the server's `*tls.Config` (when built by `iec62351`),
  `e2e.ServerConfig.OnEvent` and the A-profile path, chaining any callback the
  user set rather than replacing it.
- `client.WithSecurityPolicy(p) Option`, `client.WithCyberEventSink(s) Option`,
  `(*Client).PeerInfo()`. These set new fields on `mms.Options`.
- `mms.AcceptOptions.Events` / `mms.Options.Events` (an internal emitter type
  exported through `secevent`), for users of the `mms` package without
  `server`.
- `goose.Subscriber.SetCyberEventSink(s)`, `sv.Subscriber.SetCyberEventSink(s)`,
  plus `SubscribeOptions.Expect` (§5.6).
- `rsession`, `gdoi`, `e2e`, `iec62351`: **no API change**. The user (or the
  `cmd`s) wires `secevent.RSessionRejectHook(sink)`,
  `secevent.GDOIHooks(sink)`, `secevent.E2EHook(sink)` and
  `secevent.TLSHook(sink)` into the existing callbacks. The only code change
  in those packages is the new emit points for silent drops (`rsession`
  unsecured-accepted, `gdoi` cookie mismatch), which go to the existing
  callbacks with new sentinel errors.

### 6.3 `ServicePolicy` (hardening)

An allow/deny set of MMS services plus ACSI qualifiers: `DenyServices []int`,
`ReadOnly` (deny Write, controls, DefineNVL/DeleteNVL, file write services,
InitializeJournal), `DenyControls`, `DenyFileWrite` (FileDelete, FileRename,
ObtainFile), `DenyFileRead`, `DenySettingGroupChange`, `DenyModeChange`
(`Mod` to anything but on), `DenySimulation` (`LPHD.Sim`), `DenyRCBOfOthers`
(a client may not touch RCBs another association reserved; partly enforced
today by reservation). Each rule can be scoped by peer (`KnownClients`
entry), so an engineering workstation keeps rights an HMI does not have.

A denied request gets the standard answer (access-denied, a RejectPDU for a
service, LastApplError + negative response for a control) and
`access.service_blocked`. The handler is never called.

Note: several of these overlap what an application can do in `OnWrite` /
`OnControl` / `WithAuthenticator` today. `ServicePolicy` exists so the
common cases need no code and produce the right events.

### 6.4 Stats (`secevent.Stats`)

Monotonic counters per Kind and per Category, dropped and aggregated counts,
current associations, rejected connections, and per-stream GOOSE/SV counters.
`rsession.Stats` stays and is folded in. Snapshot by value, for pull-based
monitoring (IEC 62351-7 NSM, a Prometheus exporter built by the user). No
Prometheus dependency.

---

## 7. Robustness fixes found during analysis (behaviour changes, called out)

1. **Accept loop resilience (F1).** `Server.Serve`: back off on errors that
   are not `net.ErrClosed` (5 ms doubling to 1 s, like `net/http.Server`) and
   continue; emit `conn.accept_error` (Critical). Same for
   `gdoi.Server.Serve`. `rsession.Session.read`: add the same backoff to the
   `continue` at `session.go:281`. Regression test: a fake listener / packet
   conn that fails N times.
2. **Explicit TLS handshake with deadline (F3).** Move the handshake out of
   `cotp.Accept` into `serveConn`, under the existing handshake timeout, for
   both the Go and the OpenSSL engine. Wire behaviour is unchanged; the error
   becomes classifiable and the TLS state is known before the OSI layers run.
3. **Idle timeout and frame-assembly deadline (F4).** `ServerConn.Serve` sets
   a read deadline of `IdleTimeout` (opt-in, default off: some HMIs keep a
   quiet association open for hours and only receive reports, so the timeout
   counts inbound *and* outbound activity). Separately, once the first octet
   of a TPKT is read, set `FrameAssemblyTimeout` (default 30 s, the write
   timeout's default) until the TPKT completes, then clear it. A deadline
   error mid-frame → `dos.slow_frame`, close. **This one is on by default**
   and is the behaviour change of this section.
4. **Silent drops become reported (F12, F13, F15).** No behaviour change: the
   GOOSE/SV parse errors and the GDOI cookie mismatches are still dropped,
   but counted and reported.

Each is its own commit with a test, landed *before* the event work so the
events can rely on it.

---

## 8. Model and decoding helpers

- `model.IsModeObject(ref)`, `IsSimulationObject(ref)`,
  `IsSettingGroupCB(ref)`, `IsBlockingFC(fc)`, `IsConfigurationFC(fc)`: table
  lookups by DO/DA name and FC, used by §4.7 and §6.3. Not ad-hoc switches.
- `mms.ServiceName(tag) string` for `Detail` and JSON (the tag constants
  exist in `mms` and `server/handler.go:21-36`).
- `goose.HashData(m *Message) uint64` and the SV equivalent, computed on the
  encoded allData slice the parser already holds (no re-encoding). Fuzzed
  with the existing parsers.
- Existing errors stay and gain no new wrapping, so `errors.Is` keeps working.
  New sentinels only where the event needs a stable sub-reason (e.g.
  `cotp.ErrTSDUTooLarge`, `tpkt.ErrBadLength`, `rsession.ErrUnsecuredAccepted`,
  `gdoi.ErrCookieMismatch`).

---

## 9. Performance and safety requirements

- No sink → per-frame overhead is one atomic pointer load. Detectors are not
  updated. Benchmarks: an MMS read throughput benchmark with nil and with a
  no-op `SinkFunc`, and `BenchmarkSVSubscriber` at 9-2LE 4 kHz × 8 streams
  and 14.4 kHz × 2 streams. Targets: < 2 % throughput loss with a sink on
  MMS, < 5 % added CPU on the SV reader, 0 allocations per frame on the happy
  path (events allocate only when emitted).
- Per-association buckets are owned by the association goroutine (lock-free).
  Shared structures (conn tracker, auth-failure tracker, MAC cache, duplicate
  window) use one mutex each, bounded size.
- Every detector's memory is bounded: LRU caps on aggregation keys, scan
  windows, duplicate window, stream states (`MaxStreams`, already 4096) and
  the MAC cache.
- No `Detail` is built with `fmt.Sprintf` unless the event will be emitted.
- Thresholds are validated against legitimate heavy load: `cmd/ied-client
  test` against `cmd/ied-server`, the interop suites (`interop/`,
  `mms/interop_test.go`, `client/*_interop_test.go`) and a GOOSE burst after
  a state change (`goose/retransmit_test.go`). They must produce **zero**
  events above Info.

---

## 10. Tests

| Layer | Tests |
|-------|-------|
| `secevent` | dispatcher non-blocking under a slow sink; drop accounting and `meta.events_dropped`; aggregation; always-deliver kinds; sink panic recovery; JSON stability (golden file); Kind table completeness (every Kind has Category/Severity); bridges from `e2e.Event`, `iec62351.Event`, `rsession.Reject`, GDOI callbacks |
| `netpeer` | netlink parser on canned bytes; `/proc/net/arp` parser; on-link logic with synthetic interfaces; Windows/Darwin parsers (build-tagged); cache change detection, TTL, LRU, persistence; fake Resolver |
| `internal/secmon` | token bucket; sliding distinct counter; auth-failure tracker; duplicate window; command age incl. T = 0 and unsynchronised quality |
| server socket tests (style of `server/connections_test.go`, `mms/refuse_abort_test.go`) | connect without data → `conn.no_data`; allowlist; per-IP limit; accept rate; handshake timeout → `conn.never_associated`; idle timeout; slow TPKT → `dos.slow_frame`; client that stops reading → `dos.write_stall`; each setup stage malformed → `assoc.setup_failed{Stage}`; wrong password ×N → `assoc.auth_failed` then `assoc.brute_force`; A-profile failure; E2E required; RejectPDU cases; unrecognized service; reads of non-existent names → `access.scan`; write to ST → `access.denied`; each `ctrl.*` (Mod, Sim, ActSG, EditSG/CnfEdit, CF write, LogEna, InitializeJournal); controls: refused, operate without select, test on enhanced, stale T (reject on/off), duplicate Oper over a second association; file directory/read/obtain/delete, `..` name |
| TLS (certs generated in-test, as `iec62351/tls_test.go` does) | unknown CA, expired, revoked, stale CRL, no client cert, plaintext on TLS port (TPKT header), HTTP probe, handshake timeout; the same set on the OpenSSL engine under the `openssl` build tag |
| client | response for unknown invoke ID; report with unknown RptID; CommandTermination without operate; server certificate rejected |
| GOOSE/SV (with `ethernet.Pipe`) | parse error; stNum regress, jump, duplicate; data change without stNum; time regress; ConfRev/DatSet mismatch; source MAC change; simulated frame dropped; untracked stream; flood; SV smpCnt gap/duplicate/regress, smpSynch loss, stream lost; all of it again over an `rsession.Session` pair |
| rsession / gdoi | each `OnReject` error → its Kind; unsecured accepted; GDOI cookie mismatch; phase-1 flood and eviction |
| MAC end-to-end | Linux-only, skipped unless `IEC61850_NETNS=1` and root: veth pair in a netns, connect, assert MAC; change the veth MAC, reconnect → `peer.mac_changed` |
| Regression | `go test -race ./...`; the interop suites must stay green with **policy unset and with DefaultPolicy+sink**: proves no wire-behaviour change apart from §7 |
| Fuzz | existing fuzzers (`internal/osi/*/fuzz_test.go`, `iec62351/e2e/fuzz_test.go`) plus new ones for `goose.Parse`, `sv.Parse` and `rsession.Unmarshal`, run with a sink attached: every malformed input yields an event and never a panic or a blocked goroutine |

---

## 11. Phased delivery (each phase = one PR, green CI)

| Phase | Content | Depends |
|-------|---------|---------|
| **P0** | Agree on open questions (§12); freeze Kind names (`kinds.go` + doc table) | — |
| **P1** | §7 robustness fixes (accept loop in server and gdoi, rsession read backoff, explicit TLS handshake, frame-assembly deadline, opt-in idle timeout). Behaviour change, called out. | — |
| **P2** | `secevent` core: Event, Kinds table, Dispatcher, sinks, Reporter/Report, Stats, Policy skeleton; emitter in `mms.ServerConn` and `server.Server`; `conn.accepted/closed/no_data/never_associated/accept_error/rejected_limit`, `assoc.established/setup_failed` | P1 |
| **P3** | `netpeer` Linux + cache; `PeerInfo` accessors; `peer.*`; pinning; mid-session re-check | P2 |
| **P4** | Connection policy (allowlist, per-IP limits, rates); TLS classification and `tls.*` for both engines; bridge of `iec62351.Options.OnEvent` | P2 |
| **P5** | Association and authentication: `assoc.*`, brute-force tracker, `e2e.*` bridge, `peer.identity_changed` | P2 |
| **P6** | MMS/ACSI layer: `proto.*`, outbound-result observation, `access.*` incl. scan and enumeration, `ServicePolicy`, `OnWriteCtx` | P5 |
| **P7** | Control and configuration audit: `cmd.*` incl. stale T and duplicate Oper, `ctrl.*`, model helper tables | P6 |
| **P8** | Flood detectors and actions, `dos.*` | P6 |
| **P9** | MMS client: `unsol.*`, `remote.rejected`, client TLS events | P6 |
| **P10** | GOOSE and SV stream monitors, `SubscribeOptions.Expect`, SCL-driven expectations, benchmarks | P2 |
| **P11** | R-GOOSE/R-SV and GDOI: bridges, new emit points for silent drops, `gdoi.phase1_flood`, key expiry | P10 |
| **P12** | File services: `file.*` | P6 |
| **P13** | `netpeer` Windows and Darwin/BSD backends | P3 |
| **P14** | Docs: new `docs/security-events.md` (event catalogue = §4 tables, policy guide, MAC caveats, IEC 62351-14 mapping, deployment guidance: IEC 62351-3 TLS, E2E, A-profile, R-GOOSE keys from GDOI, firewalling, SYN cookies, process-bus VLANs and storm control, what the library cannot see); updates to `docs/api.md`, `docs/developer-guide.md`, `docs/pics.md` (security-related PICS lines), `SKILL.md`, `README.md`. `cmd/ied-server` gets `-events FILE` (JSON lines) and policy flags; `cmd/goose-sniff` prints `goose.*`/`sv.*` events; `iedx` gets an optional events pane. | all |

Rough size: P2–P8 are the bulk (~4–5 k lines including tests). Each later
phase is ≤ 1 k.

---

## 12. Open questions (decisions needed before P2)

Carried over from the iec104 plan, with the answers given there unless the
question changes for IEC 61850:

1. **Package names:** split packages `secevent` + `netpeer` + `internal/secmon`.
   *Answer (iec104): split packages.*
2. **`OnWrite` has no connection (§3.5).** Add `OnWriteCtx` beside it
   (proposed), or change `OnWrite`'s signature (breaking)? *Answer:
   non-breaking (`OnWriteCtx` beside `OnWrite`).*
3. **Defaults when a sink is set:** report only. *Answer (iec104): report only.*
   The frame-assembly deadline of §7.3 is a robustness fix, not an
   enforcement, and is on regardless.
4. **`conn.accepted` for every connection:** Info. *Answer (iec104): Info.*
5. **Darwin/BSD MAC backend:** `golang.org/x/net/route` as a new dependency.
   *Answer (iec104): new dep.*
6. **Output formats:** JSON lines. *Answer (iec104): JSON.*
7. **Existing hooks (`iec62351.Options.OnEvent`, `e2e` `OnEvent`,
   `rsession.Config.OnReject`, `gdoi` callbacks, `server.OnConnection`):** keep
   them and bridge (proposed), or deprecate them in favour of the sink?
   *Answer: keep and bridge.*
8. **Idle timeout default:** off (proposed), or on with a long value (e.g.
   10 min with report traffic counting as activity)? *Answer: off.*
9. **Event sink delivery:** one dispatcher per endpoint unless the user shares
   one. *Answer (iec104): proposed.* For an IED process the documented set-up
   is one shared dispatcher for the Server, its GOOSE/SV subscribers and its
   R-sessions.
10. **IEC 62351-14 identifiers:** fill `Std62351` only where the standard has
    a matching identifier (proposed), or also define library-specific
    extension identifiers in its private range? *Answer: all — standard
    identifiers where they exist, library extension identifiers for every
    other Kind, so every event carries one.*
