# Protocol Implementation Conformance Statement (PICS)

**Implementation:** go-iec61850, `github.com/dscsystems/go-iec61850`
**Kind:** library — an IEC 61850 client, server, GOOSE and sampled-value
publisher and subscriber, and SCL loader, for applications to build on.
**Version described:** the tree this document is committed with.
**Standards targeted:** IEC 61850 Edition 2 with Amendment 1 ("Edition
2.1"): 7-2 (2007B5), 7-3, 7-4, 8-1, 9-2, and SCL 2007B4 (IEC 61850-6);
IEC 61850-90-5, IEC 62351-3 and IEC 62351-9 for security.

This statement follows the structure of the ACSI conformance statement of
IEC 61850-7-2 Annex A — basic conformance, models, services — and adds the
IEC 61850-8-1 mapping, GOOSE, sampled values, security, and the
implementation-specific information a tester asks for. Rows are named by
the ACSI model and service names; the numeric row codes of the Annex A
tables are not repeated, as they differ between editions and templates.

It is a statement about the library, not about a device. A device built
on it inherits these capabilities and adds its own model, limits and
policies, and has to state its own PICS, MICS, PIXIT and TICS; the
"Server" column is what such a device can offer, and the options that
govern it are named. Nothing here has been assessed by a certified test
laboratory. Each "Y" is backed by the tests of this repository, and the
interoperability runs of `interop/` against libiec61850 1.6.
`docs/edition-2.1.md` is the detailed conformance record, and says why
each gap is one.

### Legend

| Mark | Meaning |
|---|---|
| **Y** | Supported |
| **N** | Not supported |
| **P** | Partly supported — see the note |
| **—** | Not applicable to this role |
| (g) | Available through the generic read and write of the client (`Client.Read`, `Client.Write`) on the control block's attributes, rather than a dedicated call |

## 1. Basic conformance

| Item | Client / subscriber | Server / publisher | Notes |
|---|---|---|---|
| Client side of two-party application association | Y | — | package `client` |
| Server side of two-party application association | — | Y | package `server` |
| SCSM: IEC 61850-8-1 (MMS) | Y | Y | |
| SCSM: IEC 61850-9-2 (sampled values) | Y | Y | 9-2LE dataset layout; see 6 |
| SCSM: IEC 61850-9-1 | N | N | withdrawn |
| GSE model: GOOSE | Y (subscriber) | Y (publisher) | package `goose`; not driven by the server's GoCB, see 5 |
| GSE model: GSSE | N | N | withdrawn in Ed 2; a GSSE control block loads from SCL and is served as a GsCB object. The GSSE message has no public reference to verify an encoding against, see 9 |
| Sampled values: multicast | Y (subscriber) | Y (publisher) | package `sv`; the server reports MSVCB SvEna for the application to publish on, see 6 |
| Sampled values: unicast | Y (subscriber) | Y (publisher) | package `sv`, to an individual MAC, or over R-SV to the block's IP; the server runs USVCB reservation, see 6 |
| Routable GOOSE / SV (IEC 61850-90-5) | Y | Y | package `rsession`; see 8 |

## 2. ACSI models

| Model | Client | Server | Notes |
|---|---|---|---|
| Server | Y | Y | |
| Association (two-party) | Y | Y | ACSE password and TLS; see 3.1 |
| Logical device | Y | Y | |
| Logical node | Y | Y | 7-4 classes: `model.NewLogicalNode`, `Model.CheckLNClasses` |
| Data | Y | Y | 7-3 classes of Ed 2 and 2.1: `model.NewDataObject` |
| Data set | Y | Y | static (SCL) and dynamic, see 3.4 |
| Substitution | Y (g) | P | the SV attributes are writable by default; the server does not substitute the value or set the quality's source — the application does |
| Setting group control | Y | Y | `server.WithSettingGroups` |
| Buffered report control | Y | Y | |
| Unbuffered report control | Y | Y | |
| Log control | Y | Y | |
| Log | Y | Y | in memory, `server.WithLogCapacity` |
| GOOSE control (GoCB) | Y (g) | P | served read-only; see 5 |
| GSSE control | N | P | served read-only |
| Multicast sampled value control (MSVCB) | Y | Y | `Client.EnableSVCB`; `Server.OnSVControl` |
| Unicast sampled value control (USVCB) | Y | Y | `Client.ReserveUSVCB`, `Client.EnableSVCB`; `Server.OnSVControl` |
| Control | Y | Y | all four control models |
| Time and time synchronisation | P | P | time quality set by the application; no time synchronisation protocol |
| File transfer | Y | Y | writing needs a writable store; see 3.9 |
| Service tracking (LTRK, 7-2 Ed 2) | Y (g) | Y | the server records each control and control block service in its LTRK (see 9); compared with libiec61850's service tracking server |

### 2.1 Reporting and logging options

| Option | Client | Server | Notes |
|---|---|---|---|
| Sequence number | Y | Y | |
| Report time stamp | Y | Y | |
| Reason for inclusion | Y | Y | |
| Data set name | Y | Y | |
| Data reference | Y | Y | |
| Buffer overflow | Y | Y | |
| EntryID | Y | Y | server-wide monotonic identifiers |
| Configuration revision | Y | Y | |
| Segmentation | P | Y | the server segments a report that does not fit the negotiated PDU; the client delivers each segment with `SubSeqNum` and `MoreFollows` and does not reassemble |
| Trigger: data change (dchg) | Y | Y | |
| Trigger: quality change (qchg) | Y | Y | |
| Trigger: data update (dupd) | Y | Y | |
| Trigger: integrity (IntgPd) | Y | Y | |
| Trigger: general interrogation | Y | Y | |
| BufTm | Y | Y | |
| Resynchronisation of a BRCB by EntryID | Y | Y | |
| PurgeBuf | Y (g) | Y | |
| Reservation: Resv (URCB) | Y (g) | Y | |
| Reservation: ResvTms (BRCB, Ed 2) | Y (g) | Y | |
| Reservation by `ClientLN` (SCL) | — | Y | enforced by client IP address |
| Owner | Y (g) | Y | |
| Log: integrity period | — | Y | |

### 2.2 Control options

| Option | Client | Server | Notes |
|---|---|---|---|
| status-only | Y | Y | |
| direct-with-normal-security | Y | Y | |
| sbo-with-normal-security | Y | Y | SBO timeout from `sboTimeout`, else 30 s |
| direct-with-enhanced-security | Y | Y | CommandTermination |
| sbo-with-enhanced-security | Y | Y | |
| Originator (orCat, orIdent) | Y | Y | |
| ctlNum | Y | Y | |
| Test | Y | Y | |
| Interlock-check, synchro-check | Y | Y | the server passes them to the application's `ControlHandler` |
| LastApplError with AddCause | Y | Y | |
| Time-activated operate (operTm) | N | N | |

## 3. ACSI services

### 3.1 Server and association

| Service | Client | Server | Notes |
|---|---|---|---|
| GetServerDirectory (LOGICAL-DEVICE) | Y | Y | MMS GetNameList of domains |
| GetServerDirectory (FILE) | Y | P | only with `server.WithFileStore` |
| Associate | Y | Y | |
| Abort | Y | Y | ACSE A-ABORT in a presentation ARU in a session ABORT |
| Release | Y | Y | MMS Conclude |
| Authentication: password (ACSE) | Y | Y | `server.WithPassword`, or `server.WithAuthenticator` for the application's own decision (it also sees the ACSE identities and the TLS peer certificates); a refusal is an ACSE rejection with the diagnostic authentication-failure or authentication-required, reported to the client as `mms.RejectedError` |
| Authentication: certificates (IEC 62351-4 native mode, E2E) | Y | Y | signed handshake (`client.WithE2E`, `server.WithE2E`); the authenticated peer is in `AssociationRequest.Security`; see section 8.1 |
| Authentication: certificates (IEC 62351-4 A-profile, compatibility mode) | Y | Y | `client.WithAProfile`, `server.WithAProfile` (package `iec62351/aprofile`); the client certificate is in `AssociationRequest.AProfile`, the server's in `Conn.PeerAProfileCertificate`; see section 8.1 |

### 3.2 Logical device and logical node

| Service | Client | Server | Notes |
|---|---|---|---|
| GetLogicalDeviceDirectory | Y | Y | |
| GetLogicalNodeDirectory | Y | Y | by ACSI class, derived from the functional constraint |
| GetAllDataValues | Y | Y | per functional constraint (`LN$FC`) |

### 3.3 Data

| Service | Client | Server | Notes |
|---|---|---|---|
| GetDataValues | Y | Y | |
| SetDataValues | Y | Y | writable FCs SP, SV and SE by default (`server.WithWritableFCs`); `OnWrite` may refuse; SE only while a group is being edited |
| GetDataDirectory | Y | Y | |
| GetDataDefinition | Y | Y | MMS GetVariableAccessAttributes |

### 3.4 Data set

| Service | Client | Server | Notes |
|---|---|---|---|
| GetDataSetValues | Y | Y | |
| SetDataSetValues | N | N | |
| CreateDataSet (persistent, domain-specific) | Y | Y | held in memory; lost at restart |
| CreateDataSet (non-persistent, association-specific) | N | N | |
| DeleteDataSet | Y | Y | a data set configured in SCL, or one a control block refers to, is not deleted; the client reports the refusal (`mms.ErrNotDeleted`) |
| GetDataSetDirectory | Y | Y | MMS GetNamedVariableListAttributes |

### 3.5 Setting group control

| Service | Client | Server | Notes |
|---|---|---|---|
| SelectActiveSG | Y | Y | |
| SelectEditSG | Y | Y | |
| SetEditSGValue | Y | Y | |
| ConfirmEditSGValues | Y | Y | |
| GetEditSGValue | Y | Y | |
| GetSGCBValues | Y | Y | |

### 3.6 Reporting and logging

| Service | Client | Server | Notes |
|---|---|---|---|
| Report | Y | Y | MMS InformationReport |
| GetBRCBValues | Y | Y | |
| SetBRCBValues | Y | Y | |
| GetURCBValues | Y | Y | |
| SetURCBValues | Y | Y | |
| GetLCBValues | Y (g) | Y | |
| SetLCBValues | Y (g) | P | LogEna is writable; the rest of the block is configured by SCL |
| QueryLogByTime | Y | Y | MMS ReadJournal |
| QueryLogAfter | Y | Y | MMS ReadJournal |
| GetLogStatusValues | Y (g) | Y | the LCB's OldEntrTm, NewEntrTm, OldEnt, NewEnt |

### 3.7 GOOSE and sampled value control blocks

| Service | Client | Server | Notes |
|---|---|---|---|
| SendGOOSEMessage | Y (receive) | Y (send) | package `goose` |
| GetGoReference | N | N | |
| GetGOOSEElementNumber | N | N | |
| GetGoCBValues | Y (g) | Y | |
| SetGoCBValues | Y (g) | N | the GoCB is served read-only |
| GSSE services | N | N | |
| SendMSVMessage | Y (receive) | Y (send) | package `sv` |
| GetMSVCBValues | Y | Y | `Client.GetSVCB` |
| SetMSVCBValues | Y | P | SvEna; the rest is configuration, as in the 9-2 mapping |
| SendUSVMessage | Y (receive) | Y (send) | package `sv` |
| GetUSVCBValues | Y | Y | `Client.GetSVCB`, which tells a USVCB from an MSVCB by its FC |
| SetUSVCBValues | Y | P | Resv and SvEna; the rest is configuration, as in the 9-2 mapping. A reservation is exclusive to one association and ends with it, disabling the block |

### 3.8 Control

| Service | Client | Server | Notes |
|---|---|---|---|
| Select | Y | Y | |
| SelectWithValue | Y | Y | |
| Cancel | Y | Y | |
| Operate | Y | Y | |
| CommandTermination | Y | Y | positive and negative |
| TimeActivatedOperate | N | N | |

### 3.9 File transfer

| Service | Client | Server | Notes |
|---|---|---|---|
| GetFile | Y | Y | streamed; server needs `server.WithFileStore` |
| SetFile | Y | Y | MMS ObtainFile: the server reads the file back from the client; server needs a writable store (`server.DirFS`); an existing file is not overwritten |
| DeleteFile | Y | Y | server needs a writable store |
| GetFileAttributeValues | Y | Y | MMS FileDirectory |

## 4. IEC 61850-8-1 mapping (MMS)

### 4.1 MMS services

The server advertises in its Initiate response exactly the services it
implements: the journal services only when the model has logs
(InitializeJournal only with `server.WithDeletableLogs`), the file
services only with a file store, and FileDelete and ObtainFile only with
a writable one.

| MMS service | Client (requests) | Server (responds) |
|---|---|---|
| Initiate | Y | Y |
| Conclude | Y | Y |
| Abort (ACSE, session) | Y | Y |
| Reject | Y | Y |
| Identify | Y | Y |
| GetNameList | Y | Y |
| Read | Y | Y |
| Write | Y | Y |
| GetVariableAccessAttributes | Y | Y |
| InformationReport (unconfirmed) | Y (receives) | Y (sends) |
| DefineNamedVariableList | Y | Y |
| DeleteNamedVariableList | Y | Y |
| GetNamedVariableListAttributes | Y | Y |
| ReadJournal | Y | Y |
| InitializeJournal | Y | Y (with `WithDeletableLogs`) |
| ReportJournalStatus | Y | Y |
| FileOpen | Y | Y (and answers them during ObtainFile) |
| FileRead | Y | Y (likewise) |
| FileClose | Y | Y (likewise) |
| FileDirectory | Y | Y |
| FileDelete | Y | Y |
| ObtainFile | Y | Y |
| FileRename | Y | Y (with a store that is a `server.RenameFS`, as `server.DirFS` is; never over an existing file) |
| Status | Y | Y |
| Cancel (MMS) | Y | Y (a request still running, an ObtainFile, is cancelled; one already answered is reported as unknown) |

### 4.2 MMS parameters

| Parameter | Value |
|---|---|
| Parameter CBB proposed | str1, str2, vnam, valt, vlis (the set 8-1 makes mandatory); the negotiated set is the intersection with the peer's |
| Maximum PDU size | 65001 octets proposed; the negotiated value limits every response, and reports are segmented to it |
| Maximum outstanding requests | 10 (server); the client uses what the server grants |
| Data structure nesting level | 10 |
| Application context | MMS; the ACSI context is accepted from a peer and proposed with `client.WithApplicationContext` |
| Presentation contexts | negotiated by identifier |
| Object name scopes | domain-specific and VMD-specific; not association-specific |
| Floating point | FLOAT32 and FLOAT64 |
| Time types | UtcTime with time quality, BinaryTime (EntryTime), GeneralizedTime |
| TCP port | 102; 3782 for MMS over TLS (the application chooses) |

### 4.3 Data model mapping

| Item | Supported | Notes |
|---|---|---|
| Functional constraints of Ed 2 | Y | ST, MX, CO, SP, SG, SE, SV, CF, DC, EX, OR, BL, RP, BR, LG, GO, GS, MS, US, SR |
| Unknown functional constraint from SCL | Y | carried verbatim and readable under it |
| Data object arrays (SDO count) | Y | instances `Name(n)` |
| Attribute arrays, including arrays of structures | Y | |
| PhyComAddr as the 8-1 structure | Y | |
| Quality, Timestamp with time quality, Dbpos, Tcmd, Check, TrgOps, OptFlds | Y | |

## 5. GOOSE (IEC 61850-8-1)

| Feature | Subscriber | Publisher | Notes |
|---|---|---|---|
| goosePdu encoding and decoding, Ed 2 fields | Y | Y | goID always sent; accepted absent from an Ed 1 publisher |
| Retransmission, MinTime/MaxTime from SCL | — | Y | `RetransFromSCL` |
| timeAllowedToLive supervision | Y | Y | `SubscribeSupervised` |
| stNum/sqNum rules, rollover to 1 | Y | Y | |
| test, ndsCom | Y | Y | |
| Simulation bit (Reserved 1) | N | N | not in `goose.Message`; over R-GOOSE the session payload carries it (`rsession.Payload.Simulation`) |
| Time quality of `t` | Y | Y | |
| VLAN tag | Y | Y | |
| Frame too large for one Ethernet frame | — | Y | refused with `ErrFrameTooLarge` |
| Fixed-offset encoding | N | N | `fixedOffs` is loaded and reported |
| TLV (tagged) allData | N | N | |
| Publishing driven by the server's GoCB (GoEna) | — | N | the application runs the publisher; `NewPublisherFromModel` configures it from the model |
| Layer-2 security (IEC 62351-6) | N | N | |
| Transport | Linux AF_PACKET; any `ethernet.Interface`; R-GOOSE over UDP (8) |

## 6. Sampled values (IEC 61850-9-2)

| Feature | Subscriber | Publisher | Notes |
|---|---|---|---|
| savPdu and ASDU encoding and decoding | Y | Y | multi-ASDU |
| smpMod, smpRate, refrTm, datSet, gmIdentity (Amd 1) | Y | Y | sent only as `SmvOpts` asks |
| refrTm time quality | Y | Y | |
| 9-2LE PhsMeas1 dataset and quality word | Y | Y | |
| Other dataset layouts | P | N | raw sample bytes |
| SmvOpts timestamp | N | N | |
| SmvOpts security (on Ethernet) | N | N | refused by the publisher |
| Unicast SV | Y | Y | `NewLEPublisherFromModel` sends a USVCB's stream to its individual DstAddress, or over R-SV through an `rsession.Session` to its IP |
| Publishing driven by the server's MSVCB / USVCB | — | P | the server reports SvEna and Resv through `Server.OnSVControl`; the application starts and stops the publisher, since it owns the samples and the clock |

## 7. SCL (IEC 61850-6)

| Feature | Supported | Notes |
|---|---|---|
| ICD, CID, SCD loading into a runtime model | Y | |
| SCL 2003, 2007B through 2007B4 | Y | 2007C5 (Ed 2.2) is recognised; its new elements are not interpreted and are listed by `SCL.Dropped` |
| Permissive loading with diagnostics; `Strict` option | Y | |
| DataTypeTemplates, DOI/SDI/DAI values, `sAddr`, `ix`, `Val@sGroup` | Y | |
| ReportControl, LogControl, GSEControl, SampledValueControl, SettingControl | Y | |
| ClientLN reservations | Y | |
| Communication: GSE/SMV addresses, R-GOOSE/R-SV IP destination | Y | |
| Substation section, Inputs/ExtRef resolution | N | decoded, not instantiated |

## 8. Security

| Feature | Client / subscriber | Server / publisher | Notes |
|---|---|---|---|
| MMS over TLS, IEC 62351-3 profile | Y | Y | package `iec62351`; TLS 1.2 (ECDHE AES-GCM) and 1.3; mutual certificates; CRLs; key strength; pinning |
| TLS session key renewal | N | N | |
| IEC 62351-3 Table 1 DHE_RSA suites (0x009E; 0x009F after Part 3 TISSUE 79) | N | N | not implemented by Go `crypto/tls` |
| Trusted CA indication, `trusted_ca_keys` (Part 3 7.5.3, TISSUE 58) | N | N | Go `crypto/tls` neither sends the extension nor answers it in the ServerHello |
| OCSP, including a response without nextUpdate (Part 3 TISSUE 99) | N | N | CRLs only |
| Disallowed-cipher alarm `TLS_DISALLOWED_CIPHER` (Part 3 7.3; alarm level per TISSUE 88) | N | N | a handshake with no common suite fails inside `crypto/tls` before the profile sees it; peers refused by the certificate checks are reported (`Options.OnEvent`) |
| R-GOOSE / R-SV session protocol (IEC 61850-90-5) | Y | Y | package `rsession`; UDP unicast and multicast, IPv4 and IPv6; protocol versions 1 and 2 |
| SPDU authentication HMAC-SHA256-80/128/256 | Y | Y | |
| SPDU encryption AES-128-GCM, AES-256-GCM | Y | Y | |
| SPDU authentication AES-GMAC | N | N | |
| Replay protection, refusal of unsecured SPDUs | Y | — | |
| Group key distribution, IEC 62351-9 (GDOI, RFC 6407/8052) | Y (member) | Y (key server) | package `gdoi`; GROUPKEY-PULL with IKEv1 main mode, certificates or pre-shared key |
| GDOI GROUPKEY-PUSH | N | N | members re-register |
| IEC 62351-9 TISSUEs (none in force; accepted or editorial) | — | — | 121: auth values 2 = HMAC-SHA256-128, 3 = HMAC-SHA256, as implemented. 149: HASH(2)–(4) take Ni_b/Nr_b without the payload header, as implemented. 170: TEK integrity and encryption keys are drawn independently, as implemented. 123: a member whose HASH check fails sends nothing to the key server, as implemented. 169: `61850_UDP_Tunnel` moves to 1.0.62351.9.61850.8.1.3 (group OIDs are the application's). 168 (open): a fresh, clear 16-octet IV per message would replace the RFC 2409 IV chaining implemented here; not adopted until published. 160: HMAC-SHA-384/512 (auth 6/7) not implemented |
| IEC 62351-4 E2E security, native mode (OSI) | Y | Y | packages `iec62351/e2e`, `iec62351/e2e/osi`; see 8.1 for the declared profile |
| IEC 62351-4 A-profile (compatibility mode) | Y | Y | package `iec62351/aprofile`; see 8.1 |
| IEC 62351-4 native-mode TLS profile (Table 10) | P | P | `iec62351.Options.NativeMode` on crypto/tls, or on OpenSSL with package `iec62351/ossltls` (build tag `openssl`, cgo), which adds DHE_RSA, and on OpenSSL 1.0.2 (tags `openssl,openssl_v1`) the static DH_RSA suites; see 8.1 |
| IEC 62351-6 on Ethernet | N | N | |
| IEC 62351-8 role-based access control | N | N | the server offers write and control hooks (`OnWrite`, `OnControl`) for an application's own policy |

### 8.1 IEC 62351-4 declaration

IEC 62351-4:2018+AMD1:2020 conformance tables (clause 17), as implemented. Design, interpretations and the register of open items: [iec62351-4-implementation-guide.md](iec62351-4-implementation-guide.md).

| Table / row | Client | Server | Notes |
|---|---|---|---|
| T6 OSI operational environment | Y | Y | |
| T6 XMPP operational environment | N | N | |
| T7 Compatibility mode | Y | Y | A-profile (clause 11): certificate, time and RSASSA-PKCS1-v1_5 SHA-256 signature over the time's content octets in the ACSE authentication value; 10-minute window and per-certificate replay cache; P-ABORT on a failed check, AARE rejection for a missing mechanism-name (server), ABRT authentication-mechanism-name-required (client). Sends version1-mechanism 1.0.62351.4.3.1, or the 2007 1.0.840.0.1.0.1.1 (`Config.Mechanism`); accepts any. A server echoes the client's mechanism-name. The mmsAuthenticationAS presentation context is not proposed, and the indirect-reference is omitted unless configured (11.1.4.4 tolerance). The profile requires TLS (7.1 a)); `Config.AllowWithoutTLS` relaxes that for lab devices |
| T7 Native mode | Y | Y | |
| T8 compatibility suite (m): TLS_DHE_DSS_WITH_AES_128_CBC_SHA 0x0032 after Part 4 TISSUE 129 (printed 0x0030) | N | N | DSS is not implemented by Go `crypto/tls` |
| T9 Use of authenticated encryption | N | N | not built (WP9). TISSUE 95 makes AE and non-AE mandatory for a server, so server conformance to Table 9 is not claimed (R-32) |
| T9 Non-use of AE | Y | Y | clear transfer; E2E encryption (AES-CBC) not yet implemented |
| T10 TLS_RSA_WITH_AES_128_CBC_SHA256 0x003C (m) | Y | Y | `NativeMode`, both engines; offered last (no forward secrecy) |
| T10 TLS_DH_RSA_WITH_AES_128_GCM_SHA256 0x00A0 (m) | Y | Y | static DH, likewise the optional 0x00A1 and 0x0031: only in a build against OpenSSL 1.0.2 (tags `openssl,openssl_v1`); not implemented by Go, and removed from OpenSSL in 1.1.0. A server needs a PKCS #3 DH certificate (`ossltls.Context.SetStaticDH`); offered after the forward-secret suites, before 0x003C |
| T10 TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 0x009E (m; printed 0xC0,0x9E) | Y | Y | OpenSSL engine only (`ossltls`, `ied-client -tls-openssl`); not implemented by Go crypto/tls. Group from `SSL_CTX_set_dh_auto` (2048-bit or larger) |
| T10 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xC02B (m; printed 0xC0,0x23) | Y | Y | |
| T10 ECDHE_RSA AES-128/256-GCM, ECDHE_ECDSA AES-256-GCM (o) | Y | Y | AES-256 printed 0xC0,0x24, IANA 0xC02C. Both engines prefer forward-secret suites: ECDHE, then DHE, then RSA key exchange |
| TLS renegotiation ([B] 6.2.4) | N | N | not implemented by Go; refused by the OpenSSL engine (`SSL_OP_NO_RENEGOTIATION`; on OpenSSL 1.0.2, which lacks it, the connection is dropped, `ossltls.ErrRenegotiation`); E2E rekeys at the application layer |
| T11 rsaEncryption, secp256r1 | Y | Y | |
| T11 brainpoolP256r1 (m) | N | N | not supported by Go `crypto/x509` |
| T11 sha256WithRSAEncryption, ecdsa-with-SHA256 | Y | Y | |
| T11 aes128-CBC, aes256-CBC (c[5]) | i | i | encryption not declared |
| T11 aes128-GCM, aes256-GCM as AE (c[6]) | i | i | AE not declared |
| T11 ICV hmacWithSHA256, aes128-GMAC, aes256-GMAC (c[7]) | Y | Y | 12-octet tag; sent as id-aes128-GMAC / id-aes256-GMAC (TISSUE 52), the earlier aesNNN-GCM identifiers also accepted |
| Diffie-Hellman groups 14, 23 | Y | Y | 28 (brainpool) N |
| Rekey (client-driven, server request) | Y | Y | 15 min to 24 h; idle associations carry it with an Identify request |
| Signed release, aborts (HandshakeSecReject/Abort, DtSecAbort, ApplAbort) | Y | Y | |
| Attribute certificates (IEC 62351-8) | N | N | ignored (TISSUE 97); refused with invalid-attribute-certificate when `Policy.RequireAuthorization` is set |
| OCSP | N | N | CRLs only |
| E2E certificate subject | Y | Y | X.520 `objectIdentifier` (2.5.4.106) holding the AE title; other OID-valued attributes only with `Policy.AcceptAnyAEAttributeType` |
| Published corrections (TISSUEs in force through 57/2901/INF, 16 July 2026) | Y | Y | default: 94 (handshake diagnostics renumbered), 52, 53/55, 90, 97; `Policy.Corrections = CorrectionsNone` for AMD1 as printed. See the guide, 19.6 |
| First-edition wire format (IEC 62351-4:2018 code component) | Y | Y | `Policy.Edition = e2e.Edition2018` (ClearToken1 layout, bare-OID algorithm lists, ApplData without the EXTERNAL); the default is AMD1:2020 |

## 9. Implementation-specific information

| Item | Value |
|---|---|
| Maximum client associations | unlimited by default; `server.WithMaxConnections` |
| Buffered report capacity | 256 reports per BRCB while no client is enabled; `server.WithReportBufferSize` or SCL `bufDepth` |
| Log capacity | `server.WithLogCapacity`; logs are in memory and start empty |
| Number of setting groups | `server.WithSettingGroups` |
| SBO timeout | the object's `sboTimeout`, else 30 s |
| Writable functional constraints | SP, SV, SE by default; `server.WithWritableFCs` (ST, MX, OR, EX and SG are never writable) |
| Identity (Identify service) | `server.WithIdentity` |
| Time source | the host clock; quality stated with `Server.SetTimeQuality` |
| File store | any `fs.FS` given to `server.WithFileStore`; read-write when it is a `server.WritableFS` (`server.DirFS`) |
| SetFile limits | 256 MiB per file; 2 minutes for the client to serve it |
| Association authentication | none by default; `server.WithPassword`, `server.WithAuthenticator` |
| Log deletion by clients | refused by default; `server.WithDeletableLogs` |
| Status service answer | state-changes-allowed, operational; `Server.SetStatus` |
| Dynamic data sets | persistent (domain-specific) names, kept in memory; deletable by clients; configured ones are not |
| Platforms | pure Go, no cgo; raw Ethernet on Linux (AF_PACKET) |
| Service tracking | an LTRK in the addressed object's device, else the server's first, records: Select, SelectWithValue, Operate, Cancel and CommandTermination in the tracking object of the control's CDC (SpcTrk … BacTrk); SetBRCBValues, SetURCBValues, SetLCBValues, SetGoCBValues, SetMSVCBValues and SetUSVCBValues, one per attribute written, refused or not; SelectActiveSG, SelectEditSG and ConfirmEditSGValues. The block's state is copied after the service (a report block's written attribute with the value asked for), references in ACSI notation, and data access errors mapped to service errors as libiec61850 maps them. objRef raises data-update, so a data set holding a tracking object reports every service |
| Setting group control block | served for a device with SG/SE settings, or one whose SCL declares a SettingControl |
| Sampled-value control blocks | SvEna and, on a USVCB, Resv are writable; a reserved USVCB refuses other associations with temporarily-unavailable and is released and disabled when its association ends; the application publishes on `Server.OnSVControl` |
| GSSE | not implemented. GSSE (IEC 61850-8-1 Ed 1, from UCA 2.0) was withdrawn in Edition 2; its message is not in any public specification, and neither libiec61850 nor Wireshark decodes it, so there is nothing to verify an encoding against |

## 10. Verification

- `go test -race ./...` covers every "Y" above.
- `interop/run.sh` runs the client against libiec61850's servers and
  libiec61850's clients against the server (MMS, control, logs, TLS), and
  R-GOOSE and R-SV both ways in every security mode both implement, and
  the association and file services (authentication, Status, SetFile,
  DeleteFile, fileRename, release, abort) both ways, and libiec61850's
  `ClientSVControlBlock` against the server's MSVCB and USVCB. The
  client reads, reserves and enables libiec61850's 9-2LE SV control block
  and receives its stream. The server's LTRK is compared, value by value
  and report by report, with libiec61850's service tracking server
  running the same services on the same ICD.
  GDOI registrations are decrypted and dissected by Wireshark. The
  coverage table is `interop/README.md`.
- `testdata/ed21_diverse.cid` exercises the Edition 2.1 SCL constructs.
