---
title: "IEC 62351-4 implementation plan"
subtitle: "go-iec61850 library and datadiode-mms application — revision 2"
date: "11 October 2026"
lang: en-GB
toc: true
toc-depth: 2
numbersections: false
geometry: "a4paper, margin=2cm"
fontsize: 10pt
colorlinks: true
---

# 0. Document control

| Item | Value |
| --- | --- |
| Revision | 2 (supersedes revision 1 of 11 October 2026, kept as `output/pdf/iec62351-4-implementation-guide-rev1.pdf`) |
| Scope | IEC 62351-4 support in `go-iec61850` (library) and its use by `datadiode-mms` (application), plus the dependent work in `tase2` |
| Normative sources | **[B]** BS EN IEC 62351-4:2018+A1:2020 (consolidated IEC 62351-4 ed. 1.1); **[T]** PD IEC TS 62351-100-4:2023 (E2E conformance test cases) |
| Code baselines | **[R]** `go-iec61850` at `2b7bb9620ae2`; **[D]** `datadiode-mms` at `7221d40be6cb`; **[S]** `tase2` at `e689c2b93211` |
| Toolchain checked | Go 1.27.1 (`crypto/tls`, `crypto/ecdh`, `crypto/hkdf`, `crypto/x509` behaviour quoted below was verified against it) |
| Status | Engineering plan. It does not claim or certify conformance |

Page references: [B] printed page = PDF page − 7; [T] printed page = PDF page − 2. Both PDFs are scanned images. They were OCR'd for this revision, and every table quoted here (cipher suites, conformance tables, OSI subclasses) was checked against the page image. Code components (Annexes A, B, D) were read from the scan. Do **not** generate production code from OCR. Obtain the machine-readable archive named in [B] 1.2 (section 17, item R-01).

## 0.1 What changed from revision 1

Revision 1 was a design survey. This revision turns it into an executable plan and corrects the points below. Each correction was checked against the page image.

| # | Revision 1 said | Correct position (source) |
| --- | --- | --- |
| C1 | [T] Tables 68/69 append `.1` to the E2E *abstract syntax* | [T] Tables 68/69 give the **application-context-name** as `1.0.62351.4.1.2.1.1`, i.e. the abstract-syntax arc with `e2eMMS(1)` appended. [B] 15.2.2 defines `e2eMmsAC` = `1.0.62351.4.2.1`. The abstract syntax `e2eSecurityAS` = `1.0.62351.4.1.2.1` is not disputed. |
| C2 | The protected MMS PDU must not be wrapped arbitrarily (no structure given) | [B] Annex F.3 fixes the OSI Virtual API: `ApplData ::= [UNIVERSAL 8] IMPLICIT SEQUENCE { indirect-reference INTEGER, single-ASN1-type [0] MMSpdu }`. The MMS PDU travels as an EXTERNAL that names the **MMS** presentation context, inside the SecPDU that travels on the **E2E** context. |
| C3 | Rekey: the client pauses its sends until `changedKey` | [B] 13.3.2 f)/h): key switching is **per direction**. The client sends with new keys immediately after the PDU carrying `rekey`, and the server receives with new keys from the next client PDU. The server sends with new keys after the PDU carrying `changedKey`, and the client receives with new keys after that PDU. No pause is needed. |
| C4 | Replay detection needs bounded per-association replay storage | For data transfer, [B] 14.4.3 makes `(time, seq)` strictly ordered per direction, so the check is O(1) against the last tuple. Only the *handshake* `(time, assoID)` replay check (14.3.4 g) needs a cache, bounded by the freshness window. |
| C5 | Five-minute [T] check and ten-minute [B] threshold conflict | They test different things. [T] checks that the **emitted** time is within ±5 min of the tester's clock (clock quality). [B] sets the **receiver** rejection threshold at 10 min. Both are satisfied by a receiver threshold of 10 min and synchronised clocks (deployment requirement ≤ 1 min skew). |
| C6 | Diagnostic numbering "not resolvable" | Annex B is the normative *code component*. Its numbering (`altSig-mismatch (19)` inserted; `DtDiagnostics` with `--not used (5)`) is adopted as the baseline, to be confirmed against the IEC archive (R-01). |
| C7 | DH group "23" conflicts with IANA and is a blocker | [B] 13.3.1.2 and [T] Table 55 agree on the code points used **in this protocol**: 14 = MODP-2048, 23 = secp256r1, 28 = brainpoolP256r1. Treat `groupId` as an IEC 62351-4 code point, not an IKE registry lookup. The registry mismatch is recorded but does not block. |
| C8 | Brainpool support could be optional | [B] Table 11 makes `brainpoolP256r1` **mandatory** (m/m) as a *public-key* algorithm. Only DH group 28 is optional ([B] 13.3.1.2 a) 2)). Go's `crypto/x509` cannot parse Brainpool keys. |
| C9 | Native TLS: Go lacks "finite-field DH/DHE suites" | Verified on Go 1.27.1. Of the four suites [B] Table 10 makes **mandatory**, Go implements `0x003C` (only in `InsecureCipherSuites`, so it must be enabled explicitly) and `0xC02B`. It cannot do `0x00A0` (DH_RSA) or `0x009E` (DHE_RSA). The literal number [B] prints for ECDHE_ECDSA_AES_128_GCM, `0xC023`, **is** implemented by Go, as the CBC suite. Configuring from the printed number would silently negotiate the wrong cipher. |
| C10 | Session constraints (audit only) | The library sends the association in session **User Data** (PGI `0xC1`). [B] 10.3 requires **Extended User Data** in CONNECT (up to 10 240 octets) and forbids User Data there. This is a hard blocker for E2E, because certificates do not fit in 512 octets. |
| C11 | Diode: "independent sessions plus export format" (one paragraph) | Section 13 gives a full design: two terminating E2E legs, identity strategy for the replica, configuration schema, wire records, operations and tests. |

## 0.2 Reading guide

- Sections 1–3: the decisions to take now, and what the standards require.
- Section 4: the exact wire contract, byte for byte, for the OSI environment.
- Sections 5–7: cryptography, certificates and error handling, at implementation detail.
- Sections 8–11: the library gap analysis, architecture, API and work packages.
- Sections 12–14: the A-profile track, the diode application and the TASE.2 stack.
- Sections 15–17: verification, schedule and risks, and the discrepancy register.

# 1. Executive summary and decisions

IEC 62351-4 defines three independent capabilities:

1. **T-security**, i.e. TLS on port 3782 ([B] clause 6).
2. **A-security**, the compatibility-mode certificate authentication in the ACSE AARQ/AARE ([B] clause 11).
3. **E2E security** ([B] clauses 12–15): a signed, Diffie–Hellman-keyed association with an ICV on every MMS PDU, optional encryption and periodic rekeying.

[T] tests **E2E only**. T-security is tested by IEC TS 62351-100-3, and A-security is not tested at all.

The library today has T-security close to the IEC 62351-3 profile and nothing of A-security or E2E. The diode uses the library's TLS on both legs.

**Recommended target.** Implement E2E in the OSI environment for IEC 61850-8-1, in both client and server roles, in the library. Then use it on both diode legs as two **independent, terminating** E2E associations. A one-way link cannot carry an end-to-end association (section 13.1).

## 1.1 Decisions required (with recommendation)

| ID | Decision | Recommendation | Rationale |
| --- | --- | --- | --- |
| DEC-1 | Environments | OSI only. Declare XMPP "not supported" ([B] Table 6 needs only one) | 61850-8-1 and ICCP are OSI; the diode is OSI |
| DEC-2 | Modes ([B] Table 7) | Native **m**. Compatibility (A-profile) **o**, as a separate later track (section 12) | [T] tests native only; A-profile is still common in ICCP |
| DEC-3 | Encryption modes ([B] Table 9) | Declare **Non-use AE = m**: clear transfer, plus separate CBC+ICV encryption in a later phase. Declare **AE = not supported** until R-08 (AEAD nonce transport) is resolved | AEAD has no defined nonce field ([B] 13.3.2 e) covers CBC only) |
| DEC-4 | ICV algorithms | `hmacWithSHA256`, `aes128-GCM` and `aes256-GCM` (GMAC), all **m** under c[7] | [B] Table 11 c[7] |
| DEC-5 | Signature and public-key algorithms | RSA ≥ 2048 with SHA-256 and ECDSA P-256 with SHA-256 in release 1. Brainpool P-256 **verification** in release 2 (section 6.6) | Table 11 makes brainpool mandatory; Go has no implementation |
| DEC-6 | DH groups | 14 and 23 in release 1; 28 optional, later | [B] 13.3.1.2 |
| DEC-7 | T-security | Keep pure-Go TLS. Declare the 62351-4 Table 10 rows `0x00A0` and `0x009E`, and renegotiation, **not supported**. Add `0x003C` and the native ordering as an opt-in "62351-4 native" TLS profile | The diode's "pure Go, no cgo, static binary" constraint rules out an OpenSSL backend; a forked TLS stack is a disproportionate risk |
| DEC-8 | Ambiguities in the standards | Adopt the **Annex B code component** wherever body text and Annex B differ. Where [T] differs from [B], default to [B] and add a **named, narrowly scoped** test-campaign setting (section 7.4) | Reproducible, auditable behaviour |
| DEC-9 | Diode replica identity | Default: the replica answers with the **device's AE title**, using a certificate issued by the **DMZ** PKI for that AE title. Alternative: an own AE title (section 13.3) | Preserves client configuration ("transparent copy") without moving device keys |
| DEC-10 | Revocation-unavailable policy | Per [B] 6.2.7: warn and continue by default for E2E. Keep the existing TLS fail-closed default as a separate, explicit setting | [B] 6.2.7 requires that unavailable revocation information does not terminate |
| DEC-11 | TASE.2 | Expose a reusable, environment-agnostic E2E core and an OSI mapping package from `go-iec61850`, so the separate `tase2` ISO stack can call them | The diode's ICCP leg runs on `tase2`, not on `go-iec61850/mms` |

## 1.2 Deliverables

1. Library: packages `iec62351/e2e`, `iec62351/e2e/osi` and `iec62351/pki` (new); changes to `asn1`, `internal/osi/*`, `mms`, `client` and `server`; command-line support in `cmd/ied-client` and `cmd/ied-server`; PICS/PIXIT documents; test vectors and a fault-injection tester.
2. Diode: configuration schema, an E2E profile loader, inner and outer integration, a security status wire record, health metrics, `dd-probe` support, documentation and runbooks.
3. `tase2`: E2E integration in its ISO layer and bilateral-table security settings (optional track).
4. Evidence: a requirement-to-code-to-test trace matrix and a conformance campaign package (section 15).

# 2. Sources and baseline

- [B] is identical to IEC 62351-4:2018 + AMD1:2020. Its normative references fix IEC 62351-3:2014+A1:2018 for T-security.
- [T] cites IEC 62351-3:2023 and IEC 62351-4:2018/AMD1:2020. It states that T-profile testing (IEC TS 62351-100-3) precedes E2E testing ([T] clause 1). It also points to IEC 62351-6:2020 for the IEC 61850-8-1 security PICS ([T] 5.4). Record the agreed edition set in the PIXIT.
- [B] 1.2 names the machine-readable code components as `www.iec.ch/public/tc57/supportdocuments/IEC_62351-4.ASN.1_XSD.full.zip`. Obtaining and diffing this archive against Annexes A, B and D is work item WP0.2.

Existing library assets that the plan reuses:

| Asset | Location | Reuse |
| --- | --- | --- |
| BER encoder/decoder with indefinite-length support and depth limit | `asn1/decoder.go`, `asn1/element.go` | Extend with raw-span access (WP1) |
| IEC 62351-3 TLS profile, CRL and pinning checks | `iec62351/tls.go` | Unchanged for TLS; revocation logic moves to the shared `iec62351/pki` |
| MODP-2048 and ECP Diffie–Hellman with peer-value range checks | `gdoi/crypto.go:140-205` | Move into `internal/cryptox/dh` and share |
| AES-GCM key handling | `rsession/keys.go` | Reference only |
| Single send/receive choke point for MMS PDUs | `mms/transport.go:32-61` (`framing`) | Becomes the security adapter boundary |
| Serialised writers (`Conn.writeMu`, `ServerConn.writeMu`, `pumpUnconfirmed`) | `mms/conn.go`, `mms/server_conn.go` | Token-2 sequencing runs inside these locks |

# 3. Requirements digest

## 3.1 Conformance tables as they apply here

Tables 6–11 of [B] were decoded from the page images. The "Plan" column is the proposed PICS declaration.

| [B] table / row | Client | Server | Plan |
| --- | --- | --- | --- |
| T6 Operational environment: OSI / XMPP | c[2] / c[2] | c[2] / c[2] | OSI = Y, XMPP = N |
| T7 Compatibility mode | c[3] | c[3] | release 1: N; A-profile track: Y |
| T7 Native mode | c[4] | c[4] | Y |
| T8 TLS compatibility suites; only `TLS_DH_DSS_WITH_AES_256_CBC_SHA` (0x0036) is m | m | m | N, not implementable in Go `crypto/tls` |
| T9 Use of AE / Non-use AE | c[2] | c[2] | AE: N (R-08); Non-use AE: Y |
| T10 `TLS_RSA_WITH_AES_128_CBC_SHA256` 0x003C | m | m | Y, in the opt-in native TLS profile |
| T10 `TLS_DH_RSA_WITH_AES_128_GCM_SHA256` 0x00A0 | m | m | N |
| T10 `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` (printed `0xC0,0x9E`) | m | m | N |
| T10 `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (printed `0xC0,0x23`) | m | m | Y as **0xC02B** (R-10) |
| T10 optional suites `0x0031`, `0x00A1`, `0xC02F`, `0xC030`, `0xC024`→`0xC02C` | o | o | `0xC02F`, `0xC030` and `0xC02C`: Y |
| T11 `rsaEncryption`, `secp256r1` | m | m | Y |
| T11 `brainpoolP256r1` | m | m | release 2: verification only (section 6.6) |
| T11 `sha256WithRSAEncryption`, `ecdsa-with-SHA256` | m | m | Y |
| T11 `aes128-CBC`, `aes256-CBC` | c[5] | c[5] | phase P5: Y |
| T11 `aes128-GCM`, `aes256-GCM` as AE | c[6] | c[6] | N (follows T9) |
| T11 ICV: `hmacWithSHA256`, `aes128-GCM`, `aes256-GCM` | c[7] | c[7] | Y |

Other "shall" requirements outside the tables:

| Ref | Requirement | Owner in plan |
| --- | --- | --- |
| [B] 6.2.3 | TLS session resumption at least every 2 h (native mode) | WP11 |
| [B] 6.2.4 | TLS renegotiation at ≥ half the CRL period, min. 10 min | WP11: not supported in Go, declare it |
| [B] 6.2.5 | ≥ 2 trust anchors | WP5 |
| [B] 6.2.6 | Certificates up to 8192 octets; larger → terminate and raise event | WP5 |
| [B] 6.2.7 | CRL refresh ≥ every 24 h, configurable (default 24 h); OCSP cache ≤ 24 h; unavailable → warning event, **no termination** | WP5 |
| [B] 6.2.8 | Able to refuse a revoked or expired certificate; events "incident: revoked…", "warning: expired…" | WP5 |
| [B] 6.3.2/6.3.3 | Port 3782 with TLS, 102 without; TLS can be disabled | already met |
| [B] 7.2.2 c) | Check that certificates are DER | WP5 |
| [B] 10.3 | Session: version 2, duplex FU only, no extended concatenation, no TSDU max size, Extended User Data in CONNECT, ABORT user data > 9 octets | WP6 |
| [B] 10.4 | Odd context identifiers, BER transfer syntax, ACSE context always present | WP6 |
| [B] 10.4.4 | No constructed strings shorter than 1024 octets (OCTET STRING) or 256 bits (BIT STRING) in MMS | WP1 (already the encoder's behaviour; add a receive check) |
| [B] 10.5.2/10.5.3 | ACSE v1; AP-title form 2 (OID) and AE-qualifier mandatory for called and calling; responding identity equal to called | WP6 |
| [B] 13–15 | E2E protocol and OSI mapping | WP2–WP8 |
| [B] Annex G | E2E end-entity certificate profile | WP5 |
| [B] Annex H | TP0 limits, TSEL ≤ 32 octets, RFC 1006 version ignored, length ≤ 2056, TCP keep-alive ≈ 1 min | WP6 |
| [B] 4.6, 6.2.9 | Separate, tamper-resistant security log; events per IEC 62351-14 | WP8, D6 |

## 3.2 What [T] tests (OSI)

| [T] table | Role | Content | Required |
| --- | --- | --- | --- |
| 14 / 15 | client / server | Association establishment and signed release; EnvPDUs checked against Tables 68/69/74/75, SecPDUs against 55/56/66/67 | m |
| 16 / 17 | client / server | Environment-level association resiliency (indirect reference, application context) | m |
| 49 / 50 | client / server | Handshake SecPDU resiliency (22 and 20 rows) | m |
| 18 | either | Clear data transfer, checked against 62/63 and 72 | m |
| 19, 52 / 20, 51 | client / server | Clear-transfer resiliency (environment + SecPDU) | m |
| 21; 22, 53; 23, 54 | either / client / server | Encrypted transfer and its resiliency | optional (follows T9) |
| 24 / 25 | client / server | Rekey initiated by client / requested by server, shortest interval (15 min) | m |
| 55–67 | — | SecPDU field checks | — |
| 68–75 | — | OSI EnvPDU field checks | — |

[T] 5.2.2 requires every normal and resiliency test to run at least once for one mandatory algorithm set with mandatory key lengths. [T] Table 2 (PIXIT) requires the device under test to expose association events, rekeys, certificate validation results, cipher change results and the security events raised in resiliency tests. Sections 8.8 and 13.7 meet this through structured events and the command-line tools.

# 4. Wire contract — OSI environment

This section is the reference the codec and the fault-injection tester are built from. Tags are hexadecimal; `L` is a definite length. Modules E2E-Security (Annex B), OSI-Env (Annex D) and the OSI Virtual API (Annex F.3) are written with `DEFINITIONS IMPLICIT TAGS`, except Virtual-API, which uses the default (explicit) tagging. Every `[n]` below is therefore implicit unless marked EXPLICIT.

## 4.1 Object identifiers

| Name | Value | Source | Use |
| --- | --- | --- | --- |
| `id-acseAS` | `2.2.1.0.1` | [B] 10.4.2 | ACSE abstract syntax (always proposed) |
| `id-mmsAS` | `1.0.9506.2.1` | [B] 11.1.3 | MMS abstract syntax (proposed in both modes, [B] 15.2.1) |
| `e2eSecurityAS` | `1.0.62351.4.1.2.1` | [B] 15.2.1 | E2E abstract syntax |
| `e2eMmsAC` | `1.0.62351.4.2.1` | [B] 15.2.2 | Application context, native mode (R-02 for the [T] variant) |
| `basic-AC` (`mms-application-context-version1`) | `1.0.9506.2.3` | [B] 11.1.4.2 | Application context, compatibility mode |
| `mmsAuthenticationAS` | `1.0.840.0.1.1.4.1` | [B] 11.1.3 | A-profile abstract syntax (historically wrong OID, kept) |
| A-profile mechanism-name | `1.0.840.0.1.0.1.1` | [B] 11.1.4.3 | A-profile only |
| BER transfer syntax | `2.1.1` | [B] 10.4.1 | All contexts |
| `rsaEncryption` | `1.2.840.113549.1.1.1`, NULL params | [B] 8.3 | Public key |
| `id-ecPublicKey` | `1.2.840.10045.2.1`, curve OID params | [B] 8.3 | Public key |
| `secp256r1` | `1.2.840.10045.3.1.7` | [B] 8.3 | Curve |
| `brainpoolP256r1` | `1.3.36.3.3.2.8.1.1.7` | [B] 8.3 | Curve |
| `id-sha256` | `2.16.840.1.101.3.4.2.1` | [B] 8.4 | Hash |
| `sha256WithRSAEncryption` | `1.2.840.113549.1.1.11`, NULL params | [B] 8.5 | Signature |
| `ecdsa-with-SHA256` | `1.2.840.10045.4.3.2`, params absent | [B] 8.5 | Signature |
| `id-aes128-CBC` / `id-aes256-CBC` | `2.16.840.1.101.3.4.1.2` / `.42` | [B] 8.6 | Encryption |
| `id-aes128-GCM` / `id-aes256-GCM` | `2.16.840.1.101.3.4.1.6` / `.46` | [B] 8.7 | AE or GMAC ICV |
| `id-hmacWithSHA256` | `1.2.840.113549.2.9`, NULL params | [B] 8.8 | ICV, and HKDF hash selector (R-15) |
| Module OIDs | `1.0.62351.4.0.{1,2,3,31}.1` | Annexes A, B, D, F | Not on the wire |

## 4.2 Presentation contexts

The library's client proposes three contexts with odd identifiers ([B] 10.4.1 a)):

| Id | Abstract syntax | Transfer syntax |
| --- | --- | --- |
| 1 | `id-acseAS` | BER |
| 3 | `id-mmsAS` | BER |
| 5 | `e2eSecurityAS` | BER |

As a server, the library must accept **any** odd identifiers the peer chooses and remember them (the existing `presentation.Negotiated` pattern, extended to a third context). The CPA lists a result per proposed context, in order. A native-mode association whose CP lacks the E2E or the MMS context is refused at the presentation level (CPR with provider rejection), before ACSE is parsed.

## 4.3 Association request (AARQ in CP in session CONNECT)

```text
Session CONNECT SPDU (SI 0x0D)
  PGI 0x05 Connect/Accept Item: protocol options 0x00, version number 0x02
  PI  0x14 Session User Requirements: 0x0002 (duplex)
  PGI 0xC2 Extended User Data  <- [B] 10.3: NOT 0xC1; max 10 240 octets in total
    CP-type SET (presentation)
      mode-selector, normal-mode-parameters
        context-definition-list (1 ACSE, 3 MMS, 5 E2E)
        fully-encoded-data, context 1:
60 L                                  AARQ-apdu
  A1 L 06 L <1.0.62351.4.2.1>         application-context-name = e2eMmsAC
  A2 L 06 L <called AP-title>         mandatory ([B] 10.5.3)
  A3 L 02 L <called AE-qualifier>     mandatory
  A6 L 06 L <calling AP-title>        mandatory
  A7 L 02 L <calling AE-qualifier>    mandatory
                                      NO [10] sender-acse-requirements, [11] mechanism-name,
                                      [12] calling-authentication-value ([B] 15.2.2)
  BE L                                user-information = OSI-AssoReq ([B] 15.3.2)
    28 L                              EXTERNAL
      02 01 05                        indirect-reference = E2E context id
      A0 L                            single-ASN1-type [0] EXPLICIT
        30 L                          HandshakeReq
          0C L "IEC 61850-8-1"        pp (NMTOKEN as UTF8String)
          30 L                        tbs   <== signed span: content octets only
            30 L ...                  token1 ClearToken1 (4.6)
            28 L                      applData ApplData (Annex F.3)
              02 01 03                indirect-reference = MMS context id
              A0 L <A8 L ...>         [0] EXPLICIT MMSpdu = initiate-RequestPDU
          30 L                        sign Signature
            30 L 06 L <alg> [05 00]   algo (must equal token1.sigAlg)
            04 L <signature octets>   sign
```

The protected-protocol identifier for ICCP is `"IEC 60870-6-503"` ([B] 13.1.3 a)). Whether a TASE.2 client should use `-503`, `-702` or `-802` is R-17.

## 4.4 Association response (AARE in CPA/CPR in ACCEPT/REFUSE)

```text
61 L                                  AARE-apdu
  A1 L 06 L <e2eMmsAC>
  A2 03 02 01 rr                      result: 0 accepted | 1 rejected-permanent | 2 rejected-transient
  A3 05 A1 03 02 01 dd                acse-service-user: 0 null (accepted) | 1 no-reason-given (rejects)
  [A4 L 06 L <responding AP-title>]   if present, must equal called ([B] 10.5.3)
  [A5 L 02 L <responding AE-qual>]
  BE L 28 L 02 01 05 A0 L             OSI-AssoRsp, [0] EXPLICIT HandshakeRsp:
      A1 L {30 L tbs, 30 L sign}      assoAccept [1] HandshakeAcc     (result 0)
    | A2 L {30 L tbs, 30 L sign}      applReject [2] ApplicationReject (result 1|2; MMS initiate-Error)
    | A3 L {30 L tbs, 30 L sign}      secReject  [3] HandshakeSecReject (result 1)
```

The response is wrapped in a CPA in session ACCEPT when accepted. When rejected it goes in a CPR in session REFUSE (reason 2, as the library does today). An ACSE-level error that is not about the user information follows X.227 7.3.3.4 / [B] 15.6.1: an AARE reject with the ordinary diagnostic and **no** user-information, or an ABRT from the ACSE provider for a protocol error (4.5).

## 4.5 Abort (ABRT in ARU in session ABORT)

```text
64 L                                  ABRT-apdu
  80 01 ss                            abort-source: 0 acse-service-user (all E2E aborts) | 1 provider
                                      [1] abort-diagnostic absent for every E2E abort ([B] 15.3.4)
  BE L 28 L 02 01 05 A0 L             OSI-AssoAbr, [0] EXPLICIT AssoAbort:
      A0 L {...}                      handsSecAbort [0] HandshakeSecAbort  (client rejects HandshakeAcc)
    | A1 L {...}                      dtSecAbort    [1] DtSecAbort         (data-transfer security fault)
    | A2 L {...}                      applAbort     [2] ApplAbort          (protected protocol abort)
    | 83 01 nn                        osiDiag       [3] OsiDiagnostics     (environment fault; unsigned)
```

When an ACSE-kernel protocol error is found, the abort is `64 03 80 01 01` with no user-information ([B] 15.6.1). The session ABORT must carry more than 9 octets of user data ([B] 10.3).

## 4.6 SecPDU bodies (Annex B)

```text
ClearToken1 ::= 30 L
  30 L 06 L <sigAlg> [05 00]          sigAlg
  04 L <DER end-entity cert>          pkCert (<= 8192 octets)
  [30 L {04 L <CA cert>}+]            certPath: first = signed by trust anchor, last = issuer of pkCert
  03 02 07 80                         version {v1}   (always emitted; absence accepted = DEFAULT, R-05)
  0C L "123" | "123:456"              assoID (client: 1-3 digits; server: client part ":" own 1-3 digits)
  30 L 02 01 gg 04 L <pub>            dHKey: groupId (14 | 23 | 28), dhPublicKey (encoding R-13)
  30 L 06 L <hmac alg> [05 00]        hmac (R-15)
  18 L "YYYYMMDDhhmmss[.f+]Z"          time (13.1.2, see 5.6)
  encr-mode CHOICE:
    30 L {30 L <AlgId>}+              aea: ordered preference list (AES-GCM, parameters per R-08)
  | A0 L                              non-aea [0]
        [A0 L {30 L <AlgId>}+]        encr [0] SEQUENCE OF, ordered (present iff encryption wanted)
         A1 L {30 L <AlgId>}+         icvAlgID [1] SET OF (R-16)
  03 L <bits>                         confParams {tlsProtected(0), applProtected(1), vpn(2)}
  [04 L <DER attribute cert>]         attCert

ClearToken2 ::= 30 L
  [03 02 07 80]                       version DEFAULT {v1} (emitted)
  0C L assoID
  18 L time
  02 L seq
  [80 10 <16 octets>]                 iv [0]   (present iff AES-CBC)
  [81 L <dh public>]                  rekey [1] (client only)
  [82 01 FF]                          reqRekey [2] (server only; FALSE is omitted)
  [83 01 FF]                          changedKey [3] (server only; FALSE is omitted)

ClearToken3 ::= 30 L
  30 L <sigAlg>                        sigAlg
  [03 02 07 80]                       version DEFAULT {v1}
  [0C L assoID]                       full ID if known; client part only if just that; absent otherwise
  18 L time
  04 L <pkCert>                       pkCert
  [30 L certPath]

Signature     ::= 30 L {30 L <AlgId>, 04 L <sig>}
Authenticator ::= 30 L {[04 L nonce], 30 L <AlgId>, 04 L icv}   Annex B (untagged; R-04)
            (clause 13.4.2 variant:  {[80 L nonce], 30 L <AlgId>, 81 L icv})

HandshakeReq        ::= 30 L {0C pp, 30 tbs{ClearToken1, [ApplData]}, Signature}
HandshakeAcc        ::= 30 L {30 tbs{ClearToken1, [ApplData]}, Signature}
ApplicationReject   ::= 30 L {30 tbs{ClearToken3, ApplData}, Signature}
HandshakeSecReject  ::= 30 L {30 tbs{ClearToken3, [0A 01 diag]}, Signature}
HandshakeSecAbort   ::= 30 L {30 tbs{ClearToken3, [0A 01 diag]}, Signature}
DtSecAbort          ::= 30 L {30 tbs{ClearToken3, [0A 01 diag]}, Signature}
ApplAbort           ::= 30 L {30 tbs{ClearToken3, [ApplData]}, Signature}
ReleaseReq/Rsp      ::= 30 L {30 tbs{ClearToken3}, Signature}
ClearTransfer       ::= 30 L {30 tbp{ClearToken2, ApplData}, Authenticator}
EncrTransfer        ::= 30 L {30 tbp{ClearToken2, 04 L Encrypted-ApplData}, [Authenticator]}
```

The `tbs` and `tbp` sequences and the token sequences carry ASN.1 extension markers in Annex B. A receiver must therefore tolerate unknown trailing elements at those positions. The plan bounds this to at most 8 extra elements of at most 4 KiB each, and ignores them *after* the signature or ICV has verified.

## 4.7 Release (RLRQ in session FINISH, RLRE in session DISCONNECT)

```text
62 L 80 01 00 BE L 28 L 02 01 05 A0 L <ReleaseReq>   RLRQ: reason normal(0) (urgent(1) allowed)
63 L [80 01 00] BE L 28 L 02 01 05 A0 L <ReleaseRsp> RLRE
```

Release SPDUs carry presentation `User-data` on the **ACSE** context (1). The library implements neither FINISH nor DISCONNECT today (8.1).

## 4.8 Data transfer (session DT, presentation TD)

```text
01 00 01 00                           GIVE TOKENS + DATA TRANSFER
61 L 30 L                             fully-encoded-data, one PDV-list
  02 01 05                            presentation-context-identifier = E2E (anything else: invalid-pci)
  A0 L <ClearTransfer | EncrTransfer> [0] EXPLICIT
```

Inside, `ApplData` = `28 L 02 01 03 A0 L <MMSpdu>`. In native mode a plain MMS PDU on context 3 after the handshake is an environment error ([B] 15.6.2 c); [T] Tables 19, 20, 22, 23).

## 4.9 Exact protected spans

| Operation | Input octets | Source |
| --- | --- | --- |
| Signature (all signed SecPDUs) | Content of `tbs`: everything after `tbs`'s tag and length octets. With indefinite length, everything up to **and including** the closing `00 00` | [B] 13.1.3 c) etc. |
| Handshake salt `data1`, `data2` | Content of `tbs` of HandshakeReq / HandshakeAcc, as received | [B] 13.3.1.3 a) |
| ICV of ClearTransfer / non-AE EncrTransfer | Content of `tbp`; for EncrTransfer, computed after encryption | [B] 13.2.2 b), 13.2.3 b) |
| Encryption plaintext | The full ApplData TLV, from its `28` tag to the end of its content | [B] 13.2.3 a) 2) |
| AE additional authenticated data | The full ClearToken2 TLV, including its `30 L` | [B] 13.2.3 a) |
| Rekey salt `data3` | Content of `tbp` of the PDU carrying `rekey` | [B] 13.3.1.3 a) 4) |
| A-profile signature | Content octets of the GeneralizedTime (no tag or length) | [B] 11.2.2 c) |

Emitters always use definite lengths. Receivers must sign or verify the bytes as received. They must never decode and re-encode.

## 4.10 Size budget

The session CONNECT user data is limited to 10 240 octets ([B] 10.1, G.3): presentation PCI + ACSE PCI + HandshakeReq.

| Element | ECDSA P-256, group 23 | RSA-2048, group 14 |
| --- | --- | --- |
| Presentation + ACSE + session PCI | ~180 | ~180 |
| ClearToken1 without certificates | ~260 | ~450 |
| pkCert (typical) | ~650 | ~1 100 |
| certPath, 1 intermediate | ~650 | ~1 300 |
| MMS initiate-Request + ApplData | ~60 | ~60 |
| Signature | ~95 | ~280 |
| **Total** | **~1 900** | **~3 400** |

Enforce on send: refuse to send a HandshakeReq that would exceed 10 240 octets, and report which certificate is too large. Enforce on receive: a CONNECT above 10 240 → REFUSE/abort. An individual certificate above 8192 octets → terminate and raise event `CertificateTooLarge` ([B] 6.2.6). ACCEPT and ABORT user data may reach 65 539 octets ([B] 10.3 NOTE).

Per-PDU overhead in the data phase: about 120 octets for HMAC-SHA-256, about 85 for GMAC-12, and CBC adds 18 (IV) plus up to 16 (padding). The MMS `localDetail` (maximum MMS PDU size) still bounds the **inner** MMS PDU. The COTP reassembly limit must be raised to `localDetail + 1 KiB`, but must stay bounded (8.1 G-COTP-2).

# 5. Cryptography and key schedule

## 5.1 Algorithm registry

One registry (`iec62351/e2e/alg`) maps each OID to its implementation and to the **exact** parameter encoding it accepts. A receiver must check the parameters, not just the OID. An unknown or badly parameterised algorithm produces the specific diagnostic for its field (7.2), not a decode error.

| Role | Algorithm | Go implementation | Parameters on send | Parameters accepted |
| --- | --- | --- | --- | --- |
| Signature | sha256WithRSAEncryption | `crypto/rsa.SignPKCS1v15` via `crypto.Signer` | `05 00` | `05 00` or absent (R-18) |
| Signature | ecdsa-with-SHA256 | `crypto/ecdsa` via `crypto.Signer` | absent | absent |
| HKDF selector | hmacWithSHA256 | `crypto/hkdf` with `crypto/sha256` | `05 00` | `05 00` or absent |
| ICV | hmacWithSHA256 | `crypto/hmac` | `05 00` | `05 00` or absent |
| ICV (GMAC) | aes128-GCM / aes256-GCM | `cipher.NewGCMWithTagSize` with empty plaintext | in proposal: R-08; in Authenticator: `GCMParameters` without nonce, `aes-ICVlen` 12 | `aes-ICVlen` 12–16 |
| Encryption | aes128-CBC / aes256-CBC | `crypto/aes` + `cipher.NewCBCEncrypter` | in proposal: absent ([B] 13.3.1.1 i) 2) i)) | absent |
| AE | aes128-GCM / aes256-GCM | deferred (R-08) | — | — |
| DH | group 14 MODP-2048 | `math/big`, moved from `gdoi` | — | — |
| DH | group 23 secp256r1 | `crypto/ecdh.P256` | — | — |
| DH | group 28 brainpoolP256r1 | release 2+, optional | — | — |

The private key is always a `crypto.Signer`, so keys can live in an HSM, TPM or PKCS#11 module, and the library never holds raw key bytes it does not need.

## 5.2 Diffie–Hellman

- **Generation**: a fresh key pair per association ([B] 13.3.1.2 b)), and a fresh client pair per rekey. The server **keeps** its private key for the life of the association, because rekeying reuses it ([B] 13.3.2 f) 2)).
- **MODP-2048 (14)**: a private exponent of at least 256 bits (the `gdoi` code uses 512, which is acceptable). The public value is 256 octets, big-endian and left-padded. Peer check: `1 < y < p−1`. Z is 256 octets, left-padded.
- **secp256r1 (23)**: proposed public-key encoding is the SEC1 uncompressed point `04‖X‖Y` (65 octets). `crypto/ecdh` rejects invalid points and the point at infinity. Z is the 32-octet X coordinate. R-13 must confirm this; `gdoi` uses RFC 5903 `X‖Y` without the prefix, which is a different convention.
- The ECDH or MODP private key is cleared (best effort) at association end. Document that Go cannot guarantee zeroisation.

## 5.3 Key derivation ([B] 13.3.1.3)

```text
h0        = INITIAL                       -- R-12: representation of "0"
h1        = H(data1 || h0)                 -- data1 = HandshakeReq.tbs content
salt0     = h2 = H(data2 || h1)            -- data2 = HandshakeAcc.tbs content
PRK       = HMAC-H(salt0, Z)               -- HKDF-Extract (RFC 5869)
OKM       = HKDF-Expand(PRK, info = <absent>, L)
rekey i:  salt_i = H(data3_i || salt_{i-1}) -- data3 = tbp content of the PDU carrying rekey
          Z_i    = DH(client_new_priv_i, server_priv_0)
          OKM_i  = HKDF(salt_i, Z_i, L)
```

`H` is the hash of the `hmac` field (SHA-256). Key layout and lengths (R-11 confirms the lengths):

| Mode | L | Split, in order |
| --- | --- | --- |
| Clear, ICV = HMAC-SHA-256 | 64 | client ICV key (32), server ICV key (32) |
| Clear, ICV = GMAC-AES-128 / 256 | 32 / 64 | client key, server key (16 / 32 each) |
| Encrypted, separate cipher + ICV | ICV + enc | client ICV, server ICV, client enc, server enc ([B] four-key order) |
| AE (deferred) | 2 × key length | client key, server key |

"Client key" means the key the client uses to *send*. The server uses the same key to verify. Implement this as `deriveKeys(hash, salt, z, layout) (dirKeys, error)` and fix it with test vectors covering every row (WP0.3).

## 5.4 Data protection procedures

**Clear transfer, send:**

1. Build the ClearToken2.
2. Encode `tbp = SEQUENCE{token2, ApplData}`.
3. Compute `ICV = MAC(k_send_icv, content(tbp))`. For GMAC: a fresh 12-octet nonce, `tag = GCM.Seal(nil, nonce, nil, content(tbp))`, then truncate to `aes-ICVlen`.
4. Emit `Authenticator{nonce?, algo, icv}`.

**Clear transfer, receive:**

1. Structural decode with spans.
2. `algo` ≠ agreed → alarm.
3. GMAC without a nonce → `gmac-nonce-required`.
4. Verify the ICV in constant time (`hmac.Equal`). Failure → alarm.
5. Token checks (5.5).
6. Commit the token state.
7. Check that the ApplData indirect reference is the MMS context.
8. Hand the MMS bytes to the dispatcher.

**Encrypted, non-AE, send:**

1. Fresh 16-octet IV from `crypto/rand`, placed in `token2.iv`.
2. `C = AES-CBC(k_send_enc, IV, pad(ApplData TLV))`.
3. `tbp = {token2, OCTET STRING C}`.
4. ICV over `content(tbp)`, as in clear transfer. This is encrypt-then-MAC.

**Encrypted, non-AE, receive:** verify the ICV **before** decrypting. Then check the IV is present (`aes-init-vector-required`), decrypt, strip and check the padding, and parse ApplData. Every padding or parse failure after a valid ICV is a protocol error (DtSecAbort `protocol-error`), handled in constant work.

**Padding** (R-09): PKCS#7 by default (the CMS convention of RFC 5084, which [B] cites for GCM). The IPsec convention of RFC 3602 ([B] bibliography for CBC) differs. This must be fixed by a vector before encrypted mode is released.

**Nonce and IV uniqueness**: random 96-bit GMAC nonces are safe below 2^32 messages per key. Rekeying at most every 24 h (minimum 15 min) keeps every key far below that. Keep a per-key message counter, and force a rekey at 2^30 messages as a defence in depth.

## 5.5 ClearToken2 rules (per direction)

State per direction: `(epoch, lastTime, lastSeq, haveLast)`.

**Sender** (inside the connection write lock, 9.4):

- `t = now()` truncated to milliseconds. If `t < lastTime` (the wall clock moved back), use `t = lastTime`.
- If `t == lastTime`, `seq = lastSeq + 1`. Otherwise `seq = 0`.
- Encode `t` in canonical form (5.6).
- If the clock has been held for more than half the freshness window, raise event `ClockRegression`. Beyond the freshness window, abort with `ApplAbort` and re-associate.

**Receiver**, in [B] 14.4.3 order, after the ICV has verified:

1. `|t − now| > 10 min` → `invalid-time-value`.
2. `t < lastTime` → `invalid-time-value`.
3. `t == lastTime && seq <= lastSeq` → replay **alarm**.
4. `t == lastTime && seq != lastSeq + 1` → `invalid-sequence-number`.
5. `t > lastTime && seq != 0` → `invalid-sequence-number`.
6. The first PDU of a direction must have `seq == 0`.
7. Commit `(t, seq)` only after the whole PDU, including MMS decoding of the envelope, has been accepted.

Equality of `t` is equality of the parsed instant, so `…12Z` and `…12.000Z` are the same time. This deliberately follows [B]. [T] Tables 62–65 row 6 instead expect `seq` to increase by one per message regardless of time (R-06).

Flag rules ([B] 13.3.2 f)–h), 14.4.3 f)–i)):

| Received | By | Condition | Result |
| --- | --- | --- | --- |
| `rekey` present | client | always | `protocol-error` |
| `changedKey` present | server | always | `protocol-error` ([T] Table 54 row 7 expects `unexpected-changedKey`: R-07) |
| `rekey` present | server | a previous `rekey` has not yet been answered with `changedKey` | `unexpected-dhPublicKey` |
| `changedKey` TRUE | client | no `rekey` outstanding | `unexpected-changedKey` |
| `reqRekey` present | server | always | `protocol-error` |

## 5.6 Time ([B] 13.1.2)

- **Emit** GeneralizedTime as `YYYYMMDDhhmmss[.fff]Z`, in DER-canonical form: no trailing zeros in the fraction, no `.` when the fraction is zero, `.` as the decimal mark, no `T`.
- **Accept** hour, minute or second precision and any fraction length. Accept `.` or `,` as the decimal mark. A trailing `Z` is mandatory. Reject local-time and offset forms, and any non-digit or out-of-range field, as `protocol-error`. A wrong time *syntax* is a protocol error; a time out of *window* is `invalid-time-value`.
- Freshness window: 10 min ([B] 14.3.4 f), 14.4.3 a)), configurable **downwards only**.
- The clock is injected (`func() time.Time`) for tests. Production uses `time.Now()` and expects NTP or PTP synchronisation; this is a deployment requirement (PIXIT "primary time source").

## 5.7 Rekey state machine

Directional epochs (correction C3):

```text
Client                                         Server
------                                         ------
[tx e0, rx e0]                                 [tx e0, rx e0]
send ClearTransfer{rekey=Pc1} under tx e0  -->  verify under rx e0; derive e1 (salt1, Z1)
tx := e1  (immediately after this PDU)          rx := e1 (for every following client PDU)
                                                pendingChanged := true
send ... under tx e1                        -->  verify under rx e1
                                       <--  next server PDU: changedKey=TRUE under tx e0
verify under rx e0; rx := e1                     tx := e1 (after this PDU)
                                       <--  server PDUs under tx e1
```

- The client keeps its old receive key until `changedKey` arrives. The server keeps its old send key until it has written the `changedKey` PDU. Each direction holds at most two keys.
- The client must not send a new `rekey` before it has seen `changedKey` ([B] 13.3.2 f)).
- The server may set `reqRekey` on any PDU when its policy interval expires. The client then rekeys on its next PDU.
- **Triggers** for the client: the policy interval (15 min–24 h, default 1 h), the message-count limit (5.4), or `reqRekey`.
- **Carrier**: ClearTransfer always carries an MMS PDU, so the `rekey` field rides on the next outgoing PDU. If the association is idle when a rekey is due, the client issues an MMS `Identify` request to carry it (configurable: `RekeyCarrier: Piggyback | Identify`).
- **Timeouts**: if no `changedKey` arrives within `max(30 s, 2 × request timeout)` after the rekey PDU, the client aborts (`ApplAbort`, event `RekeyTimeout`) and re-associates.
- In [T] Table 24 the tester answers the rekey PDU with `changedKey` before the client sends again, so the test passes with the immediate switch. [T] Table 25 (server-requested) runs `reqRekey` → `rekey` → `changedKey`.

# 6. Certificates, identity and trust

## 6.1 Separate E2E credentials

[B] G.2: when an implementation does TLS **and** application security, the end-entity certificates must be different.

- Validation at configuration time refuses an E2E certificate whose public key equals the TLS certificate's.
- The E2E trust store is a separate object. It may contain the same anchors.
- At least two trust anchors are supported ([B] 6.2.5). Trust-store replacement is atomic (copy-on-write snapshot), and each association keeps the snapshot it was validated with.

## 6.2 Peer certificate checks ([B] Annex G, 7.2.2, 14.3.4)

These run in this order on `pkCert` and `certPath` of ClearToken1 (and on `pkCert` of ClearToken3, which must equal the one used in the handshake: [T] Tables 59–61, 66–67):

1. Size ≤ 8192 octets, before parsing. Otherwise terminate and raise event `CertificateTooLarge`.
2. Parse as strict DER (`x509.ParseCertificate`), and check that `cert.Raw` equals the input exactly. Otherwise `invalid-public-key-certificate`.
3. Version 3; serial number positive; no issuer or subject unique IDs; signature hash SHA-256 or stronger; the signature algorithm equals the issuer's `signatureAlgorithm` field.
4. Subject public key: RSA ≥ 2048, or EC secp256r1 or brainpoolP256r1 (section 6.6). Ed25519 is **not** allowed, even though the TLS profile accepts it.
5. Key usage present, with `digitalSignature` **and** `keyAgreement`, for RSA as well ([B] G.5.2).
6. Path: convert `certPath` (top-down) into Go's intermediates, verify with the E2E roots and `KeyUsages: ExtKeyUsageAny`, at the time of the PDU, not of decoding. Failure → `invalid-certification-path` (or `invalid-public-key-certificate` when the leaf itself is malformed).
7. Revocation (6.4).
8. Identity binding (6.3) → address-mismatch **alarm**.

Peer-supplied certificate paths are bounded: at most 4 CA certificates and 32 KiB in total.

## 6.3 Identity binding

[B] G.6.2: the subject DN is a single RDN with one `objectIdentifier` attribute (X.520). Its value is the AE-title OID, formed by appending the AE-qualifier to the AP-title OID ([B] 10.5.3 NOTE 1). For example, AP-title `1.3.9999.1.10` with AE-qualifier `12` gives `1.3.9999.1.10.12`.

- Implement this by walking `cert.Subject.Names` (Go keeps unknown attribute types) and requiring exactly one RDN with exactly one attribute, whose type is the X.520 `objectIdentifier` attribute type and whose value is an OBJECT IDENTIFIER.
- Take the attribute-type OID from X.520 / ISO/IEC 9594-6 (WP0.5). Do not guess it. It must be in the PICS.
- **Server** compares the peer certificate with the AARQ *calling* AP-title and AE-qualifier.
- **Client** compares with the AARE *responding* values, or the *called* values when the responding ones are absent ([B] 10.5.3).
- Both sides check that the AARE responding values, when present, equal the AARQ called values. A mismatch is an ACSE protocol issue (AARE reject or abort) before any E2E processing.
- AE-qualifier must be ≥ 0, so that it can form an OID arc. A configured negative value is rejected at configuration time.

## 6.4 Revocation

- A shared `pki.RevocationChecker` serves TLS and E2E. Sources: CRL files or URLs configured explicitly, with a refresher (default period 24 h, configurable, minimum refresh interval 1 h) ([B] 6.2.7). Network fetches **never** happen inside a handshake.
- Per certificate, the result is one of: `Good`, `Revoked`, `Unknown` (no CRL covers the issuer) or `Unavailable` (CRL stale or unreachable).
- Policy for `Unavailable` and `Unknown`: `Warn` (default for E2E, as [B] requires) or `FailClosed` (opt-in). `Revoked` always refuses: `invalid-public-key-certificate` or `invalid-certification-path`, plus event `CertificateRevoked`. An expired certificate always refuses, plus event `CertificateExpired`.
- **Long associations**: on every CRL refresh, and when the peer certificate expires, re-evaluate each live association. If the peer is now revoked or expired, send `ApplAbort` with no applData and raise event `PeerInvalidatedDuringAssociation`. This is a design choice; [B] requires it only for TLS renegotiation.
- OCSP: not supported in release 1. Declare it in the PICS. If added later, cache responses for at most 24 h.

## 6.5 Attribute certificates (IEC 62351-8)

Release 1 never sends `attCert`. On receipt, it is refused with `invalid-attribute-certificate`, unless the setting `AcceptUnverifiedAttributeCertificates` is enabled. That setting logs a warning and ignores the attribute certificate. Role-based access control is a separate future work package and is not implied by E2E.

## 6.6 Brainpool P-256 (release 2)

Go's `crypto/x509` returns "unsupported elliptic curve" for brainpool keys, and `crypto/ecdh` has no brainpool curve. Plan:

- Add `internal/cryptox/brainpool`, providing curve parameters from RFC 5639 and ECDSA **verification only**. Verification uses public data, so a variable-time implementation is acceptable there. It must have test vectors from RFC 5639 / RFC 7027 and Wycheproof.
- A custom SubjectPublicKeyInfo parser and certificate-signature verifier for paths that contain a brainpool key. Use `x509.ParseCertificate` wherever it succeeds, and a minimal path validator (name chaining, validity, basic constraints, key usage, signature) for the rest.
- Do not use brainpool for this side's own key or for DH group 28 until a reviewed constant-time implementation is available.
- Until release 2, the PICS declares brainpoolP256r1 "N" (a known deviation from Table 11).

# 7. Error handling, diagnostics and events

## 7.1 Check order

To emit the diagnostic [T] expects for single-fault tests, the checks run in a fixed order that follows [B]'s numbering. The first failure decides.

**Handshake (server on HandshakeReq; client on HandshakeAcc):**

1. Envelope (environment, [B] 15.6): ACSE kernel only. Wrong or missing user-information → ABRT `acse-service-provider` with no user-information. Indirect reference ≠ E2E context → `invalid-indirect-reference`. On the server, the application context ≠ `e2eMmsAC` → AARE reject with `application-context-name-not-supported` ([T] Table 17 row 1).
2. Structural decode with spans and limits. A malformed **structure** (not a semantic error such as an empty SEQUENCE OF, which is handled later) → `protocol-error`. Accept `SIZE(1..MAX)` violations structurally and map them semantically: an empty `encr` → `single-encrypt-algo-required`, as [T] Table 49 row 14 expects.
3. Size of `pkCert` ([B] 6.2.6) → terminate and raise the event.
4. `token1.sigAlg ≠ sign.algo` → **alarm** `SignatureAlgorithmMismatch` ([B] 14.3.2 a)).
5. Signature algorithm not supported or not allowed by policy → `invalid-signatureAlgorithm`.
6. Parse the certificate to obtain the public key. A parse failure → `invalid-public-key-certificate`.
7. Verify the signature over `content(tbs)`. Failure → **alarm** `InvalidSignature`.
8. `pp` (HandshakeReq only) ≠ the configured protected protocol → `protected-protocol-not-supported`.
9. ClearToken1, in [B] 14.3.4 order:
   - b) certificate → `invalid-public-key-certificate`
   - c) identity → **alarm** `AddressMismatch`
   - d) path → `invalid-certification-path`
   - e) version → `unexpected-version`
   - f) time → `invalid-time-value`
   - g) `(time, assoID)` replay → **alarm** `Replay`
   - h) and i) DH group → `dhGroup-not-supported` (server) or `illegal-dhGroup-selected` (client)
   - j) hmac → `hmac-algorithm-not-supported`
   - k)–z) encryption mode and algorithms (table 7.3)
   - aa) attribute certificate → `invalid-attribute-certificate`
10. Only now is `applData` handed to MMS: `ParseInitiateRequest` on the server, `ParseInitiateResponse` on the client. An MMS refusal on the server → ApplicationReject carrying an MMS `initiate-ErrorPDU`.
11. Only after all of this does the server call the application `Authenticate` hook, with the authenticated peer (9.3).

On the server, a failure in steps 4–9 → HandshakeSecReject: `diag` present for diagnostics, absent for alarms (7.4). On the client → HandshakeSecAbort in ABRT. A signature failure is never followed by semantic diagnostics ([B] 14.3.2).

**Data transfer**, in [B] 14.4 order: environment context id (`invalid-pci`, `protocol-error`) → structure (`protocol-error`) → `encryption-not-selected` / `encryption-required` → Authenticator (`invalid-icv-algorithm` alarm, `gmac-nonce-required`, invalid ICV alarm) → ClearToken2 (`unexpected-version`, 5.5 rules, `aes-init-vector-required`, flag rules). A failure → DtSecAbort in ABRT. Then close the connection, fail every pending request, and run no further callbacks.

## 7.2 Diagnostic code values

| HandshakeDiagnostics | Value | DtDiagnostics | Value |
| --- | --- | --- | --- |
| no-reason-given | 0 | no-reason-given | 0 |
| protocol-error | 1 | protocol-error | 1 |
| protected-protocol-not-supported | 2 | unexpected-version | 2 |
| invalid-signatureAlgorithm | 3 | encryption-not-selected | 3 |
| unexpected-version | 4 | encryption-required | 4 |
| hmac-algorithm-not-supported | 5 | (not used) | 5 |
| encryption-not-required | 6 | gmac-nonce-required | 6 |
| encryption-required | 7 | invalid-time-value | 7 |
| invalid-public-key-certificate | 8 | invalid-sequence-number | 8 |
| invalid-certification-path | 9 | aes-init-vector-required | 9 |
| invalid-time-value | 10 | unexpected-dhPublicKey | 10 |
| dhGroup-not-supported | 11 | unexpected-changeKeys (TISSUE 90) | 11 |
| illegal-dhGroup-selected | 12 | **OsiDiagnostics** | |
| icv-algorithms-not-supported | 13 | no-reason-given | 0 |
| encrypt-algorithms-not-supported | 14 | protocol-error | 1 |
| aea-algorithms-not-supported | 15 | invalid-indirect-reference | 2 |
| invalid-attribute-certificate | 16 | invalid-pci | 3 |
| encr-mode-aea-not-supported | 17 | | |
| ae-is-required | 18 | | |
| altSig-mismatch | 19 → removed | | |
| aea-select-but-encryp-not-supp | 20 → 19 | | |
| invalid-ae-algorithm | 21 → 20 | | |
| single-ae-algorithm-required | 22 → 21 | | |
| ae-not-used | 23 → 22 | | |
| invalid-encryption-algorithm | 24 → 23 | | |
| single-encrypt-algo-required | 25 → 24 | | |
| single-icv-algo-required | 26 → 25 | | |

"a → b" is AMD1 Annex B as printed → after TISSUE 94 (in force since 16 July 2026), which removed `altSig-mismatch` and so restored the clause 14.2.1 numbering. The code keeps the Annex B values as its constants and maps them on the wire by policy: TISSUE numbering by default, Annex B with `Corrections = CorrectionsNone`, and values above 16 sent as `protocol-error` under `Edition2018` (R-03, R-27).

## 7.3 Encryption-mode negotiation (server) and checks (client)

**Server** with policy `{EncryptionPolicy: Forbid | Optional | Require; AEADPolicy: Never | Allow | Require}`:

| HandshakeReq | Server policy | Result per [B] | [T] expectation (if different) |
| --- | --- | --- | --- |
| aea present | AEAD Never | `encr-mode-aea-not-supported` (k) | `aea-algorithms-not-supported` (T50 #12): R-07 |
| aea present | encryption Forbid | `aea-select-but-encryp-not-supp` (l) | same |
| aea, no supported algorithm | — | `aea-algorithms-not-supported` (m) | same |
| non-aea | AEAD Require | `ae-is-required` (n) | same |
| non-aea with encr | encryption Forbid | `encryption-not-required` (q) | same |
| encr present, none supported | — | `encrypt-algorithms-not-supported` (r) | same |
| no supported ICV | — | `icv-algorithms-not-supported` (s) | same |
| `applProtected` set | encryption Forbid | `encryption-not-required` (w) | same |
| `applProtected` clear | encryption Require | `encryption-required` (z) | same |
| `applProtected` inconsistent with `encr` presence | — | `protocol-error` (design choice) | — |
| otherwise | — | accept; choose the **first** supported item in the client's order, a single algorithm per list, the same alternative, the same group, the same hmac | T50 #19 |

**Client** checks on HandshakeAcc, in [B] o)–y) order: different alternative → `ae-not-used` (t) ([T] T49 #11 expects `aea-algorithms-not-supported`: R-07); algorithm not proposed → `invalid-ae-algorithm` / `invalid-encryption-algorithm` (u) / `icv-algorithms-not-supported` (x: [B] names a non-existent `invalid-icv-algorithm`; [T] T49 #15 uses `icv-algorithms-not-supported`, which is adopted); count ≠ 1 → `single-*-required`; `encr` dropped although proposed → `encryption-required` (T49 #18); `encr` or AE added although not proposed → `encryption-not-required` (T49 #19, #20).

## 7.4 Alarm encoding setting (R-07)

[B] says: when an alarm is raised, `diag` is **absent**. [T] agrees on the client tables (49 #1, #4, #8). But the server tables (50 #2, #5, #9) and both data-transfer tables (51 #6, 52 #6, 53 #6, 54 #6) expect `no-reason-given`.

Setting: `e2e.Policy.AlarmDiagnostic = OmitDiagnostic (default) | NoReasonGiven`. It applies only to the alarm cases and is recorded in the PIXIT for a test campaign. Nothing else changes with it.

## 7.5 Security events

Events are typed structs delivered through `OnSecurityEvent`, over a bounded, non-blocking channel. Drops are counted as event `EventsDropped`. Each event carries the time, connection id, peer address, the AE titles (when known), the certificate fingerprint (SHA-256), the class (`Info`, `Warning`, `Incident`, `Alarm`), the code and the diagnostic sent. It **never** carries keys, Z, PRK or plaintext.

| Code | Class | Trigger | [B] text |
| --- | --- | --- | --- |
| `HandshakeAccepted` / `HandshakeRejected` | Info / Warning | association outcome | — |
| `CertificateTooLarge` | Warning | > 8192 octets | "warning: session termination due to unsupported public-key certificate size" |
| `RevocationUnavailable` | Warning | stale or missing CRL | "warning: certificate revocation information unavailable" |
| `CertificateRevoked` | Incident | revoked | "incident: revoked public-key certificate" |
| `CertificateExpired` | Warning | expired | "warning: expired public-key certificate" |
| `SignatureAlgorithmMismatch` | Alarm | 14.3.2 a) | — |
| `InvalidSignature` | Alarm | 14.3.2 c) | — |
| `AddressMismatch` | Alarm | 14.3.4 c) | — |
| `Replay` | Alarm | 14.3.4 g), 14.4.3 c) | — |
| `InvalidICV` / `InvalidICVAlgorithm` | Alarm | 14.4.2 | — |
| `DiagnosticSent` / `DiagnosticReceived` | Warning | any reject or abort with diag | — |
| `RekeyStarted` / `RekeyCompleted` / `RekeyTimeout` | Info / Info / Warning | 5.7 | — |
| `ClockRegression` | Warning | 5.5 | — |
| `ReleaseCompleted` / `AbortSent` / `AbortReceived` | Info / Warning / Warning | lifecycle | — |
| `PeerInvalidatedDuringAssociation` | Incident | 6.4 | — |
| `ResourceLimit` | Warning | handshake concurrency, sizes | — |

These map one to one onto IEC 62351-14 message identifiers once that mapping is defined. The diode logs them as `security_event=<code>` (13.7).

# 8. Library gap analysis ([R] at `2b7bb9620ae2`)

Each gap has an id that the work packages refer to. "Blocker" means E2E cannot work without the fix. "Conformance" means it is needed for [B] or [T]. "Hardening" means it is advisable regardless of E2E.

## 8.1 OSI layers

| Id | Location | Finding | Class | Fix |
| --- | --- | --- | --- | --- |
| G-TPKT-1 | `internal/osi/tpkt/tpkt.go:44` | Rejects any version ≠ 3; [B] H.3.2 says ignore the field | Conformance | Accept any version; count and log it once per connection |
| G-TPKT-2 | `tpkt.go:17` | `MaxPacket` 1 MiB (the header limits it to 65 535 anyway) | Conformance | Limit to `tpduSize + 7`, at most 2056 in 62351-4 mode ([B] H.3.3, R-19) |
| G-COTP-1 | `internal/osi/cotp/accept.go` | Accepts any TPDU size code from the CR | Hardening | Clamp to 7–11 (128–2048) for class 0 |
| G-COTP-2 | `cotp.go:189-207` | TSDU reassembly is unbounded | Hardening (DoS) | Configurable limit (default 64 KiB; E2E: `localDetail + 1 KiB` after association) |
| G-COTP-3 | `accept.go` | TSEL length not checked | Conformance | Abort if > 32 octets ([B] H.2.3) |
| G-COTP-4 | — | ED/AK/EA/RJ TPDUs are an error today | Conformance | Ignore them ([B] H.2.2) |
| G-SES-1 | `internal/osi/session/session.go:241` | CONNECT/ACCEPT carry User Data PGI `0xC1`; Extended User Data `0xC2` is unsupported, both on send and on receive (`findUserData`, line 313) | **Blocker** | Send CONNECT user data in `0xC2` (always in 62351-4 mode; when > 512 octets otherwise). Accept both on receive. ACCEPT uses `0xC1` up to 65 539 |
| G-SES-2 | `session.go` | FINISH (SI 9) and DISCONNECT (SI 10) are defined but not implemented | **Blocker** (signed release) | `Finish(t, ud)`, `Disconnect(t, ud)`, and receive-side classification of FINISH, DISCONNECT, ABORT and DT |
| G-SES-3 | `session.go` | No CONNECT size limit or session parameter validation | Conformance | Enforce 10 240 on CONNECT user data; check version 2, duplex only, no TSDU maximum |
| G-PRES-1 | `internal/osi/presentation/presentation.go:56` | `BuildCP` proposes only ACSE and MMS | **Blocker** | `BuildCPContexts([]ContextDef)` with an E2E context (id 5) |
| G-PRES-2 | `presentation.go:100` (`Negotiate`) | Knows only ACSE and MMS; rejects others | **Blocker** | Generic abstract-syntax registry; `Negotiated` holds a map OID → id |
| G-PRES-3 | `presentation.go:371` (`UnwrapData`) | Ignores the presentation context identifier | **Blocker** / security | `UnwrapDataCtx() (ctx int, data []byte, err error)`; callers check `ctx` |
| G-PRES-4 | `presentation.go` | ARU and abort parsing take the first fully-encoded data and ignore the context | Conformance | Return the context id; require ACSE |
| G-ACSE-1 | `internal/osi/acse/acse.go:80` (`AARQFor`) | Wraps a pre-encoded MMS PDU in an EXTERNAL with fixed context 3; password mechanism only | **Blocker** | `AARQ{Context, Called, Calling, UserInfo []External, Auth *Authentication}` builder |
| G-ACSE-2 | `acse.go:421` (`parseUserInfo`) | Returns the first EXTERNAL's content and ignores the indirect reference | **Blocker** / security | Return every EXTERNAL with `IndirectRef` and the raw TLV span |
| G-ACSE-3 | `acse.go:206` | Unknown application context in the AARE falls back to the MMS context | **Blocker** | Explicit context handling; `e2eMmsAC` known; unknown → reject `application-context-name-not-supported` |
| G-ACSE-4 | `acse.go:262`, `281` | ABRT has only `abort-source`; RLRQ and RLRE are empty | **Blocker** | ABRT with `abort-diagnostic` and user-information; RLRQ and RLRE with reason and user-information; matching parsers |
| G-ACSE-5 | `acse.go:375` | AARQ parser ignores `sender-acse-requirements` and `mechanism-name`, and does not detect non-kernel fields | Conformance | Report the fields present, so native mode can enforce kernel-only ([B] 15.6.1) |
| G-ACSE-6 | `acse.go` | AARE reject cannot carry user-information | **Blocker** (ApplicationReject, SecReject) | Add user-information to the reject builder |

## 8.2 ASN.1

| Id | Finding | Fix |
| --- | --- | --- |
| G-ASN-1 | `Decoder.ReadTLV` returns content without its end-of-contents octets for indefinite lengths, and no raw spans | `ReadSpan() (Span{Tag, Header, Content, ContentWithEOC, Full []byte})`. Signatures use `ContentWithEOC` |
| G-ASN-2 | No GeneralizedTime type with the [B] 13.1.2 rules | `asn1.GeneralizedTime{Instant time.Time; Raw []byte}` with `Parse62351` and `Format62351` |
| G-ASN-3 | `BitString` named-bit encoding not DER-canonical in all cases | `NamedBits` helper for Version and ConfidentialityParms: trailing zero bits removed |
| G-ASN-4 | No receive check of [B] 10.4.4 (constructed strings below their size limits) | Optional strict-MMS mode in the MMS decoder: reject with a P-U-Abort-like abort, never a P-P-Abort |
| G-ASN-5 | Fuzz coverage only of the generic decoder | Fuzz targets per SecPDU and per EnvPDU (WP10) |

## 8.3 MMS association and data path

| Id | Location | Finding | Fix |
| --- | --- | --- | --- |
| G-MMS-1 | `mms/conn.go:159` | TLS handshake runs before the connect deadline is set (`SetDeadline` at line 179) | One context and deadline from the TCP dial to the end of the E2E handshake |
| G-MMS-2 | `mms/server_conn.go:172` | No handshake deadline on the server | `AcceptOptions.HandshakeTimeout` (default 10 s); `server.Server` sets it |
| G-MMS-3 | `server_conn.go:201` | `Authenticate` is called before the MMS initiate is parsed, but there is no cryptographic verification at all | Native mode verifies the E2E handshake first, then MMS, then `Authenticate` (7.1) |
| G-MMS-4 | `mms/transport.go:32-61` | `framing` sends and receives plain MMS | Interface `secLayer` with a plain and an E2E implementation (9.4) |
| G-MMS-5 | `conn.go:524-545` | `Close` sends a conclude and closes the socket; no ACSE release | `CloseContext`: conclude → RLRQ/RLRE (E2E: ReleaseReq/Rsp) → transport close; `Abort` remains for failures |
| G-MMS-6 | `server_conn.go:366` | On conclude, replies and closes immediately | Reply, then wait (bounded) for RLRQ; answer RLRE |
| G-MMS-7 | — | No MMS initiate-ErrorPDU encoder | Needed for ApplicationReject |
| G-MMS-8 | `mms/server_ext.go:22` | Comment says `TLS.PeerCertificates` is the *verified* chain; it is the offered chain (`VerifiedChains` is empty because of `InsecureSkipVerify`) | Correct the documentation; expose the verified chain from `iec62351` verification |
| G-MMS-9 | `server/server.go:395` | The server package never passes `Responding` (AE identity) or TLS deadlines | `server.WithAEIdentity`, `server.WithHandshakeTimeout`, `server.WithE2E` |
| G-MMS-10 | — | No TCP keep-alive configuration | `net.Dialer.KeepAliveConfig` and `net.ListenConfig.KeepAliveConfig` (idle 30 s, interval 10 s, count 3 → detection in about 1 min, [B] H.3.4) |

## 8.4 Security packages

| Id | Finding | Fix |
| --- | --- | --- |
| G-SEC-1 | No E2E, no A-profile | New packages (section 9) |
| G-SEC-2 | `iec62351/tls.go`: stale CRL fails closed; there is no "unavailable" class | Shared `pki.RevocationChecker` with an explicit policy; the TLS default is unchanged |
| G-SEC-3 | `tls.go:114`: tickets disabled on the server; no client session cache | Optional 62351-4 native TLS profile: tickets enabled with 2 h lifetime and key rotation; client `ClientSessionCache` ([B] 6.2.3) |
| G-SEC-4 | `tls.go:232`: Ed25519 accepted | Keep it for TLS (62351-3 allows it); E2E has its own allow-list |
| G-SEC-5 | DH code private to `gdoi` | Move to `internal/cryptox/dh`; `gdoi` imports it |
| G-SEC-6 | `docs/pics.md` rows 133 and 349 say N | Update only with evidence (WP12) |

# 9. Library architecture and API

## 9.1 Package layout

```text
iec62351/                 existing TLS profile (unchanged API)
iec62351/pki/             NEW  shared: trust stores, revocation checker, cert profile checks, events
iec62351/e2e/             NEW  public, environment-independent E2E core
   config.go              Identity, Policy, ClientConfig, ServerConfig, validation
   alg.go                 algorithm registry and OIDs
   pdu.go, pdu_codec.go   SecPDU types + BER codec with spans (uses go-iec61850/asn1)
   token.go               ClearToken1/2/3 build and check
   keys.go                DH, HKDF, key layouts, directional key state
   assoc.go               Association state machine (handshake, data, rekey, release, abort)
   diag.go                diagnostics, alarms, SecurityError
   events.go              SecurityEvent
iec62351/e2e/osi/         NEW  public OSI mapping on byte slices (EnvPDU wrap and unwrap,
                               OsiDiagnostics, context ids); used by mms AND by tase2
iec62351/aprofile/        NEW  (track A) MMS-Authentication-value codec, signer and verifier
internal/cryptox/dh/      moved from gdoi; MODP-2048, P-256
internal/cryptox/brainpool/   release 2, verification only
internal/osi/...          extended (section 8.1)
mms/                      security-mode plumbing, secLayer, release
client/, server/          options
cmd/ied-client, cmd/ied-server   flags for E2E and test hooks (PIXIT)
cmd/e2e-teq/              NEW  test-only fault-injection peer (section 15.3)
```

The `e2e` core imports only the standard library and `go-iec61850/asn1`. This keeps it reusable by `tase2` and testable in isolation.

## 9.2 Core API (sketch)

```go
package e2e

type AETitle struct {
    APTitle     asn1.OID // form 2
    AEQualifier int32    // >= 0
}
func (t AETitle) OID() asn1.OID // AP-title || AE-qualifier, the certificate subject value

type Identity struct {
    AE          AETitle
    Certificate []byte        // DER end-entity, <= 8192 octets
    Path        [][]byte      // DER CA certificates, top-down (anchor side first); may be empty
    Signer      crypto.Signer // RSA >= 2048 or ECDSA P-256
}

type EncryptionPolicy uint8 // Forbid, Optional, Require
type AEADPolicy uint8       // Never (release 1), Allow, Require
type AlarmDiagnostic uint8  // OmitDiagnostic (default), NoReasonGiven

type Policy struct {
    SignatureAlgs  []SigAlg  // accepted from peers; own algorithm follows the Signer
    DHGroups       []Group   // client: preference order (first is used); server: accepted
    ICVAlgs        []ICVAlg  // preference order
    CipherAlgs     []CipherAlg
    Encryption     EncryptionPolicy
    AEAD           AEADPolicy
    Freshness      time.Duration // <= 10m
    RekeyInterval  time.Duration // 15m..24h, client
    RekeyRequest   time.Duration // server: set reqRekey after this; 0 = never
    RekeyCarrier   RekeyCarrier
    AlarmDiagnostic AlarmDiagnostic
    Trust          *pki.TrustStore
    Revocation     *pki.RevocationChecker
    UnverifiedAttributeCertificates bool
    MaxCertPath    int // default 4
}

type ClientConfig struct {
    Local    Identity
    Peer     AETitle // called; the certificate must match
    Protocol string  // "IEC 61850-8-1"
    TLSProtected bool // sets confParams.tlsProtected; derived from the transport if zero
    Policy   Policy
    Clock    func() time.Time // nil = time.Now
    Rand     io.Reader        // nil = crypto/rand
    OnEvent  func(SecurityEvent)
}

type ServerConfig struct {
    Local     Identity
    Protocols []string
    Policy    Policy
    // Admit is called after the handshake is cryptographically verified,
    // before MMS initiate processing. Returning an error sends ApplicationReject.
    Admit     func(PeerSecurity) error
    Clock     func() time.Time
    Rand      io.Reader
    OnEvent   func(SecurityEvent)
}

type PeerSecurity struct { // immutable snapshot, no secrets
    Mode           Mode    // None, TLS, AProfile, E2E (bit set)
    AE             AETitle
    Certificate    *x509.Certificate // nil for brainpool until release 2; see Raw
    CertificateRaw []byte
    VerifiedChain  [][]byte
    AssoID         string
    Signature      SigAlg
    Group          Group
    ICV            ICVAlg
    Cipher         CipherAlg // zero when clear
    KeyEpoch       uint32
    ValidatedAt    time.Time
    TLS            *tls.ConnectionState // when TLS is also used
}

// Association is the environment-independent state machine. The environment
// (mms via e2e/osi, or tase2) owns I/O and calls these methods under its own
// write serialisation.
type Association struct { /* unexported */ }

func NewClient(cfg *ClientConfig) (*Association, error)
func NewServer(cfg *ServerConfig) (*Association, error)

func (a *Association) HandshakeRequest(initiate []byte) (secPDU []byte, err error)
func (a *Association) ProcessHandshakeRequest(secPDU []byte) (initiate []byte, err error) // *SecurityError
func (a *Association) HandshakeAccept(initiateResp []byte) ([]byte, error)
func (a *Association) ApplicationReject(initiateErr []byte, transient bool) ([]byte, error)
func (a *Association) SecReject(err *SecurityError) ([]byte, error)
func (a *Association) ProcessHandshakeResponse(rsp HandshakeRsp) (initiateResp []byte, err error)

func (a *Association) Seal(prpdu []byte) ([]byte, error)          // ClearTransfer / EncrTransfer
func (a *Association) Open(secPDU []byte) ([]byte, Control, error) // Control: rekey events, flags
func (a *Association) ReleaseRequest() ([]byte, error)
func (a *Association) ProcessRelease(secPDU []byte) error
func (a *Association) ReleaseResponse() ([]byte, error)
func (a *Association) Abort(cause error) (abort AssoAbort, err error) // DtSecAbort / ApplAbort / HandshakeSecAbort
func (a *Association) Peer() PeerSecurity
func (a *Association) Close() // forget keys

type SecurityError struct {
    Phase   Phase           // Handshake, Data
    Diag    int             // HandshakeDiagnostics or DtDiagnostics; -1 = none
    Alarm   AlarmCode       // non-zero = alarm; Diag omitted per AlarmDiagnostic
    Env     *OsiDiagnostic  // environment fault
    Event   SecurityEvent
    Err     error           // internal cause, never sent
}
```

`ApplData` wrapping (Annex F.3) is the environment's job. In OSI it lives in `e2e/osi`, so the core is protocol-agnostic as [B] 12.1 intends. The MMS context id is passed to the OSI mapper.

## 9.3 MMS, client and server API

```go
// mms
type ApplicationSecurity uint8
const (
    AppSecurityNone ApplicationSecurity = iota // plain MMS (password allowed)
    AppSecurityAProfile                        // track A
    AppSecurityE2E                             // native mode
)
type Options struct { // existing fields kept
    ...
    AppSecurity ApplicationSecurity
    E2E         *e2e.ClientConfig
    AProfile    *aprofile.Config
    KeepAlive   net.KeepAliveConfig
    ReleaseTimeout time.Duration
}
type AcceptOptions struct { // existing fields kept
    ...
    // Accept lists the application security modes accepted.
    // Native mode is selected by the client's application context.
    Accept           []ApplicationSecurity
    E2E              *e2e.ServerConfig
    AProfile         *aprofile.Config
    HandshakeTimeout time.Duration
}
func (c *Conn) PeerSecurity() e2e.PeerSecurity
func (c *Conn) CloseContext(ctx context.Context) error // conclude + release
func (c *Conn) Abort() error
func (sc *ServerConn) PeerSecurity() e2e.PeerSecurity

type AssociationRequest struct { // existing fields kept
    ...
    Security e2e.PeerSecurity // verified identity; zero value when none
}

// client
func WithE2E(cfg *e2e.ClientConfig) Option
func WithAEIdentity(called, calling mms.ACSEIdentity) Option
func WithKeepAlive(cfg net.KeepAliveConfig) Option
// server
func WithE2E(cfg *e2e.ServerConfig, accept ...mms.ApplicationSecurity) Option
func WithAEIdentity(id mms.ACSEIdentity) Option
func WithHandshakeTimeout(d time.Duration) Option
func WithMaxHandshakes(n int) Option // concurrent, before the association slot
```

Configuration validation (`e2e.ClientConfig.Validate`, called by `Dial`) fails immediately for:

- a missing AE title or a negative AE-qualifier;
- a certificate whose subject does not encode the local AE title;
- key usage without both `digitalSignature` and `keyAgreement`;
- an unsupported key type or size;
- a password combined with E2E (a password is a plain-mode concept);
- E2E and TLS using the same key;
- `Encryption == Require` with `AEAD == Never` and no `CipherAlgs`;
- a `RekeyInterval` outside 15 min–24 h.

**No downgrade.** A client with `AppSecurity = E2E` never retries in plain mode, whatever the peer answers.

## 9.4 Data-path integration

```go
// mms/transport.go
type secLayer interface {
    send(mmsPDU []byte) error          // called with the connection write lock held
    recv() (mmsPDU []byte, err error)  // single reader goroutine
    abort(cause error) error
    release(ctx context.Context) error
    peer() e2e.PeerSecurity
}
type plainLayer struct{ framing }      // today's behaviour
type e2eLayer struct {
    f     framing   // with E2E, MMS and ACSE context ids
    assoc *e2e.Association
    rekey *rekeyScheduler
}
```

- `e2eLayer.send`: `assoc.Seal(ApplData(mmsPDU))` → `osi.WrapData(e2eCtx, secPDU)` → session DT. All three steps run inside the existing `writeMu`, so the token-2 order equals the wire order. On the server, `pumpUnconfirmed` already takes `writeMu` per PDU. Reports and responses therefore interleave safely.
- `e2eLayer.recv`: session receive → classify (DT, ABORT, FINISH, DISCONNECT) → `UnwrapDataCtx`; a context other than E2E → environment abort `invalid-pci` → `assoc.Open` → `ApplData` indirect reference = MMS context → MMS bytes. Any `SecurityError` → `abort()` builds the DtSecAbort, sends the ABRT, closes, and `failAll` delivers the terminal error to every waiter.
- **Rekey**: `rekeyScheduler` only sets flags; `Seal` reads and clears them under the write lock. A due rekey with no traffic triggers the configured carrier (5.7).
- **Server conclude**: respond under E2E, then expect RLRQ within `ReleaseTimeout` (default 10 s), verify ReleaseReq, send RLRE with ReleaseRsp, close. A missing or invalid release → ABRT and close, with an event.
- The handlers above `mms` (`client`, `server` and the diode) see no difference except `PeerSecurity()` and the new events.

## 9.5 Concurrency and resource limits

- Handshake admission on the server: `WithMaxHandshakes(n)` (default 8) is acquired **before** reading the AARQ, and released after the AARE. A per-source-IP token bucket (default 5 per second, burst 10) protects the signature and DH work.
- Each association: one reader goroutine (existing), writes serialised (existing), a rekey timer, no extra goroutines per PDU.
- Memory: handshake replay cache bounded per peer AE (default 1024 entries, entries evicted once older than the freshness window plus 1 min); global cap 64 Ki entries.

# 10. Library work packages

Estimates are indicative engineer-weeks (ew) for one engineer familiar with the codebase, excluding external lab time. Each work package ends with tests and documentation.

## WP0 — Contract freeze (prerequisite; 1.5–2.5 ew)

| Task | Output | Exit criterion |
| --- | --- | --- |
| 0.1 PICS/PIXIT draft for the target profile (DEC-1…DEC-11) | `docs/iec62351-4-pics.md`, `docs/iec62351-4-pixit.md` | Reviewed by the owner and the test laboratory |
| 0.2 Obtain the IEC code-component archive; diff Annexes A, B, D, F with the OCR transcription | `internal/e2e/asn1/` modules, provenance note | Every item R-01…R-05 confirmed or re-opened |
| 0.3 Test-vector set: handshake, key derivation (all R-12 variants), clear, GMAC, CBC, rekey, release, aborts | `testdata/e2e/vectors/*.json` with hex PDUs | Each vector verified by the independent oracle (15.2) |
| 0.4 Resolve the R-register with the laboratory or test-equipment vendor | Register updated with decisions | No open item that blocks release-1 scope |
| 0.5 Confirm the X.520 `objectIdentifier` attribute type OID and encoding | Note in PICS | Fixture certificate decodes |

## WP1 — ASN.1 foundation (1–1.5 ew)

- `asn1.Span` API (G-ASN-1) with indefinite-length EOC inclusion. Unit tests: definite and indefinite, nested indefinite, truncated input, a length overflowing the parent.
- `GeneralizedTime` per 5.6 (G-ASN-2): table-driven valid and invalid cases, round trip of canonical form.
- `NamedBits` (G-ASN-3), `UTF8String` NMTOKEN validator (the [B] character ranges), ENUMERATED, BOOLEAN DEFAULT FALSE.
- Limits: `DecodeLimits{MaxDepth, MaxElements, MaxOctetString, MaxSeqOf}` passed to the SecPDU decoder.
- Exit: `go test ./asn1 -race`; fuzz for 10 min with no crash; coverage of the new code ≥ 90 %.

## WP2 — Cryptographic primitives (1–1.5 ew)

- `internal/cryptox/dh`, moved from `gdoi` with its tests; P-256 per R-13.
- `e2e/alg.go` registry; signer and verifier adapters (RSA PKCS#1 v1.5 SHA-256, ECDSA P-256 SHA-256 with DER signature value, R-14).
- HKDF schedule and key layouts (5.3); MACs (HMAC-SHA-256, GMAC); AES-CBC with the R-09 padding.
- Exit: RFC 5869 vectors, NIST GCM vectors, Wycheproof ECDSA and HMAC subsets pass; constant-time compare everywhere.

## WP3 — SecPDU codec (2–3 ew)

- Go types for all SecPDUs and tokens (4.6), with `Span` fields for `tbs`, `tbp` and ClearToken2.
- Encode (definite lengths, canonical) and decode (strict structure, extension tolerance per 4.6, SIZE constraints deferred to the semantic layer).
- Both Authenticator tagging variants behind R-04, Annex B by default.
- Fuzz targets: `FuzzHandshakeReq`, `FuzzHandshakeRsp`, `FuzzAssoAbort`, `FuzzClearTransfer`, `FuzzEncrTransfer`, `FuzzRelease`.
- Exit: round trip of every vector; decoding of every fault class in [T] Tables 49–54 produces the expected internal classification.

## WP4 — E2E core state machine (3–4 ew)

- `Association` (9.2): handshake (client and server), algorithm negotiation (7.3), check order (7.1), `SecurityError` mapping, alarm encoding (7.4).
- Data protection (5.4), token rules (5.5), rekey state machine (5.7), release, aborts, `assoID` allocation (per peer, 1–3 digits, unique among live associations), handshake replay cache.
- Clock and randomness injection; `Close` clears key references.
- Exit: table-driven tests for every row of section 7; property tests for token sequencing; `-race` tests with concurrent Seal and Open across a rekey.

## WP5 — PKI and identity (2–2.5 ew)

- `iec62351/pki`: `TrustStore` (atomic snapshot, at least two anchors), `RevocationChecker` (CRL loader and refresher, classes `Good`/`Revoked`/`Unknown`/`Unavailable`, policy), certificate profile checks (6.2), identity binding (6.3), events.
- Move the CRL logic out of `iec62351/tls.go` with identical TLS behaviour (regression tests unchanged).
- A test PKI generator (`internal/testpki`) producing E2E certificates with the OID subject, with and without key usage, expired, revoked and oversized variants.
- Exit: every check in 6.2 has a positive and a negative test; TLS tests are unchanged.

## WP6 — OSI upper layers (2–3 ew)

- Session: G-SES-1…3; presentation: G-PRES-1…4; ACSE: G-ACSE-1…6; COTP and TPKT: G-TPKT-1…2, G-COTP-1…4; keep-alive (G-MMS-10).
- `iec62351/e2e/osi`: wrap and unwrap for OSI-AssoReq, AssoRsp, AssoAbr, AssoRelReq, AssoRelRsp, ClearTransfer, EncrTransfer; `ApplData` (F.3); OsiDiagnostics.
- Plain-mode regression: every existing interop test (libiec61850, Wireshark captures in `testdata`) stays green, including proper ACSE release in plain mode, as a 61850-8-1 conformance improvement.
- Exit: golden EnvPDU encodings for every row of [T] Tables 68–75; plain interop unchanged.

## WP7 — MMS integration (2.5–3.5 ew)

- `secLayer` (9.4); client and server handshake paths; the native or plain decision on the server by application context; ApplicationReject with initiate-ErrorPDU (G-MMS-7); signed release (G-MMS-5/6); `Abort`; deadlines (G-MMS-1/2); `PeerSecurity`; `AssociationRequest.Security`.
- Exit: library client ↔ library server E2E association, clear transfer of every MMS service the library supports (read, write, reports, files, journals, control including CommandTermination ordering), rekey under load, release and abort; `-race` clean.

## WP8 — Public API, tools and events (1–1.5 ew)

- `client.WithE2E`, `server.WithE2E`, `WithAEIdentity`, `WithHandshakeTimeout`, `WithMaxHandshakes`, `WithKeepAlive`.
- `cmd/ied-server` and `cmd/ied-client`: flags `-e2e-cert`, `-e2e-key`, `-e2e-path`, `-e2e-ca`, `-e2e-crl`, `-ae`, `-peer-ae`, `-e2e-icv`, `-e2e-encrypt`, `-rekey`, `-alarm-diag`. `-events json` prints every security event as JSON (this answers PIXIT "how the DUT exposes events and validation results"). `-force-rekey` and `-force-release` are interactive commands (PIXIT "how the DUT is forced to…").
- Exit: documented in `docs/api.md` and `SKILL.md`; example programs `examples/e2e-client`, `examples/e2e-server`.

## WP9 — Encryption, non-AE (1.5–2 ew; after R-09 is resolved)

- AES-128/256-CBC with HMAC or GMAC ICV, encrypt-then-MAC, IV handling, `encryption-*` diagnostics, padding-oracle-safe error handling.
- Exit: [T] Tables 21, 22, 23, 53, 54 pass against the TEQ emulator; vectors pass.

## WP10 — Test infrastructure (2–3 ew, in parallel)

- `cmd/e2e-teq`: a scriptable peer acting as client or server that can emit every malformed EnvPDU and SecPDU of [T] Tables 16, 17, 19, 20, 22, 23 and 49–54, and assert the device's response (section 15.3).
- The independent oracle (15.2). CI: `go test -race ./...`, fuzz smoke runs (2 min per target per pull request, nightly 1 h), a vector-verification job and a 24 h soak with a 15 min rekey.

## WP11 — T-security alignment (0.5–1 ew)

- `iec62351.NativeModeOptions` (opt-in): suites `0xC02B, 0xC02F, 0x003C, 0xC02C, 0xC030` in that order, TLS 1.2 only; server tickets enabled with a 2 h lifetime and rotation; client session cache. The default IEC 62351-3 profile is unchanged.
- A guard test: configuring `0xC023` or `0xC024` as an "IEC 62351-4" suite fails (R-10).
- Exit: PICS rows for Tables 8 and 10 filled honestly.

## WP12 — Documentation and conformance package (1 ew)

- `docs/pics.md` (rows 133, 341, 349), new PICS and PIXIT, `docs/developer-guide.md` (security layer), `docs/api.md`, this plan as `docs/iec62351-4-implementation-guide.md`, the trace matrix `docs/iec62351-4-trace.csv` (requirement → code → test → evidence).

**Library total, release 1 (WP0–WP8, WP10–WP12):** about 21–30 ew. WP9 (encryption) adds 1.5–2 ew.

# 11. T-security (TLS) position

| Requirement | Go 1.27 | Plan |
| --- | --- | --- |
| Native mandatory suites ([B] Table 10) | 0x003C yes (explicit enable); 0x00A0 no; 0x009E no; 0xC02B yes | Declare 0x00A0 and 0x009E N. DEC-7 |
| Compatibility mandatory suite ([B] Table 8; TISSUE 129: `TLS_DHE_DSS_WITH_AES_128_CBC_SHA` 0x0032) | no (no DSS) | Declare N; compatibility mode TLS remains out of scope |
| Resumption ([B] 6.2.3) | yes (tickets, client cache) | WP11 |
| Renegotiation ([B] 6.2.4) | client can only accept a server's request; server: none | Declare N. Long associations re-evaluate certificates (6.4) and rekey at the application layer (E2E) |
| ≥ 2 trust anchors, 8192-octet certificates, CRL period, events | yes / yes / via `pki` / yes | WP5 |
| Port 3782, TLS can be disabled | yes | unchanged |

**Alternatives that were rejected:**

- An OpenSSL backend through cgo breaks the static, cgo-free build the diode requires.
- A fork of `crypto/tls` adding DHE and static DH means owning a TLS implementation.
- A TLS terminator only protects its own hop.

If a procurement **requires** the full native T-profile, a separate decision record is needed. E2E conformance per [T] does not depend on these TLS rows, but [T] expects T-profile testing to precede it, so agree the declared TLS profile with the laboratory first.

# 12. Track A — compatibility mode (A-security profile, optional)

**Why consider it.** ICCP links and older IEC 61850 devices built against IEC TS 62351-4:2007 use it. Without it, the diode cannot authenticate at the application layer to such a peer. [T] does not test it, so the evidence must come from interoperability tests.

**Wire format** ([B] 11, Annex A):

- Application context `basic-AC` (`1.0.9506.2.3`).
- `sender-acse-requirements` / `responder-acse-requirements` with the `authentication` bit set.
- `mechanism-name` = `1.0.840.0.1.0.1.1`.
- `calling-authentication-value` / `responding-authentication-value` = `[12]/[10] EXPLICIT` → `external [2] IMPLICIT SEQUENCE { [indirect-reference INTEGER], [0] MMS-Authentication-value }`.
- `MMS-Authentication-value` = `[0] IMPLICIT SEQUENCE { [0] certificate OCTET STRING, [1] time GeneralizedTime, [2] signature OCTET STRING }`.
- The signature is RSASSA-PKCS1-v1_5 with SHA-256 over the **content octets** of the GeneralizedTime. RSA ≥ 2048.

**Context `mmsAuthenticationAS`** ([B] 11.1.3):

- The client may propose it. It is recommended to remember, per peer, whether the peer accepted it, and to omit it otherwise.
- Include the indirect reference only when the context was negotiated.
- The server must accept an AARQ without the context, and must echo the context when it was proposed.

**Server checks, in order** ([B] 11.2.3.2):

1. A non-authentication error → AARE reject per X.227, without `responder-acse-requirements`.
2. No mechanism-name → AARE `rejected-permanent` with `authentication-mechanism-name-required`.
3. Invalid certificate → P-ABORT.
4. Time more than 10 min off → P-ABORT.
5. The same time value twice within 10 min → P-ABORT. The cache is per peer certificate and survives across associations.
6. Bad signature → P-ABORT.

**Client checks** ([B] 11.2.4.2) are the same, except that a missing mechanism-name produces an ABRT from the `acse-service-provider` with `authentication-mechanism-name-required`.

**Implementation:**

- Package `iec62351/aprofile` (codec, signer, verifier, replay cache).
- ACSE builder support for `Auth`.
- The MMS `AppSecurityAProfile` path.
- Reuse `pki` for certificate checks. The A-profile certificate is a different credential from the TLS one: recommended practice, mandatory only for E2E (G.2).
- Configuration validation: the A-profile requires T-security ([B] 7.1 a)). Refuse it on plain TCP unless `AllowWithoutTLS` is set, which is for lab use only.

**Effort:** 2–3 ew. Tests: vector-based, negative cases a)–f), and interop with at least one independent ICCP implementation identified during WP0.

# 13. datadiode-mms integration

## 13.1 Architectural constraint: the diode terminates E2E

[B] 15.5 allows intermediate entities only as *routers*. They forward EnvPDUs unchanged, in both directions, and the association runs end to end. The diode cannot do this:

- The physical link is one-way, but the handshake, ICV-protected requests and responses, rekey, `changedKey` and release are all two-way exchanges.
- `dd-outer` is a different MMS server, with its own state (replica model, report control blocks, staleness), and answers clients that the device never sees.
- Carrying the device's E2E keys or private key across the diode would put device credentials in the DMZ, which defeats the purpose of the diode.

Consequently:

- **Two independent E2E associations**: A (device ↔ dd-inner, OT PKI) and B (DMZ client ↔ dd-outer, DMZ PKI). The diode frames between them keep their existing HMAC-SHA-256 authentication.
- **Security claim**: a DMZ client gets end-to-end authenticity, integrity and (optionally) confidentiality **to the replica**, not to the device. The provenance of the data relies on: (1) association A being authenticated, (2) the integrity of the dd-inner host, and (3) the diode frame HMAC. Section 13.6 makes (1) visible on the DMZ side.
- Customer-facing documents must say "IEC 62351-4 E2E on each MMS leg", never "end to end through the diode".

## 13.2 Topology and key custody

```text
 OT trust domain                         | diode |             DMZ trust domain
 Device (IED / ICCP server)              |       |             SCADA / ICCP peer (E2E client)
   ^  E2E association A                  |       |               ^  E2E association B
   |  (device = server, inner = client)  |       |               |  (outer = server, client = client)
   v                                     |       |               v
 dd-inner  ---- UDP frames, HMAC-SHA-256, one-way ---->   dd-outer (replica)
   keys: OT E2E cert+key, OT trust,      |       |        keys: DMZ E2E cert+key, DMZ trust,
         optional OT TLS cert+key,       |       |              optional DMZ TLS cert+key,
         diode HMAC key                  |       |              diode HMAC key
```

| Secret | Where | Never at |
| --- | --- | --- |
| Device E2E private key | device | dd-inner, dd-outer |
| dd-inner E2E private key (OT PKI) | dd-inner host, file mode 0600 or HSM/TPM | dd-outer |
| Replica E2E private key (DMZ PKI) | dd-outer host | dd-inner, device |
| Diode HMAC key | both diode hosts | elsewhere |
| E2E session keys (A, B) | process memory of each endpoint | disk, logs, wire records |

## 13.3 Identity of the replica (DEC-9)

Today the replica answers with the **device's** ACSE identity, so that DMZ clients configured for the device accept it (`internal/replica/iec61850/server.go:217`, `respondingIdentity`). Under E2E that identity becomes **cryptographic**: the client checks that the responding (or called) AE title equals the subject OID of the replica's E2E certificate (6.3).

| Option | How | Pros | Cons |
| --- | --- | --- | --- |
| **A. Mirror the device AE title** (default) | The DMZ CA issues the replica a certificate whose subject OID is the **device's** AE title. The device key never leaves OT | DMZ clients need no reconfiguration (the project's "transparent copy" goal) | Within the DMZ PKI, the replica *is* that AE; operators must manage that this certificate is never issued to anything else |
| B. Own AE title | The replica has its own AP-title and AE-qualifier and a matching certificate | Clean separation of identities | Every DMZ client is reconfigured to the replica's AE title |

**Enforcement:**

- At startup, the configured E2E certificate subject OID must equal `server.e2e.ae` (option B) or `server.e2e.expect_device_ae` (option A, when configured).
- In option A, the outer also checks at model-ready time that the device AE title learned over the diode (`wire.Negotiation`, filled from `iec61850adapter/census.go:426`) equals the certificate subject. On mismatch it **does not open** the E2E listener, and logs `security_event=replica-identity-mismatch`.
- TASE.2 uses the configured `server.tase2.local_ap_title` and `local_ae_qual`, which already exist.

## 13.4 Inner leg (dd-inner as E2E client)

**Changes:**

1. Configuration: `device.ae` (IEC 61850 profile; TASE.2 already has `device.tase2.local_*` and `remote_*`), `device.e2e` (13.8).
2. `internal/e2eprofile` (new, modelled on `internal/tlsprofile`): load and validate the files, build `e2e.ClientConfig`, wire events to slog and counters.
3. `internal/inner/iec61850adapter/census.go:73`: pass `Called` and `Calling` identities, `AppSecurity` and `E2E`. The same for the profile probe (`internal/inner/service.go:337`), so `auto` works with E2E.
4. TASE.2: `internal/inner/tase2adapter/census.go:55` passes the E2E configuration to `tase2.Endpoint` once track 14 exists.
5. **Reconnect classification** in `inner.Service`:

| Failure | Behaviour |
| --- | --- |
| Transport (TCP, TLS), timeout | existing backoff from `backoff_min` |
| E2E `HandshakeSecReject` with diag, ApplicationReject | `backoff_max` at once; log `security_event=e2e-rejected diag=<name>`; `/status` `inner_e2e_last_reject` |
| Alarm (no diag), invalid signature, address mismatch, revoked or expired device certificate | `backoff_max`; `security_event` at error level; counter `inner_e2e_alarms` |
| DtSecAbort or ApplAbort during the data phase | reconnect with the minimum backoff once, then normal backoff (the device may have restarted) |
| Rekey timeout | reconnect, counter `inner_rekey_timeouts` |

   Never retry without E2E (no downgrade).

6. **Rekey**: client-driven at `device.e2e.rekey_interval` (default 1 h, range 15 min–24 h); `reqRekey` from the device is honoured. Integrity sweeps and report traffic carry the rekey flag, so the `Identify` carrier is rarely needed.
7. **Certificate monitoring**: log own and device certificate expiry at 30, 7 and 1 days; raise an incident when the device certificate is revoked mid-association (6.4) → `ApplAbort`, reconnect.

## 13.5 Outer leg (dd-outer as E2E server)

**Changes:**

1. Configuration: `server.e2e` (13.8), including `mode` = `off` | `optional` | `required`. `optional` accepts plain AARQs (`basic-AC` or the ACSI context) and E2E AARQs (`e2eMmsAC`) on the same listener, as [B] 5.1 "DON'T_CARE" envisages for transport. `required` rejects plain AARQs with `application-context-name-not-supported`.
2. `internal/replica/iec61850/server.go:205-257`: set `AcceptOptions.Accept`, `E2E`, `HandshakeTimeout` (default 10 s), and the concurrent-handshake limit. This limit sits **before** the association slot, so a handshake flood cannot exhaust `max_associations`.
3. **Admission** (`ServerConfig.Admit`): `server.e2e.clients` is an allow-list of client AE titles and/or certificate SHA-256 fingerprints, which replaces the password for E2E associations. A password configured together with `mode: required` is a configuration error. With `optional`, the password applies to plain associations only.
4. **Readiness**: the E2E listener opens only when (a) the model is complete (existing gate), (b) the replica identity check of 13.3 passes, and (c) when `readiness.require_inner_security` = `"e2e"` or `"tls"`, the inner leg reports at least that level (13.6).
5. **Rekey requests**: `server.e2e.request_rekey_after` (default 0 = never); the client drives rekeying.
6. **Reports**: no functional change. Reports go through `SendUnconfirmed` → `pumpUnconfirmed` → `e2eLayer.send` under `writeMu` (9.4). The "after the response" ordering for CommandTermination and write-provoked reports is preserved, because ordering happens above `secLayer`.
7. **Read-only enforcement** is unchanged. E2E authentication does not grant control rights; writes stay refused by the existing policy.

## 13.6 New diode record: inner security status

Add a `SecurityStatus` record type to `internal/wire/record.go`. It is HMAC-protected like every frame.

| Field | Type | Meaning |
| --- | --- | --- |
| `leg_mode` | enum | `plain`, `tls`, `aprofile`, `e2e`, `tls+e2e`, `tls+aprofile` |
| `association_state` | enum | `connected`, `retrying`, `failed-security`, `failed-transport` |
| `device_ae` | OID | AE title authenticated by E2E (or empty) |
| `device_cert_sha256` | 32 octets | fingerprint of the device E2E (or TLS) certificate |
| `device_cert_not_after` | time | expiry |
| `algorithms` | string | e.g. `rsa2048-sha256/dh14/hmac-sha256/clear` |
| `last_handshake`, `last_rekey` | time | — |
| `alarms`, `incidents` | counters | since dd-inner start |
| `generation` | uint | links the status to the model generation |

- dd-inner sends it on every change and with every model refresh.
- dd-outer exposes it under `/status.inner_security`, uses it for the `readiness.require_inner_security` gate, and logs every change.
- Optional `diode.forward_security_events` (default **off**) forwards OT security events (codes and counts, never certificates or addresses) to the DMZ log. Forwarding OT security telemetry into the DMZ is a site policy decision.
- Wire compatibility: an outer that does not know the record type ignores it (the existing TLV extensibility). A new outer receiving from an old inner reports `inner_security: unknown`.

## 13.7 Observability

**Logs:** `security_event=<code>` with `leg=inner|outer`, `peer`, `peer_ae`, `cert_sha256`, `diag` and `alarm`, at warn or error level. These are suitable as an IEC 62351-14 source. Key material is never logged.

**`/status` additions:**

- dd-inner: `e2e: {mode, device_ae, algorithms, assoc_id, last_handshake, last_rekey, key_epoch, alarms, incidents, rejects_by_diag{}, cert_expiry{own, device}}`.
- dd-outer: `e2e: {mode, identity, handshakes_ok, handshakes_failed, alarms, rejects_by_diag{}, active_e2e_associations, cert_expiry}` and `inner_security` (13.6).

**dd-probe:** `-e2e-cert`, `-e2e-key`, `-e2e-path`, `-e2e-ca`, `-e2e-crl`, `-ae`, `-peer-ae`, `-e2e-encrypt`. It prints the negotiated algorithms, the peer AE, the certificate chain, `assoID` and the result of each check. This is the commissioning tool for association A.

## 13.8 Configuration schema

`dd-inner` (new keys only):

```json
{
  "device": {
    "ae": { "ap_title": "1.3.9999.10.1", "ae_qualifier": 1 },
    "peer_ae": { "ap_title": "1.3.9999.20.7", "ae_qualifier": 1 },
    "app_security": "e2e",
    "e2e": {
      "cert": "/etc/datadiode/e2e/dd-inner.pem",
      "key": "/etc/datadiode/e2e/dd-inner.key",
      "path": ["/etc/datadiode/e2e/ot-issuing-ca.pem"],
      "ca": ["/etc/datadiode/e2e/ot-root-a.pem", "/etc/datadiode/e2e/ot-root-b.pem"],
      "crl": ["/etc/datadiode/e2e/ot.crl"],
      "crl_refresh": "24h",
      "revocation_unavailable": "warn",
      "dh_groups": [23, 14],
      "icv": ["hmac-sha256", "aes128-gmac"],
      "encryption": "forbid",
      "cipher": ["aes128-cbc"],
      "rekey_interval": "1h",
      "freshness": "10m",
      "alarm_diagnostic": "omit"
    }
  }
}
```

`dd-outer` (new keys only):

```json
{
  "server": {
    "e2e": {
      "mode": "required",
      "identity": "device",
      "expect_device_ae": { "ap_title": "1.3.9999.20.7", "ae_qualifier": 1 },
      "ae": null,
      "cert": "/etc/datadiode/e2e/replica.pem",
      "key": "/etc/datadiode/e2e/replica.key",
      "path": [],
      "ca": ["/etc/datadiode/e2e/dmz-root.pem"],
      "crl": ["/etc/datadiode/e2e/dmz.crl"],
      "clients": [ { "ae": "1.3.9999.30.1.1" }, { "cert_sha256": "9f2c..." } ],
      "encryption": "optional",
      "request_rekey_after": "0s",
      "handshake_timeout": "10s",
      "max_handshakes": 8,
      "alarm_diagnostic": "omit"
    },
    "bilateral_tables": [
      { "name": "BLT1", "remote_ap_title": "1.1.999.3", "remote_ae_qual": 12,
        "transport": "secure", "application": "end-to-end",
        "peer_cert_sha256": ["9f2c..."], "domains": ["SUB_A"] }
    ]
  },
  "readiness": { "require_inner_security": "e2e" },
  "diode": { "forward_security_events": false }
}
```

**Validation rules** (added to `internal/config/config.go` `validate`):

- `app_security` ∈ {`none`, `aprofile`, `e2e`}.
- `e2e` requires `ae` and `peer_ae` (inner) or `identity` (outer). With `identity: own`, `ae` is required.
- At least one `ca`. `rekey_interval` within 15 min–24 h. `freshness` ≤ 10 min. `encryption: require` needs `cipher`.
- `password` with `app_security: e2e`, or with `mode: required`, is an error.
- The E2E and TLS certificates must not share a public key (checked by the loader).
- `bilateral_tables[].application: end-to-end` requires `server.e2e.mode` ≠ `off`.
- Unknown keys stay an error (existing behaviour).

## 13.9 Work breakdown — application

| WP | Content | Depends on | Estimate |
| --- | --- | --- | --- |
| D1 | Configuration schema, defaults, validation and `-dump-config`; README configuration tables | WP8 API | 1 ew |
| D2 | `internal/e2eprofile` loader (files, key and certificate checks, identity OID, pool, events → slog and counters); unit tests with `internal/testutil/pki.go` extended for OID subjects | WP5 | 1–1.5 ew |
| D3 | Inner: adapters, probe, reconnect classification, rekey settings, certificate monitoring | WP7 | 1–1.5 ew |
| D4 | Outer: accept modes, admission allow-list, handshake limits, identity checks, readiness gate | WP7 | 1.5–2 ew |
| D5 | Wire record `SecurityStatus`, send and receive, `/status`, readiness gate | D3 | 1 ew |
| D6 | Observability: events, `/status`, counters | D3, D4 | 0.5 ew |
| D7 | dd-probe E2E flags | WP8 | 0.5 ew |
| D8 | TASE.2 leg (needs track 14) | S1–S4 | 1–1.5 ew |
| D9 | Documentation: README sections "E2E security (IEC 62351-4)", PKI runbook, commissioning checklist, failure diagnosis table; `docs/wire-protocol.md` record; `proposal.md` correction (13.12) | all | 1 ew |
| D10 | Tests (13.10) | all | 2 ew |

**Application total:** about 10.5–13.5 ew (IEC 61850 profile), plus D8 for TASE.2.

## 13.10 Application test plan

| Id | Scenario | Expected |
| --- | --- | --- |
| DT-1 | Inner E2E ↔ `ied-server -e2e`; outer plain; client plain | Model replicated; `inner_security.leg_mode=e2e` |
| DT-2 | Inner plain; outer E2E `required`; `ied-client -e2e` | Client associates; plain client refused with `application-context-name-not-supported` |
| DT-3 | Both legs E2E, identity `device` | DMZ client configured for the device AE title associates without changes |
| DT-4 | Identity mismatch (replica certificate ≠ device AE) | E2E listener stays closed; `security_event=replica-identity-mismatch` |
| DT-5 | Device certificate revoked (CRL updated while running) | Inner `ApplAbort`, reconnect fails with alarm; outer `inner_security.association_state=failed-security`; with `require_inner_security` the outer leaves ready |
| DT-6 | Rekey 15 min on both legs during a 24 h soak at full report load | No DtSecAbort; ≥ 96 rekeys per leg; no message loss on the diode |
| DT-7 | Device sends `reqRekey` | Inner rekeys on its next PDU |
| DT-8 | DMZ handshake flood (1000 AARQs/s, invalid signatures) | Established clients unaffected; CPU bounded; counters show refusals |
| DT-9 | Clock step of −5 min on the dd-inner host | Inner holds the time value (5.5); event `ClockRegression`; no reject within the freshness window |
| DT-10 | Report storm (BRCB GI on 1 000 data objects) with E2E on both legs | Order and content identical to the plain run (captures compared after unwrapping) |
| DT-11 | Old outer and new inner (record compatibility) | Outer ignores `SecurityStatus`; replication unaffected |
| DT-12 | TASE.2 leg with BLT `application: end-to-end` (after track 14) | BLT-bound peer associates; others refused |

## 13.11 Operations

- **PKI issuance:** a CSR tool, `go-iec61850/cmd/e2e-csr` (part of WP8), generates a key (RSA-2048 or P-256) and a CSR with the single-RDN `objectIdentifier` subject and key usage `digitalSignature` + `keyAgreement`, because common CA front ends cannot express this subject. The runbook covers OT CA issuance for dd-inner, DMZ CA issuance for the replica (including option A), CRL publication and refresh, and certificate rotation (restart today; hot reload is a later improvement, consistent with the existing TLS behaviour).
- **Commissioning checklist:**
  1. Time synchronisation on all hosts.
  2. `dd-probe` E2E against the device.
  3. Check the device AE title and certificate.
  4. Start dd-outer, check `identity` and readiness.
  5. Run a DMZ client test.
  6. Force a rekey (`rekey_interval: 15m` during commissioning).
  7. Run a revocation drill.
- **Failure diagnosis table** (README): `invalid-signatureAlgorithm` → algorithm policy mismatch; alarm with no diag on the client → check the device AE title against its certificate subject; `invalid-time-value` → NTP; `invalid-certification-path` → missing `path` or wrong `ca`; `encryption-required` / `-not-required` → align `encryption` with the peer; `application-context-name-not-supported` → peer not in native mode.

## 13.12 Corrections to existing project documents

- `datadiode-mms/proposal.md:75` says "Cipher suites — all supported by Go-Crypto. All listed by 62351-3 except DH_DSS/DH_RSA". This is inaccurate for IEC 62351-4. Go also lacks `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` (mandatory in [B] Table 10). `TLS_RSA_WITH_AES_128_CBC_SHA256` is available only when explicitly enabled. The compatibility-mode mandatory `TLS_DH_DSS_WITH_AES_256_CBC_SHA` is unavailable. Replace the line with: "TLS per IEC 62351-3 (ECDHE with AES-GCM). Of the IEC 62351-4 native-mode mandatory suites, the DH_RSA and DHE_RSA suites, and TLS renegotiation, are not available in the Go TLS implementation and are declared as deviations. Application-layer security is provided by IEC 62351-4 E2E."
- `datadiode-mms/proposal.md:79` ("the contractor must provide the IEC 62351-4 standard"): satisfied. Replace it with a reference to this plan and to WP0.2 (code-component archive).
- `go-iec61850/mms/server_ext.go:22`: documentation fix (G-MMS-8).

# 14. Track S — TASE.2 stack (`tase2`)

The diode's ICCP leg runs on `tase2`'s own ISO stack (`tase2/iso/acse.go`, `transport.go`, `server_listener.go`), not on `go-iec61850/mms`. The `go-iec61850` work does not cover it automatically.

| WP | Content | Estimate |
| --- | --- | --- |
| S1 | Add a dependency on `go-iec61850/iec62351/e2e` and `/e2e/osi`, or vendor them. Recommend the dependency: `datadiode-mms` already uses both modules through `replace`. Decide the module version policy | 0.5 ew |
| S2 | `tase2/iso`: three presentation contexts, Extended User Data in CONNECT, E2E AARQ/AARE/ABRT/RLRQ/RLRE through `e2e/osi`, strict context routing in `Association.Receive` and `Send`, signed release | 2–3 ew |
| S3 | `tase2/tase2`: endpoint options (`SetE2EConfig`), `pp = "IEC 60870-6-503"` (R-17), bilateral-table security per [B] 5.1 (transport `DONT_CARE`/`NON_SECURE`/`SECURE`; application `NON_SECURE`/`SECURE`/`END-TO-END SECURE`; binding of certificate information to the BLT); association parameters exposed to the BLT check | 1.5–2 ew |
| S4 | A-profile in `tase2/iso` (if track A is chosen); tests against an independent ICCP peer | 1–1.5 ew |

**Total:** about 5–7 ew.

# 15. Verification and conformance

## 15.1 Test layers

| Layer | What | Where | Gate |
| --- | --- | --- | --- |
| Unit | ASN.1 spans, time, tokens, key schedule, registry, certificate checks | each package | every pull request |
| Vector | Byte-exact PDUs and keys from `testdata/e2e/vectors` | `iec62351/e2e` | every pull request |
| Oracle | Independent decode and verify of every emitted PDU (15.2) | `internal/e2eoracle` (test only) | every pull request |
| Fuzz | SecPDU and EnvPDU decoders, session and presentation parsers | `*_fuzz_test.go` | 2 min per target per pull request; 1 h nightly |
| Fault injection | Every [T] resiliency row and every extra negative case (15.3) | `cmd/e2e-teq` + `e2e_conformance_test.go` | every pull request |
| Integration | Library client ↔ server, all MMS services, rekey, release, abort, `-race` | `mms`, `client`, `server` | every pull request |
| Soak | 24 h, rekey 15 min, report load, both roles | CI nightly / lab | before release |
| Diode | DT-1 … DT-12 | `datadiode-mms/test` | before release |
| External | Commercial test equipment (TEQ) campaign per [T] and the PIXIT; independent native-E2E peer, if one can be found | laboratory | conformance claim |

## 15.2 Independent oracle

A codec that both encodes and decodes can be self-consistently wrong. The oracle is a separate, test-only implementation:

- written against the Annex B / Annex D text (or the IEC archive once obtained);
- using a different decoding path: `golang.org/x/crypto/cryptobyte` plus `encoding/asn1`, with its own span handling;
- with its own HKDF and MAC invocation, sharing no code with `iec62351/e2e` except the standard library.

Every PDU produced in the integration tests is decoded, its signature or ICV recomputed, and the key schedule re-derived by the oracle. If possible, the oracle is written by a different engineer from the codec. This is the main defence against the risk that the only peer available during development is the library itself.

## 15.3 Mapping of [T] cases to automated tests

Test names are `TestT<table>_<row>_<role>`. The TEQ emulator produces the stimulus and asserts the expected EnvPDU and SecPDU.

| [T] case | Stimulus (by TEQ) | Expected from the DUT | Decision notes |
| --- | --- | --- | --- |
| T14-1/2 (client) | valid AARE with HandshakeAcc; RLRE | AARQ per Tables 68/55; RLRQ per 74/66 | application context per R-02 |
| T15-1/2 (server) | valid AARQ; RLRQ | AARE per 69/56; RLRE per 75/67 | — |
| T16-1 | AARE accepted, user-information without indirect reference | ABRT `osiDiag protocol-error` | — |
| T16-2 | AARE accepted, wrong indirect reference | ABRT `osiDiag invalid-indirect-reference` | — |
| T17-1 | AARQ with wrong application context | AARE rejected-permanent, `application-context-name-not-supported` | — |
| T17-2 | AARQ with wrong indirect reference | AARE rejected-permanent, `no-reason-given`, `osiDiag invalid-indirect-reference` | R-20: the schema has no osiDiag in HandshakeRsp |
| T18 | ClearTransfer both ways | per Tables 62, 63, 72 | — |
| T19-1 / T20-1 | wrong context id on data | ABRT `osiDiag invalid-pci` | — |
| T20-2 | missing context id | ABRT `osiDiag protocol-error` | — |
| T21–T23 | EncrTransfer, wrong or missing context id | as T18–T20 | after WP9 |
| T24 | client rekey after 15 min | rekey under old keys; new keys after `changedKey` | 5.7 |
| T25 | server `reqRekey` | `changedKey`, new keys | 5.7 |
| T49-1 | Acc sigAlg ≠ algo | HandshakeSecAbort, diag absent | alarm |
| T49-2 | Acc missing ClearToken1 field | `protocol-error` | — |
| T49-3 | Acc invalid certificate | `invalid-public-key-certificate` | — |
| T49-4 | Acc certificate subject ≠ responder AE | diag absent | alarm |
| T49-5 | Acc unsupported signature algorithm | `invalid-signatureAlgorithm` | — |
| T49-6 | Acc version not offered | `unexpected-version` | — |
| T49-7 | Acc time > 10 min off | `invalid-time-value` | — |
| T49-8 | Acc time and assoID replayed | diag absent | alarm |
| T49-9 | Acc DH group differs | `illegal-dhGroup-selected` | — |
| T49-10 | Acc HMAC differs or unsupported | `hmac-algorithm-not-supported` | — |
| T49-11 | Req non-aea, Acc aea | [T] `aea-algorithms-not-supported` / [B] `ae-not-used` | R-07 setting |
| T49-12 | Acc encryption algorithm not offered | `invalid-encryption-algorithm` | — |
| T49-13/14 | Acc multiple / empty `encr` | `single-encrypt-algo-required` | empty SEQUENCE OF accepted structurally (7.1) |
| T49-15 | Acc ICV not offered | `icv-algorithms-not-supported` | R-07 |
| T49-16/17 | Acc multiple / empty ICV | `single-icv-algo-required` | as 13/14 |
| T49-18 | Req with `encr`, Acc without | `encryption-required` | — |
| T49-19/20 | Req without `encr`, Acc aea / with `encr` | `encryption-not-required` | — |
| T49-21/22 | (server stimuli printed in the client table) | run as T50-17/18 | R-21 |
| T50-1 | unsupported `pp` | HandshakeSecReject `protected-protocol-not-supported` | — |
| T50-2/5/9 | sigAlg mismatch / address mismatch / replay | diag `no-reason-given` ([T]) vs absent ([B]) | R-07 setting |
| T50-3/4/6/7/8/10/11 | missing field / certificate / signature algorithm / version / time / DH group / HMAC | the matching diagnostic | — |
| T50-12…16 | AEAD and ICV negotiation faults | table 7.3 | R-07 for #12 |
| T50-17/18 | `applProtected` against policy | `encryption-not-required` / `-required` | — |
| T50-19 | several encryption algorithms offered | HandshakeAcc with the first supported | positive |
| T50-20 | time > 10 min | `invalid-time-value` | — |
| T51-1…6 (server, clear) | missing field, version, EncrTransfer, sequence, time, replay | DtSecAbort `protocol-error`, `unexpected-version`, `encryption-not-selected`, `invalid-sequence-number`, `invalid-time-value`, alarm | R-07 for #6 |
| T52-1…7 (client, clear) | as T51 plus unexpected `changedKey` | plus `unexpected-changedKey` | R-07 |
| T53-1…7 (client, encrypted) | as T52 with ClearTransfer → `encryption-required` | — | after WP9 |
| T54-1…7 (server, encrypted) | as T53; #7 `changedKey` from the client | [B] `protocol-error` / [T] `unexpected-changedKey` | R-07 |

**Additional negative tests** (not in [T], required by [B]):

- invalid signature (alarm);
- invalid ICV and wrong ICV algorithm (alarms);
- GMAC without a nonce (`gmac-nonce-required`);
- CBC without an IV (`aes-init-vector-required`);
- `rekey` received by the client and `reqRekey` received by the server (`protocol-error`);
- two `rekey` before `changedKey` (`unexpected-dhPublicKey`);
- certificate > 8192 octets (terminate and raise the event);
- certificate path deeper than the limit;
- revoked, expired, not-yet-valid and missing-key-usage certificates;
- E2E and TLS certificates being equal (configuration error);
- a plain MMS PDU on context 3 in native mode;
- release with a wrong signature;
- an unsigned ABRT `osiDiag` during the data phase (must not be trusted beyond closing);
- clock regression;
- a CONNECT above 10 240 octets;
- TPKT version ≠ 3 (accepted);
- TSEL > 32 octets (abort).

## 15.4 Conformance campaign package

- PICS ([B] Tables 6–11 with "Declared" filled in) and PIXIT ([T] Tables 1–2, plus the R-register decisions that affect test expectations: R-02, R-06, R-07).
- The device under test is `cmd/ied-server` / `cmd/ied-client` built from the release tag, with the E2E flags, `-events json`, interactive release and rekey commands, and an IEC 61850 test model with ICD/IID ([T] 5.3.2 j)).
- Certificate sets for the test PKI: trust anchor, intermediate, end entities for the device and the TEQ, plus expired, revoked, oversized and wrong-subject variants ([T] Table 2 row 1).
- T-profile test results per IEC TS 62351-100-3 for the declared TLS profile ([T] clause 1).
- The trace matrix, captures (`pcapng`) and logs of every [T] case.

## 15.5 Definition of done

**Release 1 is done when:**

1. Every [T] OSI test applicable to the declared PICS (Tables 14–20, 24, 25, 49–52) passes against the TEQ emulator in CI and against a commercial TEQ in the laboratory.
2. All vectors pass, and the oracle agrees.
3. 24 h soak (both roles, 15 min rekey, report load) with no security error.
4. The diode scenarios DT-1 … DT-11 pass.
5. PICS, PIXIT, `docs/pics.md` and the README updated with exactly the evidenced claims.
6. No open register item affects a declared capability.

# 16. Schedule, dependencies and risks

## 16.1 Milestones

| Milestone | Content | Indicative calendar (1 engineer + review) | Exit |
| --- | --- | --- | --- |
| M0 Contract | WP0 | weeks 1–3 | register items closed or scoped out; vectors drafted |
| M1 Foundations | WP1, WP2, WP6 (session, presentation, ACSE parts), G-MMS-1/2/10 | weeks 3–8 | plain-mode regression green; signed release in plain mode |
| M2 Core | WP3, WP4, WP5 | weeks 6–14 | E2E handshake between two `Association` objects in memory; all of section 7 tested |
| M3 Integration | WP7, WP8, WP10 (emulator) | weeks 13–19 | first library ↔ library E2E association; [T] 14–20, 49–52 green on the emulator |
| M4 Rekey and hardening | rekey under load, soak, fuzz campaign, WP11 | weeks 18–22 | [T] 24/25 green; 24 h soak |
| M5 Diode | D1–D7, D9, D10 | weeks 17–25 (overlaps from M3) | DT-1…DT-11 |
| M6 Encryption | WP9 | after R-09; about 2 weeks | [T] 21–23, 53, 54 |
| M7 Laboratory | external TEQ campaign | after M4 + M5; laboratory slot | test report |
| Optional | Track A (2–3 ew), track S (5–7 ew), brainpool verification (2–3 ew) | in parallel or after M7 | own exit criteria |

**Critical path:** WP0.2/0.3 (code components and vectors) → WP3/WP4 → WP7 → laboratory. Laboratory availability is the main calendar risk. Book it at M2.

## 16.2 Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Symmetric misinterpretation (library tested only against itself) | Fails at the laboratory; costly rework | Oracle (15.2); early TEQ dry run at M3; obtain the code components (R-01) |
| Ambiguities in [B] and [T] (section 17) | Divergent behaviour from test equipment | Named settings (7.4), PIXIT, early laboratory alignment |
| No AEAD nonce definition (R-08) | AE mode undeclarable | Declare non-AE only (DEC-3) |
| Brainpool mandatory, no Go support | Non-conformant row | Release-2 verification-only plan (6.6); declare the deviation |
| TLS rows not implementable in Go | Native T-profile non-conformant | DEC-7 declaration; E2E carries the application security |
| Replica identity (option A) misunderstood as impersonation | Security review objection | Separate PKIs, explicit claim (13.1), option B available |
| Performance on rugged hardware (RSA-2048 signing, MODP DH per association) | Slow handshakes | Prefer P-256 and group 23; handshake limits; measure on the target ARM64 (`go test -bench` in WP2) |
| Clock synchronisation in OT | Spurious `invalid-time-value` | Commissioning check; `ClockRegression` event; deployment requirement in the PIXIT |
| Interaction with existing interop (libiec61850, Wireshark) | Regressions in plain mode | WP6 keeps every existing interop test; plain mode stays the default |
| Size budget exceeded by long certificate paths | CONNECT refused | Section 4.10 checks on send; advise short paths in the runbook |

# 17. Discrepancy and interpretation register

Status values: **Open** (to be resolved in WP0.4), **Adopted** (a default chosen here, to confirm), **Closed**. Each closed item records its evidence: archive diff, laboratory statement or vector.

| Id | Topic | [B] | [T] / registry | Default in this plan | Status |
| --- | --- | --- | --- | --- | --- |
| R-01 | Code components | Annexes A, B, D, F printed (scan) | IEC archive URL in [B] 1.2 | Archive `IEC_62351-4.ASN.1_XSD.full` obtained (manifest dated 2018-04-19, publication IEC 62351-4:2018). It is the **first-edition** module set and predates AMD1. Diff in 19.5 | Closed (see R-27) |
| R-02 | Application context name | `e2eMmsAC` = 1.0.62351.4.2.1 (15.2.2) | T68/T69: 1.0.62351.4.1.2.1.1 | Send [B]; as a server, accept the [T] value only with the named setting `AcceptT100AppContext` (test campaigns) | Adopted |
| R-03 | Diagnostic numbering | clause 14.2.1 list vs Annex B (`altSig-mismatch(19)`); DtDiagnostics gap at 5 | [T] built on Annex B; TISSUE 94 asks for tests ≥ 19 to be repeated | **TISSUE 94** (in force): `altSig-mismatch` removed, values above it one lower. Default; Annex B numbering with `CorrectionsNone`; 2018 module stops at 16 (7.2) | Closed |
| R-04 | Authenticator tagging | 13.4.2 `[0] nonce`, `algorithm`, `[1] icv`; Annex B untagged, `algo` | — | Annex B; the clause-13 variant only as a named setting. The 2018 code component is also untagged (`nonce OCTET STRING OPTIONAL, algo, icv OCTET STRING OPTIONAL`) | Closed |
| R-05 | ClearToken1 `version` | body: mandatory; Annex B: DEFAULT {v1} | T55 #7: check bit 0 | Always emit; accept absence | Adopted |
| R-06 | Sequence number | resets to 0 when the time changes (13.3.2 d), 14.4.3 d)) | T62–T65 #6: always +1 | [B] | Adopted; raise with the laboratory |
| R-07 | Diagnostics for alarm and mode cases | alarm → diag absent; k), t), x), g) codes | T50 #2/#5/#9, T51–54 #6 `no-reason-given`; T49 #11, T49 #15, T50 #12, T54 #7 other codes | [B]; `AlarmDiagnostic` setting and a documented mapping for the others | Adopted |
| R-08 | AEAD nonce and parameters | 13.3.1.1 i) 1) nonce excluded from the proposal; `ClearToken2.iv` CBC-only, `SIZE(16)`; `auth` absent with AE | T64/T65: `iv` "if dynamic parameters", `auth` "checked for presence" | **TISSUE 53/55** (in force): `InitializationVector ::= OCTET STRING (SIZE (12 \| 16))`, 12 = GCM nonce, 16 = CBC IV; the AE IV travels in `ClearToken2.iv`; a GMAC nonce stays in `Authenticator.nonce`. The decoder accepts 12 or 16. Still unstated: `auth` presence with AE (R-29). AE not declared (DEC-3) | Partly resolved |
| R-09 | CBC padding | not specified | — | PKCS#7 | Open |
| R-10 | TLS suite numbers | T3/T10: `0xC09E`, `0xC023`, `0xC024`; T8: `0x0030` named DHE_DSS; T10: DH_RSA_AES_256_GCM "SHA256" | IANA: `0x009E`, `0xC02B`, `0xC02C`; `0x0030` = DH_DSS; `0x00A1` = SHA384 | Use the IANA number of the **named** suite; guard test against `0xC023` and `0xC024` | Adopted; confirmed by **TISSUE 129** (in force), which also corrects Table 8 to `TLS_DHE_DSS_WITH_AES_128_CBC_SHA` 0x0032 (not implementable in Go). TISSUE 171 (drafting) revises the references again |
| R-11 | Key lengths | "combined length of keys" | — | HMAC-SHA-256 key 32; AES 16 or 32 per algorithm | Adopted; vector |
| R-12 | HKDF `h0 = 0` | representation unspecified | — | Vector-driven choice among {empty, `00`, 32 × `00`} | Open (blocking) |
| R-13 | DH public value and Z encoding | not specified | — | MODP: 256 octets big-endian, Z the same; EC: SEC1 uncompressed, Z = X (32) | Open |
| R-14 | ECDSA signature value encoding in `Signature.sign` | not specified; `ecdsa-with-SHA256-Algorithm` is annotated "IETF RFC 5758" | — | DER `Ecdsa-Sig-Value`: RFC 5758 §3.2 defers to RFC 3279 §2.2.3 (X.509/CMS context, applied here by reference); parameters omitted | Adopted, pending a peer vector |
| R-15 | `hmac` field value | "HMAC algorithm"; "hash in 8.4 shall be supported" | — | `hmacWithSHA256` (NULL params); `id-sha256` accepted only with a named setting | Adopted |
| R-16 | `icvAlgID` order | text: preference order; schema: SET | T56 #17 | Encode in preference order (DER SET OF sorting not applied, as BER allows); server picks the first supported in received order | Adopted |
| R-17 | `pp` for TASE.2 | `-503`, `-702` and `-802` all listed | — | `"IEC 60870-6-503"` | Open |
| R-18 | RSA AlgorithmIdentifier NULL | PARMS NULL | — | Emit NULL; accept NULL or absent | Adopted |
| R-19 | TPKT limit | H.3.3: 2056; Table H.1 suggests 2055 | — | Accept ≤ 2056 | Adopted |
| R-20 | osiDiag in the AARE | HandshakeRsp has no osiDiag alternative (Annex D) | T17 #2 expects osiDiag in OSI-AssoRsp | AARE rejected-permanent, `no-reason-given`, no user-information ([B] 15.6.1), plus an ABRT osiDiag only if the laboratory requires it | Open |
| R-21 | Editorial errors in [T] | — | T49 #21/#22 are server stimuli; T55 #23 says `token3`; T65 #13 says "unencrypted"; rekey rows cite "table 27 or 28" | Treat as editorial; record in the PIXIT | Adopted |
| R-22 | DH group 23 | 23 = secp256r1 "according to RFC 5114" | IKE registry: 19 = secp256r1, 23 = MODP-2048/224 | Protocol code points 14, 23, 28 as in [B] and T55 | Adopted |
| R-23 | Brainpool | Table 11 m; group 28 optional | — | Release 2 verification only; declare N before that | Adopted |
| R-24 | Part 3 edition | [B] 2014+A1:2018 | [T] 2023; T5 cites 2014/AMD2:2020 | IEC 62351-3:2023 (ed. 2) cancels and replaces 2014, AMD1:2018 and AMD2:2020 (adds a TLS 1.3 profile). Which edition a campaign applies is for the laboratory; declare the implemented TLS profile in the PIXIT | Open |
| R-25 | E2E subject attribute type | G.6.2: X.520 `objectIdentifier` | — | `id-at-objectIdentifier` = {id-at 106} = **2.5.4.106** (ITU-T X.501 UsefulDefinitions, X.520 SelectedAttributeTypes, 10/2019); 2.5.4.82 is `permission`. Issued and required by default; `Policy.AcceptAnyAEAttributeType` for legacy certificates | Closed |
| R-26 | Go `crypto/x509` and OID-valued subjects | — | — | Parse with a placeholder subject, restore the raw fields (19.3) | Adopted |
| R-27 | Wire-format edition | 2018 code component: ClearToken1 `…assoID, time, dHKey, hmac` with `hmac` a bare OID, `encr-mode` aea = SET OF OID, non-aea = untagged SEQUENCE {[0] SET OF OID, [1] SET OF OID}; AMD1 Annex B: `…assoID, dHKey, hmac (AlgorithmIdentifier), time`, aea = SEQUENCE OF AlgorithmIdentifier, non-aea = [0] SEQUENCE {[0] SEQUENCE OF, [1] SET OF} | [T] tests AMD1 | AMD1 (`Edition2020`) by default; `Policy.Edition = Edition2018` for first-edition peers. Both encodings are checked against an independent `encoding/asn1` oracle | Adopted |
| R-28 | `ApplData` in the OSI environment | 2018 Annex F gives only the generic template `ApplData ::= <top-level type>` ("a synonym for the top-level entry"), so the MMS PDU itself; AMD1 F.3 specifies an EXTERNAL naming the MMS presentation context. The code component imports `Virtual-API` but does not ship it | — | Follows the edition (R-27); the 2018 reading is an interpretation to confirm with a first-edition peer | Adopted |
| R-29 | `EncrTransfer.auth` | 2018: mandatory, with `icv` absent for aea; AMD1: OPTIONAL | — | Applies to WP9 only (encryption not built) | Open |
| R-30 | GMAC ICV identifiers | 8.7/Table 11: `aes128-GCM` {aes 6}, `aes256-GCM` {aes 46} used as GMAC | — | **TISSUE 52** (in force): `aes128-GMAC` {aes 9}, `aes256-GMAC` {aes 49} (RFC 9044), PARMS `GCMParameters`. Sent by default; both forms accepted; the server echoes the client's identifier and both ends keep the negotiated one, so corrected and uncorrected peers interoperate. TISSUE 60 (editorial, not in force) would make the PARMS NULL | Adopted |
| R-31 | Received attribute certificate | 13.3.1.1 k) silent on absence/handling | T50 "aa" row expects `invalid-attribute-certificate` | **TISSUE 97** (in force): validate per IEC 62351-8 if authorization is configured, otherwise ignore. Default: ignored with an `attribute-certificate-ignored` event; `Policy.RequireAuthorization` refuses it (62351-8 validation not implemented) | Adopted |
| R-32 | Server AE / non-AE support | Table 9 conditional on the referencing standard | — | **TISSUE 95** (in force): the server shall support both, so Table 11 c[5]–c[7] are mandatory for servers. Our server cannot claim server conformance until WP9 (encryption, AE) is built; PICS 8.1 says so. Part 6 TISSUE 54 (triage) asks Part 6 to state how Table 9 is filled for IEC 61850, proposing "servers at least one option, clients both", which would reverse 95 for servers; watch | Open (WP9) |
| R-33 | Other in-force TISSUEs | — | — | 90: DtDiagnostics 11 renamed `unexpected-changeKeys` (name only, adopted). 92: AssoAbort has four elements with `osiDiag` (already so). 78: other key usages are ignored (already so: digitalSignature and keyAgreement required, others ignored). 77: DH 14 and ECDH 23 mandatory, 28 optional in Table 11 (PICS). 130: wording of item 21 (`invalid-ae-algorithm`), relevant with AE only | Adopted |
| R-34 | TISSUEs not yet in force | — | — | 60 and 64 (algorithm PARMS NULL in ClearToken1, IV out of ClearToken1), 96 (OSI-SecAsso references), 101 (rekey overlap: clarifying text, possibly symmetric `changedKey`), 171 (cipher-suite references; drafting). Track; no code change | Open |

# 18. References

- **[B]** BS EN IEC 62351-4:2018+A1:2020 — Power systems management and associated information exchange — Data and communications security — Part 4: Profiles including MMS and derivatives.
- **[T]** PD IEC TS 62351-100-4:2023 — Part 100-4: Cybersecurity conformance testing for IEC 62351-4.
- IEC 62351-4:2018 edition 1.0 and its code component `IEC_62351-4.ASN.1_XSD.full` (2018-04-19).
- IEC 62351 TISSUE database, Part 4: <https://iec62351.tissue-db.com/parts/4> (TISSUEs 52, 53, 55, 60, 64, 77, 78, 90, 92, 94, 95, 96, 97, 101, 129, 130, 171); in force through 57/2901/INF (16 July 2026).
- IETF RFC 9044 (AES-GMAC in CMS: id-aes128-GMAC, id-aes256-GMAC); ITU-T X.501 and X.520 (10/2019) modules.
- IEC TS 62351-100-3 (T-profile conformance tests); IEC 62351-3:2014+A1:2018 and IEC 62351-3:2023; IEC 62351-9 (key management); IEC 62351-14 (security event logging); IEC 62351-6:2020 (IEC 61850 security PICS).
- ITU-T X.227 (ACSE), X.226 / ISO 8823 (presentation), X.225 / ISO 8327 (session), X.224 / ISO 8073 (transport), X.690 (BER/DER), X.509 and X.520.
- IETF RFC 1006, 2104 (HMAC), 3526 (MODP groups), 5084 (AES-GCM in CMS), 5114, 5280, 5480, 5639 and 6954 (brainpool), 5869 (HKDF), 7427.
- NIST SP 800-38D (GCM and GMAC). IANA TLS Cipher Suites and IKEv2 Transform Type 4 registries.
- Go standard library documentation for `crypto/tls`, `crypto/x509`, `crypto/ecdh`, `crypto/hkdf` and `crypto/cipher` (behaviour verified on Go 1.27.1 for this plan).
- Revision 1 of this guide: `output/pdf/iec62351-4-implementation-guide-rev1.pdf`.

# 19. Implementation status (branch `feature/iec62351-4-e2e`, 11 October 2026)

This section records what has been built against the plan. Unless a deviation is stated, sections 1–18 remain the design reference.

## 19.1 Library (`go-iec61850`)

| Plan item | Status | Where |
| --- | --- | --- |
| WP1 ASN.1 spans, GeneralizedTime, named bits | Done | `asn1/span.go`, `asn1/gentime.go` |
| WP2 primitives (DH moved out of `gdoi`, HKDF, HMAC, GMAC, signatures) | Done; CBC not built (WP9) | `internal/cryptox/dh`, `iec62351/e2e/alg.go`, `keys.go` |
| WP3 SecPDU codec (all Annex B types, spans, extension tolerance, both Authenticator taggings) | Done, fuzzed | `iec62351/e2e/pdu.go`, `fuzz_test.go` |
| WP4 association state machine: check order, diagnostics, alarms, tokens, rekey (per-direction epochs), release, aborts, `assoID` allocation, handshake replay cache | Done | `iec62351/e2e/assoc.go` |
| WP5 PKI: OID-subject certificate parsing, Annex G profile, trust store, CRL revocation (`Warn`/`FailClosed`), identity binding | Done | `iec62351/pki`, test PKI in `iec62351/pki/pkitest` |
| WP6 OSI: Extended User Data, FINISH/DISCONNECT, three presentation contexts, context-checked data, ACSE user-information/ABRT/RLRQ/RLRE, Annex H hardening (TPKT version, TSEL ≤ 32, TPDU size clamp, bounded reassembly, ignored ED/AK/EA/RJ) | Done | `internal/osi/*`, `iec62351/e2e/osi` |
| WP7 MMS integration: secured framing, client and server handshakes, signed release, aborts, idle-rekey carrier, keep-alive, handshake deadline | Done | `mms/secure.go`, `mms/transport.go`, `mms/conn.go`, `mms/server_conn.go` |
| WP8 public API and tools | Done: `client.WithE2E`, `server.WithE2E`, `WithAEIdentity`, `WithHandshakeTimeout`; `ied-server`/`ied-client` E2E flags with `-events json`; `cmd/e2e-pki` (test CA, leaves, CSR, show); `e2efile` loader | `client`, `server`, `cmd/*`, `iec62351/e2e/e2efile` |
| WP9 E2E encryption | Not started (blocked by R-08 and R-09); refused with the specific diagnostics | — |
| WP10 test infrastructure | Partly done: unit and vector-free tests, single-fault tests for [T] Tables 49/50 at the core level, MMS-level tests over TCP (association, refusals, rekey ×3 with an injected clock), IEC 61850 server/client test, fuzz targets. **Not done** (oracle since done, 19.5): the `cmd/e2e-teq` fault-injection peer, external reference vectors | `*_test.go` |
| WP11 native-mode TLS profile | Done (`iec62351.Options.NativeMode`, guard test against `0xC023`/`0xC024`) | `iec62351/tls.go` |
| WP12 documentation | `docs/pics.md` §8.1, `docs/api.md`, `SKILL.md`, `README.md` | |
| Track A (A-profile), brainpool, TASE.2 stack | Not started | — |

Verified on this branch:

- `go vet ./...` and `go test ./...` pass for both repositories, with `-race` on the security packages.
- The plain-mode interoperability test against libiec61850 `server_example_basic_io` still passes.
- The command-line tools work against each other end to end: an E2E browse succeeds and a plain client is refused (diagnostic 2).

## 19.2 Application (`datadiode-mms`)

| Plan item | Status |
| --- | --- |
| D1 configuration (`device.ae`, `device.peer_ae`, `device.app_security`, `device.e2e`, `server.e2e`, `readiness.require_inner_security`) and validation | Done |
| D2 `internal/e2eprofile` loader: files, Annex G checks, G.2 separate-key check, events → `security_event=e2e-*`, counters, CRL refresh | Done |
| D3 dd-inner: E2E dial and profile probe, security status, security-failure backoff | Done |
| D4 replica: E2E accept modes, allow-list admission, identity "device"/"own" with mismatch refusal, handshake timeout, readiness gate | Done |
| D5 inner security status across the diode | Done, as heartbeat field 4, not a new record type: it is periodic, needs no model generation, and older receivers ignore it |
| D6 observability (`/status` `e2e`, `inner_security`) | Done |
| D7 dd-probe E2E flags | Done |
| D8 TASE.2 leg | Not started (needs track S); configuration refuses E2E with the tase2 profile |
| D9 documentation | README section, wire-protocol heartbeat fields, `proposal.md` corrections |
| D10 tests | `test/e2e/iec62351_4_chain_test.go`: full chain with E2E on both legs. Also config and loader tests. Soak and flood scenarios (DT-6, DT-8) not automated |

## 19.3 Interpretations taken during implementation

| Item | Decision in code |
| --- | --- |
| R-12 `h0` | `ChainZeroOctet` (one `00` octet) by default; `Policy.HKDFInit` selects the alternatives. Still open: needs a reference vector |
| R-13 EC public value | SEC 1 uncompressed point; Z = X coordinate |
| R-14 ECDSA signature value | DER `Ecdsa-Sig-Value` |
| R-02 application context | Send `1.0.62351.4.2.1`; a server accepts the [T] value only with `ServerConfig.AcceptT100AppContext` |
| R-07 diagnostics | [B] by default; `Policy.AlarmDiagnostic` and `Policy.T100Diagnostics` select the [T] expectations |
| R-20 environment errors in the AARQ | AARE rejected-permanent, no-reason-given, without user-information |
| **R-25** subject attribute type | Closed: X.520 `objectIdentifier`, 2.5.4.106 (`pki.AEAttributeType`). Issued by `cmd/e2e-pki` and `pkitest`; receivers require it unless `Policy.AEAttributeType` names another type or `Policy.AcceptAnyAEAttributeType` is set (certificates issued with the earlier provisional 2.5.4.82 must be reissued or admitted with that setting) |
| **R-26 (new)** Go `crypto/x509` | It refuses a subject with an OID-valued attribute ("invalid RDNSequence"). `pki.ParseCertificate` parses a copy with a placeholder subject and restores the raw fields, so signatures and chains are verified over the received octets |
| GMAC parameters | Emitted without parameters (12-octet tag); `GCMParameters` with ICV length 12 accepted |
| E2E responding identity | Always the AE title of the server's E2E certificate (it is what the client checks), whatever the plain-mode responding identity |

## 19.4 Next steps, in order

1. WP0.3: build reference vectors (R-12–R-14). The code components settled R-01, R-03, R-04 and R-25 (19.5); they do not settle the key-schedule encodings.
2. WP10: the `e2e-teq` peer (the encoding oracle is done, 19.5); extend [T] coverage to Tables 16, 17, 19–25 and 51–54 at the EnvPDU level.
3. Laboratory dry run with commercial test equipment.
4. WP9 (encryption) once R-08 and R-09 are settled.
5. Track S (TASE.2) and D8.
6. Track A and brainpool verification, if the target deployments need them.

## 19.5 Code components and the first edition (12 October 2026)

Inputs: the IEC archive `IEC_62351-4.ASN.1_XSD.full` (`IECManifest.xml` dated 2018-04-19, publication IEC 62351-4:2018: modules `E2E-Security`, `OSI-Env`, `XMPP-Env`, `XMPP-Stz` with their XSDs, and the first-edition `STASE-MMS-Authentication-value`), the IEC 62351-4:2018 edition 1.0 PDF, and the ITU-T X.501/X.520 (10/2019) modules in `output/standards/iec62351-4-retrieval`.

Findings:

- The archive is the **first-edition** module set. AMD1:2020 rewrote `ClearToken1` and added the OSI Virtual API; neither change is in the archive. The two editions are not wire compatible (R-27, R-28).
- What both editions share and the code already did: `ClearToken2`, `ClearToken3`, `Signature`, the signed PDUs, an untagged `Authenticator` (R-04), DiffieHellmanSet, `ConfidentialityParms`, `Version`, NMTOKEN `AssoID`, and the whole `OSI-Env` module (`HandshakeRsp` [1..3] without osiDiag, which supports R-20; `AssoAbort` [0..3] with osiDiag [3]).
- Diagnostics: the 2018 handshake list stops at 16 (`invalid-attribute-certificate`), and DtDiagnostics 5 is `gmac-init-vector-required` (R-03).
- R-25: G.6.2 names the X.520 `objectIdentifier` attribute, `id-at-objectIdentifier` = {id-at 106} = 2.5.4.106.
- The archive and the PDF repeat `h0 = 0` without a representation and do not fix the DH public-value or signature encodings: R-12–R-14 stay open.

Changes:

| Change | Where |
| --- | --- |
| `e2e.Edition` (`Edition2020` default, `Edition2018`) in `Policy.Edition`; 2018 ClearToken1 encoder/decoder; `ParseSignedEdition`; first-edition diagnostics mapping (values above 16 sent as `protocol-error`) | `iec62351/e2e/edition.go`, `pdu.go`, `assoc.go`, `diag.go` |
| ApplData per edition (`ApplDataFor`, `ParseApplDataFor`) through the MMS framing | `iec62351/e2e/osi`, `mms/secure.go`, `mms/transport.go` |
| X.520 `objectIdentifier` (2.5.4.106) issued and required; `Policy.AcceptAnyAEAttributeType` | `iec62351/pki/cert.go`, `e2e/config.go`, `cmd/e2e-pki`, `pkitest` |
| `-e2e-edition`, `-e2e-any-ae-attr` on the tools; `edition`, `accept_any_ae_attribute` in the diode's `e2e` blocks | `e2efile/flags.go`; datadiode-mms `internal/config`, `internal/e2eprofile` |
| Independent oracle (WP10, 15.2): ClearToken1 (both editions, aea and non-aea), Authenticator and ClearToken2 encoded by Go `encoding/asn1` from structs transcribed from the modules, compared octet for octet, and the oracle's octets decoded by the codec | `iec62351/e2e/oracle_test.go` |
| Tests: 2018 association and transfer, edition mismatch → `protocol-error`, MMS over TCP under both editions, the diode chain with a first-edition device leg and a 2020 DMZ leg | `edition_test.go`, `mms/e2e_test.go`, datadiode-mms `test/e2e` |

The libiec61850 interoperability suite still passes (16/16). libiec61850 has no E2E support, so it cannot confirm either edition.

## 19.6 Published corrections (TISSUEs) as the default (12 October 2026)

The IEC 62351 TISSUE database (<https://iec62351.tissue-db.com/parts/4>) lists 18 issues for Part 4 (2018, Edition 1.1). Most of those marked *In Force* go into force through 57/2901/INF on 16 July 2026, and several are flagged *Must Implement*. Part 100-4 has none. The pages summarise the changes; the exact text is in 57/2901/INF and the attachment `20250103_iec62351-4-tissue_annex-b.pdf`, which need a sign-in and have not been read. Where a page leaves the final wording open, the register says so.

`Policy.Corrections` selects the behaviour for `Edition2020`:

| Setting | Meaning |
| --- | --- |
| `CorrectionsInForce` (default) | TISSUEs 94 (handshake numbering), 52 (GMAC identifiers), 97 (attribute certificates ignored), 53/55 (IV 12 or 16 octets), 90 (name) |
| `CorrectionsNone` | AMD1:2020 as printed, for peers and test tools built before the TISSUEs (including campaigns run on the original [T] diagnostics for values ≥ 19) |

`Edition2018` is unaffected. Receivers stay lenient where it is safe: both GMAC identifiers are recognised whatever the setting, and the IV decoder takes 12 or 16 octets.

| Change | Where |
| --- | --- |
| `Corrections`, `ParseCorrections`; handshake diagnostics mapped to and from the wire (`hdToWire`, `hdFromWire`); received rejections reported with this package's constants | `iec62351/e2e/edition.go`, `assoc.go`, `diag.go` |
| `id-aes128-GMAC` / `id-aes256-GMAC`; the negotiated identifier is kept per association and sent in every Authenticator | `alg.go`, `assoc.go` |
| Attribute certificates ignored unless `Policy.RequireAuthorization`; event `attribute-certificate-ignored` | `assoc.go`, `config.go`, `events.go` |
| `-e2e-corrections` on the tools; `corrections` in the diode's `e2e` blocks | `e2efile/flags.go`; datadiode-mms `internal/config`, `internal/e2eprofile`, README |
| Tests: wire numbering in all three modes with a round trip; GMAC identifiers for corrected, mixed and uncorrected pairs with data both ways; attribute certificate ignored; IV sizes | `iec62351/e2e/tissue_test.go`, `edition_test.go` |

Compatibility: a peer built on AMD1 as printed reads handshake diagnostics 19–25 from a corrected peer one value too low; that only affects the diagnosis of a failed handshake, never a successful association. Set `CorrectionsNone` for such peers, or for a test campaign that still expects the Annex B values.

## 19.7 TISSUEs of the other parts (12 October 2026)

The parts overview (<https://iec62351.tissue-db.com/parts.mspx>) was reviewed for what touches this code. The General part and Parts 100-4 and 100-6 have no TISSUEs; Parts 5, 7, 11 and 100-1 do not concern it; Part 8 has one (RADIUS). No TISSUE outside Part 4 requires a code change: Part 9 has none in force and the code already meets its accepted ones, and Part 3's in-force ones concern features the TLS profile does not implement, now declared in the PICS.

| Part | TISSUE | Status | Effect here |
| --- | --- | --- | --- |
| 3 (TLS) | 79: Table 1 `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` = 0x009F, `..._128_...` = 0x009E | In force (57/2853/INF) | DHE suites are not implemented by Go; PICS N with the corrected values |
| 3 | 58: `trusted_ca_keys` carries the client's CA key list; the server answers with an empty extension | In force | Not supported by `crypto/tls`; PICS N |
| 3 | 99: an OCSP response without nextUpdate is valid until thisUpdate + 24 h | In force | OCSP not implemented; PICS N |
| 3 | 88: `TLS_DISALLOWED_CIPHER` is an alarm | In force | Not raised: a suite mismatch fails inside `crypto/tls`. Gap recorded in the PICS |
| 3 | 162, 172, 115, 89, 93, 50 and others | Editorial / future improvement / drafting | 172 (validating one's own certificate becomes optional) and 162 (RFC 5746 on resumption) need no change: renegotiation is off and the own certificate is not validated locally |
| 4 | 129: Table 8 suite is `TLS_DHE_DSS_WITH_AES_128_CBC_SHA` 0x0032 | In force | Section 11 and PICS corrected; still N (no DSS) |
| 6 | 54: how Part 4 Table 9 is filled for IEC 61850 | Triage | Watch with R-32 |
| 6 | 21/22: Table 6 merged, E2E or ACSE authentication conditional | Drafting / accepted | Would make E2E (native) an alternative to the A-profile in the IEC 61850 security PICS; supports the native-only position. Revisit when published |
| 9 (GDOI) | 121, 149, 170, 123 | Conformance verification / editorial | Already as implemented (package `gdoi`) |
| 9 | 169: `61850_UDP_Tunnel` → 1.0.62351.9.61850.8.1.3 | Analysis of compatibility | Group OIDs are the application's; documented |
| 9 | 168: fresh 16-octet IV in clear per encrypted message | Editorial, disputed | Not adopted: `gdoi` follows RFC 2409 Appendix B, which Wireshark also decrypts. Revisit when published |
| 9 | 160: HMAC-SHA-384/512 as GDOI auth values 6/7 | Analysis of compatibility | Not implemented; additive when needed |
| 100-3 (TLS tests) | 140, 137, 132 and others | Mostly editorial | Inform the laboratory agreement on the declared TLS profile (R-24) |
