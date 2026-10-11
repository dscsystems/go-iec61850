// Package osi maps IEC 62351-4 E2E security onto the OSI operational
// environment (IEC 62351-4 clause 15, Annex D) and the OSI Virtual API
// (Annex F.3). It works on byte slices so any ISO upper-layer stack can use
// it: the MMS stack of this module and the TASE.2 stack.
//
// The environment carries SecPDUs in an EXTERNAL whose indirect reference
// is the presentation-context-identifier of e2eSecurityAS:
//
//	AARQ user-information:  OSI-AssoReq  = EXTERNAL { ctx, [0] HandshakeReq }
//	AARE user-information:  OSI-AssoRsp  = EXTERNAL { ctx, [0] HandshakeRsp }
//	ABRT user-information:  OSI-AssoAbr  = EXTERNAL { ctx, [0] AssoAbort }
//	RLRQ/RLRE user-info:    OSI-AssoRelReq / OSI-AssoRelRsp
//	presentation data:      PDV { ctx, [0] ClearTransfer | EncrTransfer }
//
// and the protected protocol's PDU in ApplData = EXTERNAL { mms ctx, [0] PDU }.
package osi

import (
	"errors"
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/e2e"
)

// OsiDiagnostics of IEC 62351-4 15.6.3.
const (
	DiagNoReasonGiven            = 0
	DiagProtocolError            = 1
	DiagInvalidIndirectReference = 2
	DiagInvalidPCI               = 3
)

// EnvError is an exception in the OSI environment mapping (15.6.2). It is
// answered with an ABRT carrying the osiDiag alternative.
type EnvError struct {
	Diag int
	Err  error
}

func (e *EnvError) Error() string {
	names := []string{"no-reason-given", "protocol-error", "invalid-indirect-reference", "invalid-pci"}
	n := fmt.Sprintf("osi-diag-%d", e.Diag)
	if e.Diag >= 0 && e.Diag < len(names) {
		n = names[e.Diag]
	}
	return fmt.Sprintf("e2e/osi: %s: %v", n, e.Err)
}

func (e *EnvError) Unwrap() error { return e.Err }

func envErr(d int, format string, a ...any) *EnvError {
	return &EnvError{Diag: d, Err: fmt.Errorf(format, a...)}
}

var tagExternal = asn1.Tag{Class: asn1.ClassUniversal, Constructed: true, Number: 8}

// External encodes EXTERNAL { indirect-reference ctx, single-ASN1-type [0]
// EXPLICIT tlv } (IEC 62351-4 10.5.4).
func External(ctx int, tlv []byte) []byte {
	return asn1.Cons(tagExternal,
		asn1.IntElem(asn1.TagInteger, int64(ctx)),
		asn1.RawContent(asn1.ContextConstructed(0), tlv),
	).Encode()
}

// ParseExternal decodes an EXTERNAL TLV into its indirect reference (-1 when
// absent) and the TLV inside single-ASN1-type.
func ParseExternal(ext []byte) (ctx int, tlv []byte, err error) {
	c, err := asn1.NewDecoder(ext).Expect(tagExternal)
	if err != nil {
		return 0, nil, err
	}
	return parseExternalContent(c)
}

func parseExternalContent(c []byte) (int, []byte, error) {
	d := asn1.NewDecoder(c)
	ctx := -1
	if b, ok, err := d.Optional(asn1.TagInteger); err != nil {
		return 0, nil, err
	} else if ok {
		n, err := asn1.DecodeInt(b)
		if err != nil {
			return 0, nil, err
		}
		ctx = int(n)
	}
	inner, err := d.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return 0, nil, err
	}
	if d.More() {
		return 0, nil, errors.New("e2e/osi: trailing data in EXTERNAL")
	}
	return ctx, inner, nil
}

// ApplData wraps a protected-protocol PDU (an MMS PDU) in the OSI Virtual
// API ApplData (Annex F.3) with the protocol's presentation context.
func ApplData(ctx int, pdu []byte) []byte { return External(ctx, pdu) }

// ParseApplData unwraps an ApplData TLV, requiring the context wantCtx.
func ParseApplData(tlv []byte, wantCtx int) ([]byte, error) {
	ctx, pdu, err := ParseExternal(tlv)
	if err != nil {
		return nil, fmt.Errorf("e2e/osi: ApplData: %w", err)
	}
	if ctx != wantCtx {
		return nil, fmt.Errorf("e2e/osi: ApplData indirect reference %d, want %d", ctx, wantCtx)
	}
	return pdu, nil
}

// retag replaces the universal SEQUENCE tag of a SecPDU TLV with the
// implicit context tag [n] constructed (n < 31).
func retag(tlv []byte, n int) []byte {
	out := append([]byte(nil), tlv...)
	out[0] = 0xa0 | byte(n)
	return out
}

// Rsp alternatives of HandshakeRsp (Annex D).
const (
	RspAccept     = 1
	RspApplReject = 2
	RspSecReject  = 3
	AbrHandsSec   = 0
	AbrDtSec      = 1
	AbrAppl       = 2
	AbrOsiDiag    = 3
)

// AssoReq is the AARQ user-information EXTERNAL for a HandshakeReq TLV.
func AssoReq(e2eCtx int, handshakeReq []byte) []byte { return External(e2eCtx, handshakeReq) }

// AssoRsp is the AARE user-information EXTERNAL for a HandshakeAcc,
// ApplicationReject or HandshakeSecReject TLV (alt = RspAccept, ...).
func AssoRsp(e2eCtx, alt int, secPDU []byte) []byte {
	return External(e2eCtx, retag(secPDU, alt))
}

// AssoAbr is the ABRT user-information EXTERNAL for a HandshakeSecAbort,
// DtSecAbort or ApplAbort TLV (alt = AbrHandsSec, AbrDtSec, AbrAppl).
func AssoAbr(e2eCtx, alt int, secPDU []byte) []byte {
	return External(e2eCtx, retag(secPDU, alt))
}

// AssoAbrDiag is the ABRT user-information carrying osiDiag (unsigned).
func AssoAbrDiag(e2eCtx, diag int) []byte {
	return External(e2eCtx, asn1.IntElem(asn1.ContextPrimitive(AbrOsiDiag), int64(diag)).Encode())
}

// Release is the RLRQ/RLRE user-information for a ReleaseReq/ReleaseRsp TLV.
func Release(e2eCtx int, secPDU []byte) []byte { return External(e2eCtx, secPDU) }

// checkExternals selects the single EXTERNAL of an E2E user-information:
// it must exist, be the only one and carry the E2E context.
func checkExternals(exts [][]byte, e2eCtx int) ([]byte, *EnvError) {
	if len(exts) != 1 {
		return nil, envErr(DiagProtocolError, "%d EXTERNALs in user-information", len(exts))
	}
	ctx, tlv, err := ParseExternal(exts[0])
	if err != nil {
		return nil, envErr(DiagProtocolError, "%v", err)
	}
	if ctx < 0 {
		return nil, envErr(DiagProtocolError, "indirect-reference absent")
	}
	if ctx != e2eCtx {
		return nil, envErr(DiagInvalidIndirectReference, "indirect-reference %d, E2E context %d", ctx, e2eCtx)
	}
	return tlv, nil
}

// ParseAssoReq returns the content octets of the HandshakeReq of an AARQ
// user-information.
func ParseAssoReq(exts [][]byte, e2eCtx int) ([]byte, error) {
	tlv, ee := checkExternals(exts, e2eCtx)
	if ee != nil {
		return nil, ee
	}
	c, err := asn1.NewDecoder(tlv).Expect(asn1.TagSequence)
	if err != nil {
		return nil, envErr(DiagProtocolError, "HandshakeReq: %v", err)
	}
	return c, nil
}

// ParseAssoRsp returns the HandshakeRsp alternative of an AARE
// user-information and the content octets of its SecPDU.
func ParseAssoRsp(exts [][]byte, e2eCtx int) (alt int, content []byte, err error) {
	tlv, ee := checkExternals(exts, e2eCtx)
	if ee != nil {
		return 0, nil, ee
	}
	tag, c, err := asn1.NewDecoder(tlv).ReadTLV()
	if err != nil || tag.Class != asn1.ClassContextSpecific || !tag.Constructed || tag.Number < 1 || tag.Number > 3 {
		return 0, nil, envErr(DiagProtocolError, "HandshakeRsp alternative %v", tag)
	}
	return int(tag.Number), c, nil
}

// ParseAssoAbr returns the AssoAbort alternative of an ABRT user-information
// and the SecPDU content, or the osiDiag value for AbrOsiDiag.
func ParseAssoAbr(exts [][]byte, e2eCtx int) (alt int, content []byte, osiDiag int, err error) {
	tlv, ee := checkExternals(exts, e2eCtx)
	if ee != nil {
		return 0, nil, 0, ee
	}
	tag, c, err := asn1.NewDecoder(tlv).ReadTLV()
	if err != nil || tag.Class != asn1.ClassContextSpecific {
		return 0, nil, 0, envErr(DiagProtocolError, "AssoAbort alternative %v", tag)
	}
	switch {
	case tag.Number == AbrOsiDiag && !tag.Constructed:
		n, err := asn1.DecodeInt(c)
		if err != nil {
			return 0, nil, 0, envErr(DiagProtocolError, "osiDiag: %v", err)
		}
		return AbrOsiDiag, nil, int(n), nil
	case tag.Constructed && tag.Number <= 2:
		return int(tag.Number), c, 0, nil
	}
	return 0, nil, 0, envErr(DiagProtocolError, "AssoAbort alternative %v", tag)
}

// ParseRelease returns the content of the ReleaseReq/ReleaseRsp of an
// RLRQ/RLRE user-information.
func ParseRelease(exts [][]byte, e2eCtx int) ([]byte, error) {
	tlv, ee := checkExternals(exts, e2eCtx)
	if ee != nil {
		return nil, ee
	}
	c, err := asn1.NewDecoder(tlv).Expect(asn1.TagSequence)
	if err != nil {
		return nil, envErr(DiagProtocolError, "release SecPDU: %v", err)
	}
	return c, nil
}

// AbortKind maps an AssoAbort alternative to its SecPDU kind.
func AbortKind(alt int) e2e.Kind {
	switch alt {
	case AbrHandsSec:
		return e2e.KindHandshakeSecAbort
	case AbrDtSec:
		return e2e.KindDtSecAbort
	}
	return e2e.KindApplAbort
}

// RspKind maps a HandshakeRsp alternative to its SecPDU kind.
func RspKind(alt int) e2e.Kind {
	switch alt {
	case RspAccept:
		return e2e.KindHandshakeAcc
	case RspApplReject:
		return e2e.KindApplicationReject
	}
	return e2e.KindHandshakeSecReject
}

// ParseData checks a data-phase PDV (presentation context id and the
// single-ASN1-type contents) and returns the SecPDU content octets and
// whether it is an EncrTransfer.
func ParseData(ctx int, tlv []byte, e2eCtx int) (content []byte, encrypted bool, err error) {
	if ctx < 0 {
		return nil, false, envErr(DiagProtocolError, "presentation-context-identifier absent")
	}
	if ctx != e2eCtx {
		return nil, false, envErr(DiagInvalidPCI, "presentation context %d, E2E context %d", ctx, e2eCtx)
	}
	c, err := asn1.NewDecoder(tlv).Expect(asn1.TagSequence)
	if err != nil {
		return nil, false, envErr(DiagProtocolError, "transfer SecPDU: %v", err)
	}
	// ClearTransfer and EncrTransfer differ in the second element of tbp:
	// an ApplData EXTERNAL or an OCTET STRING.
	tbp, err := asn1.NewDecoder(c).Expect(asn1.TagSequence)
	if err == nil {
		d := asn1.NewDecoder(tbp)
		if d.Skip() == nil {
			if tag, ok := d.PeekTag(); ok && tag == asn1.TagOctetString {
				encrypted = true
			}
		}
	}
	return c, encrypted, nil
}
