package acse

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// This file holds the ACSE support of IEC 62351-4 native mode (clause 15):
// kernel-only APDUs whose user-information carries E2E SecPDUs, aborts and
// releases with user-information, and the parsing a responder needs to
// enforce the kernel.

var tagExternal = asn1.Tag{Class: asn1.ClassUniversal, Constructed: true, Number: 8}

// Result values of an AARE.
const (
	ResultAccepted          = 0
	ResultRejectedPermanent = 1
	ResultRejectedTransient = 2
)

// Associate-source-diagnostic values.
const (
	DiagNull                       = 0
	DiagAppContextNotSupported     = 2
	DiagCalledAPTitleNotRecognized = 7
)

func userInfoElem(userInfo [][]byte) *asn1.Element {
	if len(userInfo) == 0 {
		return nil
	}
	ui := asn1.Cons(asn1.ContextConstructed(30))
	for _, x := range userInfo {
		ui.Add(asn1.RawTLV(x))
	}
	return ui
}

// BuildAARQ builds a kernel-only AARQ (no authentication functional unit)
// whose user-information is the given EXTERNAL TLVs.
func BuildAARQ(appCtx asn1.OID, called, calling Identity, userInfo [][]byte) []byte {
	seq := asn1.Cons(tagAARQ,
		asn1.Cons(asn1.ContextConstructed(1), asn1.OIDElem(asn1.TagOID, appCtx)))
	addIdentity(seq, 2, called)
	addIdentity(seq, 6, calling)
	seq.Add(userInfoElem(userInfo))
	return seq.Encode()
}

// BuildAARE builds an AARE with the given result and acse-service-user
// diagnostic, responding identity and user-information.
func BuildAARE(appCtx asn1.OID, result, diag int, responding Identity, userInfo [][]byte) []byte {
	seq := asn1.Cons(tagAARE,
		asn1.Cons(asn1.ContextConstructed(1), asn1.OIDElem(asn1.TagOID, appCtx)),
		asn1.Cons(asn1.ContextConstructed(2), asn1.IntElem(asn1.TagInteger, int64(result))),
		asn1.Cons(asn1.ContextConstructed(3),
			asn1.Cons(asn1.ContextConstructed(1), asn1.IntElem(asn1.TagInteger, int64(diag)))),
	)
	addIdentity(seq, 4, responding)
	seq.Add(userInfoElem(userInfo))
	return seq.Encode()
}

// BuildABRT builds an ABRT with abort-source and user-information (abort-
// diagnostic absent, as IEC 62351-4 15.3.4 requires).
func BuildABRT(source int, userInfo [][]byte) []byte {
	return asn1.Cons(tagABRT,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(source)),
		userInfoElem(userInfo),
	).Encode()
}

// Release-request and release-response reasons.
const (
	ReleaseNormal = 0
	ReleaseUrgent = 1
)

// BuildRLRQ builds an RLRQ with a reason and user-information.
func BuildRLRQ(reason int, userInfo [][]byte) []byte {
	return asn1.Cons(tagRLRQ,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(reason)),
		userInfoElem(userInfo),
	).Encode()
}

// BuildRLRE builds an RLRE with a reason and user-information.
func BuildRLRE(reason int, userInfo [][]byte) []byte {
	return asn1.Cons(tagRLRE,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(reason)),
		userInfoElem(userInfo),
	).Encode()
}

// externals returns the EXTERNAL TLVs of a user-information content.
func externals(content []byte) ([][]byte, error) {
	d := asn1.NewDecoder(content)
	var out [][]byte
	for d.More() {
		s, err := d.ReadSpan()
		if err != nil {
			return nil, err
		}
		if s.Tag != tagExternal {
			return nil, fmt.Errorf("acse: user-information element %v is not EXTERNAL", s.Tag)
		}
		if len(out) >= 8 {
			return nil, fmt.Errorf("acse: too many EXTERNALs")
		}
		out = append(out, s.Full)
	}
	return out, nil
}

// ABRT-diagnostic values (ISO 8650-1, ACSE version 2).
const (
	AbortDiagNoReason               = 1
	AbortDiagProtocolError          = 2
	AbortDiagMechanismNotRecognised = 3
	AbortDiagMechanismRequired      = 4
	AbortDiagAuthenticationFailure  = 5
	AbortDiagAuthenticationRequired = 6
)

// Abort is a parsed ABRT.
type Abort struct {
	Source     int
	Diagnostic int // -1 when absent
	UserInfo   [][]byte
}

// ParseABRTFull parses an ABRT with its diagnostic and user-information.
func ParseABRTFull(apdu []byte) (Abort, error) {
	ab := Abort{Diagnostic: -1}
	content, err := asn1.NewDecoder(apdu).Expect(tagABRT)
	if err != nil {
		return ab, fmt.Errorf("acse: not an ABRT: %w", err)
	}
	d := asn1.NewDecoder(content)
	for d.More() {
		tag, c, err := d.ReadTLV()
		if err != nil {
			return ab, err
		}
		switch tag {
		case asn1.ContextPrimitive(0):
			n, err := asn1.DecodeInt(c)
			if err != nil {
				return ab, err
			}
			ab.Source = int(n)
		case asn1.ContextPrimitive(1):
			n, err := asn1.DecodeInt(c)
			if err != nil {
				return ab, err
			}
			ab.Diagnostic = int(n)
		case asn1.ContextConstructed(30):
			if ab.UserInfo, err = externals(c); err != nil {
				return ab, err
			}
		}
	}
	return ab, nil
}

// Release is a parsed RLRQ or RLRE.
type Release struct {
	Response bool
	Reason   int // -1 when absent
	UserInfo [][]byte
}

// ParseRelease parses an RLRQ or RLRE.
func ParseRelease(apdu []byte) (Release, error) {
	r := Release{Reason: -1}
	tag, content, err := asn1.NewDecoder(apdu).ReadTLV()
	if err != nil {
		return r, err
	}
	switch tag {
	case tagRLRQ:
	case tagRLRE:
		r.Response = true
	default:
		return r, fmt.Errorf("acse: not a release APDU: %v", tag)
	}
	d := asn1.NewDecoder(content)
	for d.More() {
		t, c, err := d.ReadTLV()
		if err != nil {
			return r, err
		}
		switch t {
		case asn1.ContextPrimitive(0):
			n, err := asn1.DecodeInt(c)
			if err != nil {
				return r, err
			}
			r.Reason = int(n)
		case asn1.ContextConstructed(30):
			if r.UserInfo, err = externals(c); err != nil {
				return r, err
			}
		}
	}
	return r, nil
}

// IsABRT reports whether apdu is an ABRT.
func IsABRT(apdu []byte) bool { return asn1.NewDecoder(apdu).PeekIs(tagABRT) }
