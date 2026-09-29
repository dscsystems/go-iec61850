// Package presentation implements the subset of the ISO 8823 / X.226
// connection-oriented presentation protocol used by MMS: the CP/CPA
// connection PDUs that negotiate the ACSE and MMS presentation contexts,
// and the fully-encoded-data wrapping applied to every data-phase PDU.
package presentation

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// Presentation context identifiers used by the MMS profile.
const (
	ContextACSE = 1
	ContextMMS  = 3
)

// Abstract and transfer syntax object identifiers.
var (
	oidACSE = asn1.OID{2, 2, 1, 0, 1}    // acse-as (association control)
	oidMMS  = asn1.OID{1, 0, 9506, 2, 1} // MMS abstract syntax
	oidBER  = asn1.OID{2, 1, 1}          // basic encoding transfer syntax
)

// Context is one presentation context a peer proposed: the identifier it
// chose for it, the abstract syntax it means, and the transfer syntax it
// proposes for that syntax.
type Context struct {
	ID             int
	AbstractSyntax asn1.OID
	TransferSyntax asn1.OID
}

// IsACSE and IsMMS report which syntax the context carries. The identifiers
// do not say so: a peer is free to number its contexts as it likes, and
// only the abstract syntax decides what each one is for.
func (c Context) IsACSE() bool { return c.AbstractSyntax.Equal(oidACSE) }
func (c Context) IsMMS() bool  { return c.AbstractSyntax.Equal(oidMMS) }

// BER reports whether the context proposes the basic encoding rules, the
// only transfer syntax this library implements.
func (c Context) BER() bool { return c.TransferSyntax.Equal(oidBER) }

// Acceptable reports whether this library can serve the context.
func (c Context) Acceptable() bool { return (c.IsACSE() || c.IsMMS()) && c.BER() }

// Default presentation selectors used by common 61850 stacks.
var (
	DefaultCallingPSel = []byte{0x00, 0x00, 0x00, 0x01}
	DefaultCalledPSel  = []byte{0x00, 0x00, 0x00, 0x01}
)

// BuildCP builds a CP (Connect Presentation) PDU wrapping acseData (the
// ACSE AARQ) in the ACSE presentation context.
func BuildCP(callingPSel, calledPSel, acseData []byte) []byte {
	normal := asn1.Cons(asn1.ContextConstructed(2)) // normal-mode-parameters [2]
	if len(callingPSel) > 0 {
		normal.Add(asn1.Prim(asn1.ContextPrimitive(1), callingPSel))
	}
	if len(calledPSel) > 0 {
		normal.Add(asn1.Prim(asn1.ContextPrimitive(2), calledPSel))
	}
	normal.Add(asn1.Cons(asn1.ContextConstructed(4), // context-definition-list [4]
		contextEntry(ContextACSE, oidACSE),
		contextEntry(ContextMMS, oidMMS),
	))
	normal.Add(userData(ContextACSE, acseData))

	cp := asn1.Cons(asn1.TagSet, // CP-type ::= SET
		modeSelector(),
		normal,
	)
	return cp.Encode()
}

// Negotiated records which of the contexts a peer proposed this library
// accepted, under the identifiers the peer gave them.
//
// A presentation context identifier is chosen by the proposer, not agreed
// as a constant: the ACSE and MMS contexts are conventionally numbered 1
// and 3, but that is a convention of the stacks that use it. A responder
// that assumes 3 and a proposer that chose 2 agree on nothing, and every
// subsequent PDU is mis-tagged — which a client sees as silence rather
// than as an error, since a wrong context identifier is not a decodable
// MMS PDU.
type Negotiated struct {
	// ACSE and MMS are the identifiers the peer assigned to the two
	// contexts, or zero when it proposed neither.
	ACSE, MMS int
}

// HasACSE and HasMMS report which contexts were agreed.
func (n Negotiated) HasACSE() bool { return n.ACSE != 0 }
func (n Negotiated) HasMMS() bool  { return n.MMS != 0 }

// Negotiate decides which of the proposed contexts this library accepts,
// without building anything. A responder needs the outcome before the CPA:
// the AARE inside it names the MMS context by the identifier the peer chose.
func Negotiate(proposed []Context) Negotiated {
	var neg Negotiated
	for _, c := range proposed {
		switch {
		case !c.Acceptable():
		case c.IsACSE():
			neg.ACSE = c.ID
		case c.IsMMS():
			neg.MMS = c.ID
		}
	}
	return neg
}

// Result is the per-context outcome in a CPA's result list.
type Result int

const (
	// ResultAcceptance: the context is accepted.
	ResultAcceptance Result = 0
	// ResultProviderRejection: the responder cannot serve the context.
	ResultProviderRejection Result = 1
	// ResultAbstractSyntaxNotSupported: the abstract syntax is unknown.
	ResultAbstractSyntaxNotSupported Result = 2
)

// BuildCPA builds a CPA (Connect Presentation Accept) PDU wrapping acseData
// (the ACSE AARE), accepting the contexts this library can serve and
// rejecting the rest. The result list has one entry per proposal, in
// proposal order, which is how the peer maps it back to its own contexts.
//
// The CPA is not a CP with a different name: ISO 8823 gives its normal-mode
// parameters their own tags, where the responder states one
// responding-presentation-selector [3] and there is no place for the calling
// [1] or called [2] selectors a CP carries. A CPA built from the CP's tags
// decodes as a malformed CPA, and a peer that validates it drops the
// connection before any user data is exchanged.
//
// acseContextID is the identifier the peer gave the ACSE context, used to
// wrap the AARE.
func BuildCPA(respondingPSel []byte, proposed []Context, acseData []byte) (Negotiated, []byte) {
	neg := Negotiate(proposed)
	normal := asn1.Cons(asn1.ContextConstructed(2))
	if len(respondingPSel) > 0 {
		// responding-presentation-selector [3] IMPLICIT OCTET STRING
		normal.Add(asn1.Prim(asn1.ContextPrimitive(3), respondingPSel))
	}
	results := asn1.Cons(asn1.ContextConstructed(5))
	for _, c := range proposed {
		if c.Acceptable() {
			results.Add(contextResult(ResultAcceptance))
		} else {
			results.Add(contextResult(ResultProviderRejection))
		}
	}
	normal.Add(results)
	acseID := neg.ACSE
	if acseID == 0 {
		// A peer that proposed no ACSE context cannot receive the AARE;
		// the ACSE context is the one that carries it, so the CPA is
		// built with the conventional identifier and the peer will reject
		// it. Failing here would be a clearer error than a silent one.
		acseID = ContextACSE
	}
	normal.Add(userData(acseID, acseData))

	cpa := asn1.Cons(asn1.TagSet, modeSelector(), normal)
	return neg, cpa.Encode()
}

// BuildCPR builds a CPR (Connect Presentation Reject) PDU for a
// connection the presentation user refuses — an association the ACSE
// rejects — carrying acseData (the rejecting AARE) in the ACSE context.
// Its normal-mode parameters are a SEQUENCE (ISO 8823), with the
// responding selector and the per-context results as in a CPA.
func BuildCPR(respondingPSel []byte, proposed []Context, acseData []byte) []byte {
	neg := Negotiate(proposed)
	seq := asn1.Cons(asn1.TagSequence)
	if len(respondingPSel) > 0 {
		seq.Add(asn1.Prim(asn1.ContextPrimitive(3), respondingPSel))
	}
	results := asn1.Cons(asn1.ContextConstructed(5))
	for _, c := range proposed {
		if c.Acceptable() {
			results.Add(contextResult(ResultAcceptance))
		} else {
			results.Add(contextResult(ResultProviderRejection))
		}
	}
	seq.Add(results)
	acseID := neg.ACSE
	if acseID == 0 {
		acseID = ContextACSE
	}
	seq.Add(userData(acseID, acseData))
	return seq.Encode()
}

// ParseCPRUserData extracts the ACSE user data (the AARE) from a CPR PDU.
func ParseCPRUserData(pdu []byte) ([]byte, error) {
	seq, err := asn1.NewDecoder(pdu).Expect(asn1.TagSequence)
	if err != nil {
		return nil, fmt.Errorf("presentation: CPR not a SEQUENCE: %w", err)
	}
	return findFullyEncoded(seq)
}

// WrapAbort builds an ARU (abnormal release by the user) PDU carrying abrt
// (the ACSE ABRT) in the ACSE presentation context: its normal-mode
// parameters, [0] IMPLICIT SEQUENCE, hold only the user data.
func WrapAbort(acseContextID int, abrt []byte) []byte {
	if acseContextID == 0 {
		acseContextID = ContextACSE
	}
	return asn1.Cons(asn1.ContextConstructed(0), userData(acseContextID, abrt)).Encode()
}

// UnwrapAbort extracts the user data (the ACSE ABRT) from an ARU PDU. A
// SEQUENCE in place of the [0] tag is accepted too.
func UnwrapAbort(pdu []byte) ([]byte, error) {
	tag, content, err := asn1.NewDecoder(pdu).ReadTLV()
	if err != nil {
		return nil, err
	}
	if tag != asn1.ContextConstructed(0) && tag != asn1.TagSequence {
		return nil, fmt.Errorf("presentation: ARU of tag %v", tag)
	}
	return findFullyEncoded(content)
}

// findFullyEncoded returns the data of the first fully-encoded-data element
// among a PDU's parameters.
func findFullyEncoded(content []byte) ([]byte, error) {
	dec := asn1.NewDecoder(content)
	for dec.More() {
		t, c, err := dec.ReadTLV()
		if err != nil {
			return nil, err
		}
		if t == asn1.ApplicationConstructed(1) {
			_, data, err := parsePDVList(c)
			return data, err
		}
	}
	return nil, fmt.Errorf("presentation: no user data")
}

// CP holds what a responder needs from a peer's CP: the selector it
// addressed and the presentation contexts it proposed.
type CP struct {
	CallingPSel []byte
	CalledPSel  []byte
	Contexts    []Context
	UserData    []byte // the ACSE AARQ
}

// ParseCP decodes a CP PDU.
func ParseCP(pdu []byte) (CP, error) {
	var cp CP
	dec := asn1.NewDecoder(pdu)
	setContent, err := dec.Expect(asn1.TagSet)
	if err != nil {
		return cp, fmt.Errorf("presentation: CP not a SET: %w", err)
	}
	inner := asn1.NewDecoder(setContent)
	for inner.More() {
		tag, content, err := inner.ReadTLV()
		if err != nil {
			return cp, err
		}
		if tag != asn1.ContextConstructed(2) { // normal-mode-parameters
			continue
		}
		nm := asn1.NewDecoder(content)
		for nm.More() {
			t, c, err := nm.ReadTLV()
			if err != nil {
				return cp, err
			}
			switch t {
			case asn1.ContextPrimitive(1):
				cp.CallingPSel = append([]byte(nil), c...)
			case asn1.ContextPrimitive(2):
				cp.CalledPSel = append([]byte(nil), c...)
			case asn1.ContextConstructed(4): // context-definition-list
				cp.Contexts = parseContextList(c)
			case asn1.ApplicationConstructed(1): // fully-encoded-data
				_, data, err := parsePDVList(c)
				if err != nil {
					return cp, err
				}
				cp.UserData = data
			}
		}
	}
	if cp.UserData == nil {
		return cp, fmt.Errorf("presentation: no user data in CP")
	}
	return cp, nil
}

// parseContextList decodes a context-definition-list. Each entry is
// PresentationContextDefinition ::= SEQUENCE { presentation-context-identifier
// INTEGER, abstract-syntax, transfer-syntax-name }, and the last may instead
// be the abbreviated form without a transfer syntax.
func parseContextList(content []byte) []Context {
	dec := asn1.NewDecoder(content)
	var out []Context
	for dec.More() {
		tag, body, err := dec.ReadTLV()
		if err != nil || tag != asn1.TagSequence {
			// An entry that does not decode ends the list; the caller's
			// acceptance check reports the shortfall.
			return out
		}
		entry := asn1.NewDecoder(body)
		var c Context
		for entry.More() {
			t, v, err := entry.ReadTLV()
			if err != nil {
				return out
			}
			switch t {
			case asn1.TagInteger:
				if n, err := asn1.DecodeInt(v); err == nil {
					c.ID = int(n)
				}
			case asn1.TagOID:
				// The abbreviated form names the transfer syntax directly.
				oid, err := asn1.DecodeOID(v)
				if err != nil {
					return out
				}
				if c.AbstractSyntax == nil {
					c.AbstractSyntax = oid
				} else {
					c.TransferSyntax = oid
				}
			case asn1.TagSequence:
				// transfer-syntax-name, a CHOICE of OIDs.
				ts := asn1.NewDecoder(v)
				for ts.More() {
					ot, ov, err := ts.ReadTLV()
					if err != nil {
						break
					}
					if ot == asn1.TagOID {
						if oid, err := asn1.DecodeOID(ov); err == nil {
							c.TransferSyntax = oid
						}
					}
				}
			}
		}
		out = append(out, c)
	}
	return out
}

// WrapData wraps an MMS PDU in fully-encoded-data for the MMS presentation
// context. contextID is the identifier the peer assigned to it, which is
// not necessarily ContextMMS: the identifier is the proposer's choice.
func WrapData(contextID int, mmsPDU []byte) []byte {
	if contextID == 0 {
		contextID = ContextMMS
	}
	return userData(contextID, mmsPDU).Encode()
}

// UnwrapData extracts the user data (an MMS PDU) from a data-phase
// presentation PDU, ignoring the presentation-context-identifier.
func UnwrapData(pdu []byte) ([]byte, error) {
	_, data, err := parseUserData(pdu)
	return data, err
}

// ParseCPUserData extracts the ACSE user data from a CP or CPA PDU.
func ParseCPUserData(pdu []byte) ([]byte, error) {
	dec := asn1.NewDecoder(pdu)
	setContent, err := dec.Expect(asn1.TagSet)
	if err != nil {
		return nil, fmt.Errorf("presentation: CP not a SET: %w", err)
	}
	inner := asn1.NewDecoder(setContent)
	for inner.More() {
		tag, content, err := inner.ReadTLV()
		if err != nil {
			return nil, err
		}
		if tag == asn1.ContextConstructed(2) { // normal-mode-parameters
			nm := asn1.NewDecoder(content)
			for nm.More() {
				t, c, err := nm.ReadTLV()
				if err != nil {
					return nil, err
				}
				if t == asn1.ApplicationConstructed(1) { // fully-encoded-data
					_, data, err := parsePDVList(c)
					return data, err
				}
			}
		}
	}
	return nil, fmt.Errorf("presentation: no user data in CP")
}

func modeSelector() *asn1.Element {
	// mode-selector [0] IMPLICIT SET { mode-value [0] INTEGER normal(1) }
	return asn1.Cons(asn1.ContextConstructed(0),
		asn1.IntElem(asn1.ContextPrimitive(0), 1))
}

func contextEntry(id int, abstractSyntax asn1.OID) *asn1.Element {
	return asn1.Cons(asn1.TagSequence,
		asn1.IntElem(asn1.TagInteger, int64(id)),
		asn1.OIDElem(asn1.TagOID, abstractSyntax),
		asn1.Cons(asn1.TagSequence, asn1.OIDElem(asn1.TagOID, oidBER)),
	)
}

// contextResult builds one entry of a CPA result list. An accepted context
// names the transfer syntax it is accepted with; a rejected one carries
// only the reason.
func contextResult(result Result) *asn1.Element {
	e := asn1.Cons(asn1.TagSequence,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(result)))
	if result == ResultAcceptance {
		e.Add(asn1.OIDElem(asn1.ContextPrimitive(1), oidBER))
	}
	return e
}

// userData builds a fully-encoded-data [APPLICATION 1] wrapping payload in
// the given presentation context via single-ASN1-type.
func userData(contextID int, payload []byte) *asn1.Element {
	pdv := asn1.Cons(asn1.TagSequence,
		asn1.IntElem(asn1.TagInteger, int64(contextID)),
		asn1.RawContent(asn1.ContextConstructed(0), payload), // single-ASN1-type [0]
	)
	return asn1.Cons(asn1.ApplicationConstructed(1), pdv)
}

func parseUserData(pdu []byte) (contextID int, data []byte, err error) {
	dec := asn1.NewDecoder(pdu)
	tag, content, err := dec.ReadTLV()
	if err != nil {
		return 0, nil, err
	}
	if tag != asn1.ApplicationConstructed(1) {
		return 0, nil, fmt.Errorf("presentation: expected fully-encoded-data, got %v", tag)
	}
	return parsePDVList(content)
}

func parsePDVList(content []byte) (contextID int, data []byte, err error) {
	dec := asn1.NewDecoder(content)
	seq, err := dec.Expect(asn1.TagSequence)
	if err != nil {
		return 0, nil, err
	}
	inner := asn1.NewDecoder(seq)
	// Optional transfer-syntax-name OID, then context-identifier INTEGER,
	// then presentation-data-values.
	for inner.More() {
		tag, c, err := inner.ReadTLV()
		if err != nil {
			return 0, nil, err
		}
		switch {
		case tag == asn1.TagInteger:
			n, err := asn1.DecodeInt(c)
			if err != nil {
				return 0, nil, err
			}
			contextID = int(n)
		case tag == asn1.ContextConstructed(0): // single-ASN1-type
			return contextID, c, nil
		case tag == asn1.ContextPrimitive(1): // octet-aligned
			return contextID, c, nil
		}
	}
	return contextID, nil, fmt.Errorf("presentation: no data values in PDV-list")
}
