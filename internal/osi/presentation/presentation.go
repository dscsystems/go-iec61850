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

// BuildCPA builds a CPA (Connect Presentation Accept) PDU accepting both
// contexts and wrapping acseData (the ACSE AARE).
func BuildCPA(callingPSel, calledPSel, acseData []byte) []byte {
	normal := asn1.Cons(asn1.ContextConstructed(2))
	if len(callingPSel) > 0 {
		normal.Add(asn1.Prim(asn1.ContextPrimitive(1), callingPSel))
	}
	if len(calledPSel) > 0 {
		normal.Add(asn1.Prim(asn1.ContextPrimitive(2), calledPSel))
	}
	// presentation-context-definition-result-list [5]: accept both.
	normal.Add(asn1.Cons(asn1.ContextConstructed(5),
		contextResult(0), // acceptance
		contextResult(0),
	))
	normal.Add(userData(ContextACSE, acseData))

	cpa := asn1.Cons(asn1.TagSet, modeSelector(), normal)
	return cpa.Encode()
}

// WrapData wraps an MMS PDU in fully-encoded-data for the MMS context.
func WrapData(mmsPDU []byte) []byte {
	return userData(ContextMMS, mmsPDU).Encode()
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

func contextResult(result int) *asn1.Element {
	// Result ::= SEQUENCE { result [0] INTEGER, transfer-syntax-name [1] }
	return asn1.Cons(asn1.TagSequence,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(result)),
		asn1.OIDElem(asn1.ContextPrimitive(1), oidBER),
	)
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
