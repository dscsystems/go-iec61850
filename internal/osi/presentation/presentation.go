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

// BuildCPA builds a CPA (Connect Presentation Accept) PDU accepting the
// contexts the peer proposed and wrapping acseData (the ACSE AARE).
//
// The CPA is not a CP with a different name: ISO 8823 gives its normal-mode
// parameters their own tags, where the responder states one
// responding-presentation-selector [3] and there is no place for the calling
// [1] or called [2] selectors a CP carries. A CPA built from the CP's tags
// decodes as a malformed CPA, and a peer that validates it drops the
// connection before any user data is exchanged.
//
// contexts is the number of presentation contexts the peer proposed: the
// result list has one entry per proposal, matched by position, so a fixed
// pair would misreport any peer that proposes a different number.
func BuildCPA(respondingPSel []byte, contexts int, acseData []byte) []byte {
	normal := asn1.Cons(asn1.ContextConstructed(2))
	if len(respondingPSel) > 0 {
		// responding-presentation-selector [3] IMPLICIT OCTET STRING
		normal.Add(asn1.Prim(asn1.ContextPrimitive(3), respondingPSel))
	}
	if contexts <= 0 {
		contexts = 2 // the ACSE and MMS pair every MMS peer proposes
	}
	results := asn1.Cons(asn1.ContextConstructed(5))
	for i := 0; i < contexts; i++ {
		results.Add(contextResult(0)) // acceptance
	}
	normal.Add(results)
	normal.Add(userData(ContextACSE, acseData))

	cpa := asn1.Cons(asn1.TagSet, modeSelector(), normal)
	return cpa.Encode()
}

// CP holds what a responder needs from a peer's CP: the selector it addressed
// and how many presentation contexts it proposed.
type CP struct {
	CallingPSel []byte
	CalledPSel  []byte
	Contexts    int
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
				cp.Contexts = countSequences(c)
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

// countSequences counts the SEQUENCE entries in a list.
func countSequences(content []byte) int {
	dec := asn1.NewDecoder(content)
	n := 0
	for dec.More() {
		tag, _, err := dec.ReadTLV()
		if err != nil {
			return n
		}
		if tag == asn1.TagSequence {
			n++
		}
	}
	return n
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
