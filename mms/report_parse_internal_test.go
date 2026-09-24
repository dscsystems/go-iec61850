package mms

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// Each listOfVariable entry is a SEQUENCE around its variableSpecification
// (ISO 9506-2). The names inside must come out: CommandTermination and
// LastApplError are identified by them.
func TestInformationReportListOfVariableNames(t *testing.T) {
	entry := func(name *asn1.Element) *asn1.Element {
		return asn1.Cons(asn1.TagSequence, asn1.Cons(asn1.ContextConstructed(0), name))
	}
	body := asn1.Cons(asn1.ContextConstructed(0), // informationReport
		asn1.Cons(asn1.ContextConstructed(0), // listOfVariable
			entry(asn1.Prim(asn1.ContextPrimitive(0), []byte("LastApplError"))),
			entry(asn1.Cons(asn1.ContextConstructed(1),
				asn1.Prim(asn1.TagVisibleString, []byte("LD")),
				asn1.Prim(asn1.TagVisibleString, []byte("GGIO1$CO$SPCSO1$Oper"))))),
		asn1.Cons(asn1.ContextConstructed(0), DataElement(NewBool(true)), DataElement(NewBool(false))),
	)
	dec := asn1.NewDecoder(body.Encode())
	_, content, err := dec.ReadTLV()
	if err != nil {
		t.Fatal(err)
	}
	rep := parseInformationReport(content)
	if rep == nil || len(rep.VarRefs) != 2 {
		t.Fatalf("parsed %+v", rep)
	}
	if rep.VarRefs[0] != (VarRef{Item: "LastApplError"}) {
		t.Errorf("entry 0 = %+v, want the VMD-specific LastApplError", rep.VarRefs[0])
	}
	if rep.VarRefs[1] != (VarRef{Domain: "LD", Item: "GGIO1$CO$SPCSO1$Oper"}) {
		t.Errorf("entry 1 = %+v", rep.VarRefs[1])
	}
}
