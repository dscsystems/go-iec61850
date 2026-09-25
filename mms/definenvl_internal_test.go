package mms

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// ISO 9506-2 tags DefineNamedVariableList's listOfVariable [0]. The [1] of
// the attributes response is rejected by a strict server as an invalid PDU,
// which silently breaks dataset creation on real devices.
func TestDefineNamedVariableListTagsItsListZero(t *testing.T) {
	req := defineNamedVariableListRequest("LD", "LLN0$DS",
		[]VarRef{{Domain: "LD", Item: "GGIO1$ST$Ind1$stVal"}}).Encode()

	body, err := asn1.NewDecoder(req).Expect(asn1.ContextConstructed(svcDefineNamedVarList))
	if err != nil {
		t.Fatal(err)
	}
	d := asn1.NewDecoder(body)
	if tag, _, err := d.ReadTLV(); err != nil || tag != asn1.ContextConstructed(1) {
		t.Fatalf("variableListName: tag %v, err %v; want domain-specific [1]", tag, err)
	}
	list, err := d.Expect(asn1.ContextConstructed(0))
	if err != nil {
		t.Fatalf("listOfVariable is not [0]: %v", err)
	}
	entry, err := asn1.NewDecoder(list).Expect(asn1.TagSequence)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := asn1.NewDecoder(entry).Expect(asn1.ContextConstructed(0))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := parseObjectName(spec)
	if err != nil || ref != (VarRef{Domain: "LD", Item: "GGIO1$ST$Ind1$stVal"}) {
		t.Fatalf("member = %+v, err %v", ref, err)
	}
}
