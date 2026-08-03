package mms

import (
	"bytes"
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// A real ICCP server's InitiateResponse, taken from a capture. A proxy has to
// reproduce these octets, so they are the fixture for the passthrough paths.
var refInitiateResponse = []byte{
	0xa9, 0x26,
	0x80, 0x03, 0x00, 0xfd, 0xe8, // localDetailCalling = 65000
	0x81, 0x01, 0x0a, // maxServOutstandingCalling = 10
	0x82, 0x01, 0x0a, // maxServOutstandingCalled  = 10
	0x83, 0x01, 0x05, // dataStructureNestingLevel = 5
	0xa4, 0x16,
	0x80, 0x01, 0x01, // version = 1
	0x81, 0x03, 0x05, 0xf1, 0x00, // parameterCBB
	0x82, 0x0c, 0x03, 0xee, 0x1c, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x79, 0xef, 0x18,
}

func TestParseInitiateCapturesRawBitStrings(t *testing.T) {
	got, err := ParseInitiateResponse(refInitiateResponse)
	if err != nil {
		t.Fatal(err)
	}
	if got.LocalDetail != 65000 {
		t.Errorf("localDetail = %d", got.LocalDetail)
	}
	if got.MaxServOutstandingCalling != 10 || got.MaxServOutstandingCalled != 10 {
		t.Errorf("outstanding = %d/%d, want 10/10",
			got.MaxServOutstandingCalling, got.MaxServOutstandingCalled)
	}
	if got.NestingLevel != 5 {
		t.Errorf("nesting = %d", got.NestingLevel)
	}
	wantCBB := []byte{0x05, 0xf1, 0x00}
	if !bytes.Equal(got.ParameterCBBRaw, wantCBB) {
		t.Errorf("parameterCBB raw = %x, want %x", got.ParameterCBBRaw, wantCBB)
	}
	wantSvc := []byte{0x03, 0xee, 0x1c, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x79, 0xef, 0x18}
	if !bytes.Equal(got.Services.Raw, wantSvc) {
		t.Errorf("servicesSupported raw = %x, want %x", got.Services.Raw, wantSvc)
	}
}

// The passthrough property: parse then re-encode must reproduce the device's
// octets exactly. Clients gate feature use on servicesSupported, so a
// reconstruction that merely sets the same flags is not good enough.
func TestInitiateResponseRoundTripsByteIdentical(t *testing.T) {
	parsed, err := ParseInitiateResponse(refInitiateResponse)
	if err != nil {
		t.Fatal(err)
	}
	got := EncodeInitiateResponse(parsed)
	if !bytes.Equal(got, refInitiateResponse) {
		t.Errorf("re-encoded response differs:\n got %x\nwant %x", got, refInitiateResponse)
	}
}

func TestEncodeInitiateKeepsCallingAndCalledDistinct(t *testing.T) {
	req := InitiateRequest{
		LocalDetail:               65000,
		MaxServOutstandingCalling: 5,
		MaxServOutstandingCalled:  9,
		NestingLevel:              5,
	}
	enc := EncodeInitiateResponse(req)
	back, err := ParseInitiateResponse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.MaxServOutstandingCalling != 5 || back.MaxServOutstandingCalled != 9 {
		t.Errorf("outstanding = %d/%d, want 5/9",
			back.MaxServOutstandingCalling, back.MaxServOutstandingCalled)
	}
	// The collapsed view stays the smaller of the two, which is what a client
	// deciding how many requests to keep in flight needs.
	if back.MaxServOutstanding != 5 {
		t.Errorf("collapsed = %d, want 5", back.MaxServOutstanding)
	}
}

// A responder must not accept more than the initiator offered, even when it is
// replaying a device that advertised more.
func TestClampInitiateBoundsByProposal(t *testing.T) {
	device := InitiateRequest{
		LocalDetail: 65000, MaxServOutstanding: 10,
		MaxServOutstandingCalling: 10, MaxServOutstandingCalled: 10,
		NestingLevel: 8,
		Services:     ServiceSupport{Raw: []byte{0x03, 0xff}},
	}
	client := InitiateRequest{
		LocalDetail: 32000, MaxServOutstanding: 2,
		MaxServOutstandingCalling: 2, MaxServOutstandingCalled: 2,
		NestingLevel: 5,
	}
	got := clampInitiate(device, client)

	if got.LocalDetail != 32000 {
		t.Errorf("localDetail = %d, want the client's 32000", got.LocalDetail)
	}
	if got.MaxServOutstandingCalling != 2 || got.MaxServOutstandingCalled != 2 {
		t.Errorf("outstanding = %d/%d, want 2/2",
			got.MaxServOutstandingCalling, got.MaxServOutstandingCalled)
	}
	if got.NestingLevel != 5 {
		t.Errorf("nesting = %d, want 5", got.NestingLevel)
	}
	// The bitmap describes what this end supports and is not negotiated down.
	if !bytes.Equal(got.Services.Raw, []byte{0x03, 0xff}) {
		t.Errorf("servicesSupported was altered: %x", got.Services.Raw)
	}
}

func TestClampInitiateKeepsDeviceValuesWhenSmaller(t *testing.T) {
	device := InitiateRequest{LocalDetail: 8000, MaxServOutstanding: 1, NestingLevel: 3}
	client := InitiateRequest{LocalDetail: 65000, MaxServOutstanding: 10, NestingLevel: 8}
	got := clampInitiate(device, client)
	if got.LocalDetail != 8000 || got.MaxServOutstanding != 1 || got.NestingLevel != 3 {
		t.Errorf("got %+v, want the device's smaller values preserved", got)
	}
}

func TestObjectClassConstants(t *testing.T) {
	// Journal discovery needs class 8; the rest round out ISO 9506-2.
	if ClassJournal != 8 {
		t.Errorf("ClassJournal = %d, want 8", ClassJournal)
	}
	if ClassNamedVariable != 0 || ClassNamedVariableList != 2 || ClassDomain != 9 {
		t.Error("the pre-existing constants changed value")
	}
}

// buildReport encodes an InformationReport the way a server would, so the
// decoder can be tested against a realistic PDU.
func buildReport(spec *asn1.Element, values ...*Value) []byte {
	results := asn1.Cons(asn1.ContextConstructed(0))
	for _, v := range values {
		results.Add(DataElement(v))
	}
	return asn1.Cons(asn1.ContextConstructed(unconfInformationReport), spec, results).Encode()
}

// Before this change the decoder discarded every variable name, so a report's
// values could only be attributed by position.
func TestInformationReportKeepsVariableNames(t *testing.T) {
	list := asn1.Cons(asn1.ContextConstructed(0)) // listOfVariable [0]
	for _, r := range []VarRef{
		{Domain: "ICC1", Item: "Transfer_Set_Name"},
		{Item: "VMDDiscrete1"},
	} {
		list.Add(asn1.Cons(asn1.ContextConstructed(0), objectName(r.Domain, r.Item)))
	}
	pdu := buildReport(list, NewVisibleString("ts1"), NewInt32(7))

	dec := asn1.NewDecoder(pdu)
	_, body, err := dec.ReadTLV()
	if err != nil {
		t.Fatal(err)
	}
	rep := parseInformationReport(body)
	if rep == nil {
		t.Fatal("report did not decode")
	}
	if len(rep.VarRefs) != 2 {
		t.Fatalf("VarRefs = %d, want 2", len(rep.VarRefs))
	}
	// A real dataset mixes scopes, so the domain has to survive.
	if rep.VarRefs[0] != (VarRef{Domain: "ICC1", Item: "Transfer_Set_Name"}) {
		t.Errorf("VarRefs[0] = %+v", rep.VarRefs[0])
	}
	if rep.VarRefs[1] != (VarRef{Item: "VMDDiscrete1"}) {
		t.Errorf("VarRefs[1] = %+v", rep.VarRefs[1])
	}
	if rep.VarNames[0] != "Transfer_Set_Name" || rep.VarNames[1] != "VMDDiscrete1" {
		t.Errorf("VarNames = %v", rep.VarNames)
	}
	if len(rep.Values) != 2 || rep.Values[1].Int64() != 7 {
		t.Errorf("values = %+v", rep.Values)
	}
}

func TestInformationReportKeepsListName(t *testing.T) {
	spec := asn1.Cons(asn1.ContextConstructed(1), objectName("LD0", "LLN0$RP$urcb01")) // variableListName [1]
	pdu := buildReport(spec, NewInt32(1))

	dec := asn1.NewDecoder(pdu)
	_, body, _ := dec.ReadTLV()
	rep := parseInformationReport(body)
	if rep == nil {
		t.Fatal("report did not decode")
	}
	if !rep.IsVMDNamed {
		t.Error("expected the variableListName form to be flagged")
	}
	want := VarRef{Domain: "LD0", Item: "LLN0$RP$urcb01"}
	if rep.ListRef != want {
		t.Errorf("ListRef = %+v, want %+v", rep.ListRef, want)
	}
	if rep.ListName != "LLN0$RP$urcb01" {
		t.Errorf("ListName = %q", rep.ListName)
	}
}

// Entries whose specification uses an alternative other than name [0] must
// still occupy a slot, or the values stop lining up with the names.
func TestInformationReportPositionsSurviveUnnamedEntries(t *testing.T) {
	list := asn1.Cons(asn1.ContextConstructed(0)) // listOfVariable [0]
	list.Add(asn1.Cons(asn1.ContextConstructed(0), objectName("", "First")))
	list.Add(asn1.Cons(asn1.ContextConstructed(1), asn1.Prim(asn1.TagOctetString, []byte{1, 2}))) // address
	list.Add(asn1.Cons(asn1.ContextConstructed(0), objectName("", "Third")))
	pdu := buildReport(list, NewInt32(1), NewInt32(2), NewInt32(3))

	dec := asn1.NewDecoder(pdu)
	_, body, _ := dec.ReadTLV()
	rep := parseInformationReport(body)
	if rep == nil {
		t.Fatal("report did not decode")
	}
	if len(rep.VarRefs) != 3 || len(rep.Values) != 3 {
		t.Fatalf("refs=%d values=%d, want 3 and 3", len(rep.VarRefs), len(rep.Values))
	}
	if rep.VarRefs[0].Item != "First" || rep.VarRefs[2].Item != "Third" {
		t.Errorf("names lost their positions: %v", rep.VarNames)
	}
	if rep.VarRefs[1].Item != "" {
		t.Errorf("unnamed entry should be blank, got %q", rep.VarRefs[1].Item)
	}
}
