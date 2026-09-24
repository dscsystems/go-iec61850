package mms

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// The client's proposed parameter CBB is the IEC 61850-8-1 mandatory set:
// str1, str2, vnam, valt and vlis, and nothing else.
func TestClientParameterCBB(t *testing.T) {
	cbb := parameterCBB()
	want := map[int]bool{
		cbbStr1: true, cbbStr2: true, cbbVnam: true, cbbValt: true, cbbVlis: true,
		cbbVadr: false, cbbVsca: false, cbbTpy: false, cbbReal: false, cbbCei: false,
	}
	for bit, w := range want {
		if cbb.Bit(bit) != w {
			t.Errorf("CBB bit %d = %v, want %v", bit, cbb.Bit(bit), w)
		}
	}
	// On the wire: 5 unused bits, then str1 str2 vnam valt . . . vlis.
	if got := asn1.AppendBitString(nil, cbb); len(got) != 3 || got[0] != 5 || got[1] != 0xf1 || got[2] != 0 {
		t.Errorf("CBB encoding = % x, want 05 f1 00", got)
	}
}

// The client's servicesSupported lists what it takes part in, and none of
// the type-definition or VMD-control services it has no part in.
func TestClientServicesSupported(t *testing.T) {
	s := defaultServiceSupport()
	for _, bit := range []int{
		ServiceGetNameList, ServiceIdentify, ServiceRead, ServiceWrite,
		ServiceGetVariableAccessAttributes, ServiceDefineNamedVariableList,
		ServiceGetNamedVariableListAttributes, ServiceDeleteNamedVariableList,
		ServiceReadJournal, ServiceFileOpen, ServiceFileRead, ServiceFileClose,
		ServiceFileDirectory, ServiceInformationReport, ServiceConclude,
	} {
		if !s.Has(bit) {
			t.Errorf("service bit %d missing", bit)
		}
	}
	// defineNamedType, getNamedTypeAttributes, deleteNamedType, output,
	// takeControl.
	for _, bit := range []int{14, 15, 16, 18, 19} {
		if s.Has(bit) {
			t.Errorf("service bit %d claimed but not implemented", bit)
		}
	}
}

// A caller naming only MaxServOutstanding is clamped to the proposal on
// both the calling and called values, and a proposal larger than ours is
// not adopted.
func TestClampInitiateOutstanding(t *testing.T) {
	want := InitiateRequest{MaxServOutstanding: 5}
	got := clampInitiate(want, InitiateRequest{MaxServOutstandingCalling: 20, MaxServOutstandingCalled: 3})
	if got.MaxServOutstandingCalling != 5 || got.MaxServOutstandingCalled != 3 {
		t.Errorf("calling/called = %d/%d, want 5/3", got.MaxServOutstandingCalling, got.MaxServOutstandingCalled)
	}
}
