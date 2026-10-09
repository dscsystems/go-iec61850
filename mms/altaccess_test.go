package mms

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// The GetNamedVariableListAttributes response libiec61850 v1.6's
// server_example_complex_array sends for MHAI1$TestMHAI (the content of the
// [12] response element), captured on the wire.
const complexArrayNVL = "800100a18201313030a029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617" +
	"2a50382010730" + "30a029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617" +
	"2a5038201083" + "03aa029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617" +
	"2a50da00b810109300681046356616c" + "3043a029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617" +
	"2a516a014810" + "10a300fa00d80046356616c300581036d6167" + "304aa029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617" +
	"2a51da01b81010b3016a01480046356616c300ca00a80036d6167300381016" + "6"

func TestParseListMembersKeepsAlternateAccess(t *testing.T) {
	raw, err := hex.DecodeString(strings.ReplaceAll(complexArrayNVL, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	members, deletable, err := parseListMembers(raw)
	if err != nil {
		t.Fatal(err)
	}
	if deletable || len(members) != 5 {
		t.Fatalf("deletable=%v, %d members", deletable, len(members))
	}
	want := [][]AccessStep{
		{{Index: 7}},
		{{Index: 8}},
		{{Index: 9}, {Component: "cVal"}},
		{{Index: 10}, {Component: "cVal"}, {Component: "mag"}},
		{{Index: 11}, {Component: "cVal"}, {Component: "mag"}, {Component: "f"}},
	}
	for i, m := range members {
		if m.Domain != "testComplexArray" || m.Item != "MHAI1$MX$HA$phsAHar" {
			t.Errorf("member %d = %v", i, m.VarRef)
		}
		steps, err := ParseAlternateAccess(m.AlternateAccess)
		if err != nil {
			t.Fatalf("member %d: %v", i, err)
		}
		if !reflect.DeepEqual(steps, want[i]) {
			t.Errorf("member %d steps = %v, want %v", i, steps, want[i])
		}
		// Re-encoding reproduces libiec61850's octets exactly.
		if got := AlternateAccessElement(steps); !bytes.Equal(got, m.AlternateAccess) {
			t.Errorf("member %d re-encodes as % x, device sent % x", i, got, m.AlternateAccess)
		}
	}
}

func TestAccessPath(t *testing.T) {
	vector := &TypeSpec{Kind: TypeStructure, Components: []Component{
		{Name: "mag", Spec: &TypeSpec{Kind: TypeStructure, Components: []Component{{Name: "f", Spec: &TypeSpec{Kind: TypeFloat32}}}}},
		{Name: "ang", Spec: &TypeSpec{Kind: TypeStructure, Components: []Component{{Name: "f", Spec: &TypeSpec{Kind: TypeFloat32}}}}},
	}}
	cmv := &TypeSpec{Kind: TypeStructure, Components: []Component{
		{Name: "cVal", Spec: vector}, {Name: "q", Spec: &TypeSpec{Kind: TypeBitString, Size: 13}},
	}}
	arr := &TypeSpec{Kind: TypeArray, Elements: 16, Element: cmv}

	path, spec, err := AccessPath(arr, []AccessStep{{Index: 11}, {Component: "cVal"}, {Component: "mag"}, {Component: "f"}})
	if err != nil || !reflect.DeepEqual(path, []int{11, 0, 0, 0}) || spec.Kind != TypeFloat32 {
		t.Fatalf("path %v spec %v err %v", path, spec, err)
	}
	if _, _, err := AccessPath(arr, []AccessStep{{Index: 16}}); err == nil {
		t.Error("index past the array accepted")
	}
	if _, _, err := AccessPath(arr, []AccessStep{{Index: 1}, {Component: "nope"}}); err == nil {
		t.Error("unknown component accepted")
	}
	if _, err := ParseAlternateAccess([]byte{0x84, 0x00}); err == nil {
		t.Error("allElements accepted")
	}
}
