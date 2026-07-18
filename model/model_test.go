package model

import (
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
)

func TestObjectReference(t *testing.T) {
	r, err := ParseRef("ied1LD0/GGIO1.AnIn1.mag.f")
	if err != nil {
		t.Fatal(err)
	}
	if r.LD() != "ied1LD0" || r.LN() != "GGIO1" {
		t.Fatalf("LD=%q LN=%q", r.LD(), r.LN())
	}
	if got := r.Path(); len(got) != 4 || got[3] != "f" {
		t.Fatalf("Path=%v", got)
	}
	if r.Parent() != "ied1LD0/GGIO1.AnIn1.mag" {
		t.Fatalf("Parent=%q", r.Parent())
	}

	domain, item := r.ToMMS(MX)
	if domain != "ied1LD0" || item != "GGIO1$MX$AnIn1$mag$f" {
		t.Fatalf("ToMMS: %q %q", domain, item)
	}
	back, fc := FromMMS(domain, item)
	if back != r || fc != MX {
		t.Fatalf("FromMMS: %q %v", back, fc)
	}

	// LN-only reference and FC-less item.
	domain, item = ObjectReference("ld/LLN0").ToMMS(FCNone)
	if item != "LLN0" {
		t.Fatalf("LN-only item %q", item)
	}
	back, fc = FromMMS("ld", "LLN0$DC$NamPlt")
	if back != "ld/LLN0.NamPlt" || fc != DC {
		t.Fatalf("FromMMS: %q %v", back, fc)
	}

	for _, bad := range []string{"", "noslash", "ld/", "/x", "ld/a..b"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestFC(t *testing.T) {
	fc, err := ParseFC("mx")
	if err != nil || fc != MX {
		t.Fatalf("ParseFC: %v %v", fc, err)
	}
	if _, err := ParseFC("XX"); err == nil {
		t.Fatal("XX should fail")
	}
	if ST.String() != "ST" {
		t.Fatal("FC string")
	}
}

func TestQuality(t *testing.T) {
	q := QualityGood.WithValidity(ValidityQuestionable) | QualityOldData | QualityTest
	v := q.Value()
	if v.BitLen() != 13 {
		t.Fatalf("BitLen=%d", v.BitLen())
	}
	back := QualityFromValue(v)
	if back != q {
		t.Fatalf("round trip: %v != %v", back, q)
	}
	if back.Validity() != ValidityQuestionable || !back.Is(QualityOldData) {
		t.Fatalf("flags lost: %s", back)
	}
	if QualityFromValue(mms.NewBitString(13)) != QualityGood {
		t.Fatal("zero quality must be good")
	}
}

func TestDbpos(t *testing.T) {
	for _, d := range []Dbpos{DbposIntermediate, DbposOff, DbposOn, DbposBad} {
		if got := DbposFromValue(d.Value()); got != d {
			t.Errorf("%v round trip -> %v", d, got)
		}
	}
	// stVal "on" is bits 10: first bit set, second clear.
	v := DbposOn.Value()
	if !v.Bit(0) || v.Bit(1) {
		t.Fatalf("DbposOn wire bits wrong: %s", v)
	}
}

func TestTrgOpsOptFlds(t *testing.T) {
	tr := TrgDataChange | TrgGI
	if got := TrgOpsFromValue(tr.Value()); got != tr {
		t.Fatalf("TrgOps round trip: %v", got)
	}
	of := OptFldsDefault | OptEntryID
	if got := OptFldsFromValue(of.Value()); got != of {
		t.Fatalf("OptFlds round trip: %v", got)
	}
}

func testModel() *Model {
	q := &DataAttribute{Name: "q", FC: MX, Kind: mms.TypeBitString, Value: QualityGood.Value()}
	f := &DataAttribute{Name: "f", FC: MX, Kind: mms.TypeFloat32, Value: mms.NewFloat32(1.5)}
	mag := &DataAttribute{Name: "mag", FC: MX, Kind: mms.TypeStructure, Children: []*DataAttribute{f}}
	anIn1 := &DataObject{Name: "AnIn1", CDC: "MV", Attributes: []*DataAttribute{mag, q}}
	ggio := &LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*DataObject{anIn1}}
	lln0 := &LogicalNode{Name: "LLN0", Class: "LLN0"}
	ld := &LogicalDevice{Name: "ied1LD0", Inst: "LD0", Nodes: []*LogicalNode{lln0, ggio}}
	return &Model{Name: "ied1", Devices: []*LogicalDevice{ld}}
}

func TestModelLookup(t *testing.T) {
	m := testModel()
	da := m.Attribute("ied1LD0/GGIO1.AnIn1.mag.f", MX)
	if da == nil || da.Kind != mms.TypeFloat32 {
		t.Fatalf("lookup failed: %+v", da)
	}
	if m.Attribute("ied1LD0/GGIO1.AnIn1.mag.f", ST) != nil {
		t.Fatal("wrong FC must not resolve")
	}
	if m.Attribute("ied1LD0/GGIO1.AnIn1.mag.f", ALL) == nil {
		t.Fatal("ALL must resolve")
	}
	if do, ok := m.Lookup("ied1LD0/GGIO1.AnIn1", ALL).(*DataObject); !ok || do.CDC != "MV" {
		t.Fatalf("DO lookup: %#v", m.Lookup("ied1LD0/GGIO1.AnIn1", ALL))
	}
	if _, ok := m.Lookup("ied1LD0/GGIO1", ALL).(*LogicalNode); !ok {
		t.Fatal("LN lookup failed")
	}
	if m.Lookup("nope/GGIO1", ALL) != nil {
		t.Fatal("unknown LD must be nil")
	}

	fcs := m.Device("ied1LD0").Node("GGIO1").Object("AnIn1").FCs()
	if len(fcs) != 1 || fcs[0] != MX {
		t.Fatalf("FCs=%v", fcs)
	}
}

func TestCtlModel(t *testing.T) {
	if !CtlSBOEnhanced.HasSelect() || !CtlSBOEnhanced.Enhanced() {
		t.Fatal("sbo-enhanced flags")
	}
	if CtlDirectNormal.HasSelect() || CtlDirectNormal.Enhanced() {
		t.Fatal("direct-normal flags")
	}
}
