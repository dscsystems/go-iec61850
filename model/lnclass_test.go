package model

import (
	"strings"
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
)

func objectNames(ln *LogicalNode) []string {
	var out []string
	for _, do := range ln.Objects {
		out = append(out, do.Name)
	}
	return out
}

// Every class table names each data object once, and only classes this
// package can build.
func TestLNClassTablesWellFormed(t *testing.T) {
	for _, class := range KnownLNClasses() {
		seen := map[string]bool{}
		for _, o := range LNClassObjects(class) {
			if seen[o.Name] {
				t.Errorf("%s.%s listed twice", class, o.Name)
			}
			seen[o.Name] = true
			if !KnownCDC(string(o.CDC)) {
				t.Errorf("%s.%s: class %s has no template", class, o.Name, o.CDC)
			}
		}
		// A node built from the class alone passes its own check.
		if d := CheckLogicalNode(NewLogicalNode("", class, "1")); len(d) != 0 {
			t.Errorf("%s built from its template fails the check: %v", class, d)
		}
	}
}

func TestNewLogicalNodeMandatory(t *testing.T) {
	lln0 := NewLogicalNode("X", "LLN0", "7")
	if lln0.Name != "LLN0" || lln0.Class != "LLN0" {
		t.Errorf("LLN0 named %q class %q", lln0.Name, lln0.Class)
	}
	if got := strings.Join(objectNames(lln0), ","); got != "Mod,Beh,Health,NamPlt" {
		t.Errorf("LLN0 objects = %s, want Mod,Beh,Health,NamPlt", got)
	}
	xcbr := NewLogicalNode("Q0", "xcbr", "1")
	if xcbr.Name != "Q0XCBR1" {
		t.Errorf("XCBR named %q, want Q0XCBR1", xcbr.Name)
	}
	if got := strings.Join(objectNames(xcbr), ","); got != "Beh,Loc,OpCnt,Pos,BlkOpn,BlkCls" {
		t.Errorf("XCBR objects = %s", got)
	}
	if pos := xcbr.Object("Pos"); pos.CDC != "DPC" || pos.Attribute("stVal") == nil {
		t.Errorf("XCBR.Pos = %s with %v", pos.CDC, attrNames(pos))
	}
	// A class with no template is the empty named node.
	if ln := NewLogicalNode("", "ZZZZ", "1"); ln.Name != "ZZZZ1" || len(ln.Objects) != 0 || KnownLNClass("ZZZZ") {
		t.Errorf("unknown class built %+v", ln)
	}
}

func TestNewLogicalNodeOptionalAndMulti(t *testing.T) {
	ggio := NewLogicalNode("", "GGIO", "1",
		WithObjects("SPCSO1", "SPCSO3", "Ind", "AnIn2", "NoSuchDO", "Ind0"),
		WithObjectOptions("SPCSO", WithControlModel(CtlDirectNormal)),
		WithObjectOptions("SPCSO3", WithControlModel(CtlSBOEnhanced)),
	)
	if got := strings.Join(objectNames(ggio), ","); got != "Beh,AnIn2,Ind1,SPCSO1,SPCSO3" {
		t.Errorf("GGIO objects = %s", got)
	}
	// Options for every instance apply, and an instance's own win.
	if ggio.Object("SPCSO1").Attribute("Oper") == nil || ggio.Object("SPCSO1").Attribute("SBOw") != nil {
		t.Errorf("SPCSO1 = %v, want direct control", attrNames(ggio.Object("SPCSO1")))
	}
	if ggio.Object("SPCSO3").Attribute("SBOw") == nil {
		t.Errorf("SPCSO3 = %v, want SBO with enhanced security", attrNames(ggio.Object("SPCSO3")))
	}
	if ggio.Object("AnIn2").CDC != "MV" {
		t.Errorf("AnIn2 class %s, want MV", ggio.Object("AnIn2").CDC)
	}
}

// The control tracking objects of LTRK carry the ctlVal of the control
// they track.
func TestNewLogicalNodeTracking(t *testing.T) {
	ltrk := NewLogicalNode("", "LTRK", "1", WithObjects("SpcTrk", "BscTrk", "ApcIntTrk", "GocbTrk"))
	for _, tc := range []struct {
		do   string
		kind mms.Type
	}{{"SpcTrk", mms.TypeBoolean}, {"BscTrk", mms.TypeBitString}, {"ApcIntTrk", mms.TypeStructure}} {
		c := ltrk.Object(tc.do).Attribute("ctlVal")
		if c == nil || c.Kind != tc.kind || c.FC != SR {
			t.Errorf("%s.ctlVal = %+v, want %v [SR]", tc.do, c, tc.kind)
		}
	}
	if c := ltrk.Object("ApcIntTrk").Attribute("ctlVal"); len(c.Children) != 1 || c.Children[0].Name != "i" {
		t.Errorf("ApcIntTrk.ctlVal members = %+v, want i", c.Children)
	}
	if ltrk.Object("GocbTrk").CDC != "GTS" {
		t.Errorf("GocbTrk class %s, want GTS", ltrk.Object("GocbTrk").CDC)
	}
}

func TestCheckLogicalNode(t *testing.T) {
	xcbr := NewLogicalNode("Q0", "XCBR", "1")
	// Take Pos away, make BlkOpn a status, and add a vendor object.
	var kept []*DataObject
	for _, do := range xcbr.Objects {
		if do.Name != "Pos" {
			kept = append(kept, do)
		}
	}
	xcbr.Objects = append(kept, &DataObject{Name: "VendorX", CDC: "SPS"})
	xcbr.Object("BlkOpn").CDC = "SPS"
	d := CheckLogicalNode(xcbr)
	if len(d) != 2 {
		t.Fatalf("diagnostics = %v, want Pos missing and BlkOpn of the wrong class", d)
	}
	if !strings.Contains(d[0].String(), "BlkOpn") || !strings.Contains(d[0].Message, "SPC") {
		t.Errorf("first diagnostic = %s, want BlkOpn's class", d[0])
	}
	if d[0].Path != "Q0XCBR1.BlkOpn" || d[1].Path != "Q0XCBR1" || !strings.Contains(d[1].Message, "Pos") {
		t.Errorf("diagnostics = %v", d)
	}

	// Edition 1 integer classes stand for the Edition 2 enumerated ones.
	ed1 := &LogicalNode{Name: "LLN0", Class: "LLN0", Objects: []*DataObject{
		{Name: "Mod", CDC: "INC"}, {Name: "Beh", CDC: "INS"},
		{Name: "Health", CDC: "INS"}, {Name: "NamPlt", CDC: "LPL"},
	}}
	if d := CheckLogicalNode(ed1); len(d) != 0 {
		t.Errorf("an Edition 1 LLN0 was reported: %v", d)
	}
	// ...but not the other way round, nor for a class with no integer form.
	wrong := &LogicalNode{Name: "LLN0", Class: "LLN0", Objects: []*DataObject{
		{Name: "Mod", CDC: "ENC"}, {Name: "Beh", CDC: "ENS"},
		{Name: "Health", CDC: "SPS"}, {Name: "NamPlt", CDC: "DPL"},
	}}
	if d := CheckLogicalNode(wrong); len(d) != 2 {
		t.Errorf("wrong LLN0 diagnostics = %v, want Health and NamPlt", d)
	}

	// Multi-instance objects are matched by instance name.
	ggio := &LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*DataObject{
		{Name: "Beh", CDC: "ENS"}, {Name: "Ind12", CDC: "SPS"}, {Name: "AnIn1", CDC: "WYE"},
		{Name: "Ind0", CDC: "WYE"}, {Name: "Indx", CDC: "WYE"},
	}}
	d = CheckLogicalNode(ggio)
	if len(d) != 1 || d[0].Path != "GGIO1.AnIn1" {
		t.Errorf("GGIO diagnostics = %v, want AnIn1 only", d)
	}

	// No class, or an unknown one: nothing to check against.
	if d := CheckLogicalNode(&LogicalNode{Name: "XCBR1"}); d != nil {
		t.Errorf("a node with no class was checked: %v", d)
	}
}

func TestModelCheckLNClasses(t *testing.T) {
	m := &Model{Devices: []*LogicalDevice{{Name: "IEDLD0", Nodes: []*LogicalNode{
		NewLogicalNode("", "LLN0", ""),
		{Name: "MMXU1", Class: "MMXU"},
	}}}}
	d := m.CheckLNClasses()
	if len(d) != 1 || d[0].Path != "IEDLD0/MMXU1" || !strings.Contains(d[0].Message, "Beh") {
		t.Errorf("diagnostics = %v, want MMXU1 missing Beh", d)
	}
	if len(m.Diagnostics) != 0 {
		t.Error("the check added to the model's diagnostics")
	}
}
