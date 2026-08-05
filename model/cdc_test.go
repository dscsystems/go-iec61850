package model

import (
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
)

func attrNames(do *DataObject) []string {
	var out []string
	for _, a := range do.Attributes {
		out = append(out, a.Name)
	}
	return out
}

func findAttr(t *testing.T, do *DataObject, name string) *DataAttribute {
	t.Helper()
	for _, a := range do.Attributes {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("%s has no attribute %q (has %v)", do.Name, name, attrNames(do))
	return nil
}

func hasAttr(do *DataObject, name string) bool {
	for _, a := range do.Attributes {
		if a.Name == name {
			return true
		}
	}
	return false
}

// A status class is its value, quality and timestamp, and nothing else
// until optional attributes are asked for.
func TestNewDataObjectStatusClasses(t *testing.T) {
	sps := NewDataObject("Ind1", CDCSPS)
	if got := attrNames(sps); len(got) != 3 {
		t.Fatalf("SPS attributes = %v, want stVal, q, t", got)
	}
	if sps.CDC != "SPS" {
		t.Errorf("CDC = %q, want SPS", sps.CDC)
	}
	stVal := findAttr(t, sps, "stVal")
	if stVal.Kind != mms.TypeBoolean || stVal.FC != ST {
		t.Errorf("SPS stVal = %s [%s], want boolean [ST]", stVal.Kind, stVal.FC)
	}
	if stVal.Value == nil || stVal.Value.Bool() {
		t.Errorf("SPS stVal value = %v, want a zero boolean", stVal.Value)
	}
	q := findAttr(t, sps, "q")
	if q.Kind != mms.TypeBitString || q.Value.BitLen() != 13 {
		t.Errorf("SPS q = %s of %d bits, want a 13-bit string", q.Kind, q.Value.BitLen())
	}
	if tm := findAttr(t, sps, "t"); tm.Kind != mms.TypeUTCTime {
		t.Errorf("SPS t = %s, want UTC time", tm.Kind)
	}

	// A double point's value is the 2-bit Dbpos.
	dps := NewDataObject("Pos", CDCDPS)
	if v := findAttr(t, dps, "stVal"); v.Kind != mms.TypeBitString || v.Value.BitLen() != 2 {
		t.Errorf("DPS stVal = %s of %d bits, want a 2-bit string", v.Kind, v.Value.BitLen())
	}

	// Optional attributes appear only when named.
	if hasAttr(sps, "subVal") || hasAttr(sps, "d") {
		t.Errorf("SPS built optional attributes unasked: %v", attrNames(sps))
	}
	subbed := NewDataObject("Ind1", CDCSPS, WithOptional("subEna", "subVal", "subQ", "d"))
	for _, name := range []string{"stVal", "q", "t", "subEna", "subVal", "subQ", "d"} {
		if !hasAttr(subbed, name) {
			t.Errorf("SPS with substitution lacks %q: %v", name, attrNames(subbed))
		}
	}
	if sub := findAttr(t, subbed, "subVal"); sub.FC != SV || sub.Kind != mms.TypeBoolean {
		t.Errorf("subVal = %s [%s], want boolean [SV]", sub.Kind, sub.FC)
	}
	if sq := findAttr(t, subbed, "subQ"); sq.FC != SV || sq.Value.BitLen() != 13 {
		t.Errorf("subQ = [%s] of %d bits, want [SV] of 13", sq.FC, sq.Value.BitLen())
	}
	// The description is served under DC, not under the status FC.
	if d := findAttr(t, subbed, "d"); d.FC != DC {
		t.Errorf("d [%s], want [DC]", d.FC)
	}
}

// An AnalogueValue carries one of i or f, chosen at build time.
func TestNewDataObjectAnalogue(t *testing.T) {
	mv := NewDataObject("AnIn1", CDCMV)
	mag := findAttr(t, mv, "mag")
	if mag.Kind != mms.TypeStructure || mag.FC != MX {
		t.Fatalf("MV mag = %s [%s], want a structure [MX]", mag.Kind, mag.FC)
	}
	if len(mag.Children) != 1 || mag.Children[0].Name != "f" {
		t.Fatalf("MV mag members = %+v, want just f", mag.Children)
	}
	if mag.Children[0].Kind != mms.TypeFloat32 || mag.Children[0].FC != MX {
		t.Errorf("mag.f = %s [%s], want float32 [MX]", mag.Children[0].Kind, mag.Children[0].FC)
	}

	imv := NewDataObject("AnIn1", CDCMV, WithIntegerAnalogue())
	imag := findAttr(t, imv, "mag")
	if len(imag.Children) != 1 || imag.Children[0].Name != "i" {
		t.Fatalf("integer MV mag members = %+v, want just i", imag.Children)
	}
	if imag.Children[0].Kind != mms.TypeInteger {
		t.Errorf("mag.i = %s, want integer", imag.Children[0].Kind)
	}

	// Units is a structure under CF, and optional.
	full := NewDataObject("AnIn1", CDCMV, WithOptional("units", "db", "instMag"))
	units := findAttr(t, full, "units")
	if units.FC != CF || len(units.Children) != 2 {
		t.Errorf("units = [%s] with %d members, want [CF] with SIUnit and multiplier",
			units.FC, len(units.Children))
	}
	if !hasAttr(full, "instMag") || !hasAttr(full, "db") {
		t.Errorf("optional MV attributes missing: %v", attrNames(full))
	}
}

// A complex measurand nests an AnalogueValue inside its Vector.
func TestNewDataObjectComplexMeasurand(t *testing.T) {
	cmv := NewDataObject("A", CDCCMV, WithOptional("ang"))
	cVal := findAttr(t, cmv, "cVal")
	if len(cVal.Children) != 2 {
		t.Fatalf("cVal members = %d, want mag and ang", len(cVal.Children))
	}
	for _, child := range cVal.Children {
		if child.Kind != mms.TypeStructure || len(child.Children) != 1 {
			t.Errorf("cVal.%s = %s with %d members, want an AnalogueValue",
				child.Name, child.Kind, len(child.Children))
		}
		if child.FC != MX {
			t.Errorf("cVal.%s [%s], want [MX]", child.Name, child.FC)
		}
	}
	// Without the option the vector is magnitude only.
	if plain := NewDataObject("A", CDCCMV); len(findAttr(t, plain, "cVal").Children) != 1 {
		t.Error("cVal carried ang without being asked")
	}
}

// The phase measurands of a WYE are nested data objects, not attributes.
func TestNewDataObjectNestedObjects(t *testing.T) {
	wye := NewDataObject("PhV", CDCWYE)
	if len(wye.Objects) != 3 {
		t.Fatalf("WYE sub-objects = %d, want phsA, phsB, phsC", len(wye.Objects))
	}
	for i, name := range []string{"phsA", "phsB", "phsC"} {
		sub := wye.Objects[i]
		if sub.Name != name || sub.CDC != "CMV" {
			t.Errorf("sub-object %d = %s (%s), want %s (CMV)", i, sub.Name, sub.CDC, name)
		}
		if !hasAttr(sub, "cVal") {
			t.Errorf("%s has no cVal", sub.Name)
		}
	}
	withNeut := NewDataObject("PhV", CDCWYE, WithOptional("neut"))
	if len(withNeut.Objects) != 4 || withNeut.Objects[3].Name != "neut" {
		t.Errorf("optional neutral missing: %d sub-objects", len(withNeut.Objects))
	}

	del := NewDataObject("PPV", CDCDEL)
	if len(del.Objects) != 3 || del.Objects[0].Name != "phsAB" {
		t.Errorf("DEL sub-objects = %d, first %q", len(del.Objects), del.Objects[0].Name)
	}
}

// A controllable class is status-only until a control model asks for the
// control attributes, and then carries the ones that model needs.
func TestNewDataObjectControlModels(t *testing.T) {
	statusOnly := NewDataObject("SPCSO1", CDCSPC)
	for _, name := range []string{"Oper", "SBOw", "SBO", "Cancel", "ctlModel"} {
		if hasAttr(statusOnly, name) {
			t.Errorf("a control object built without a model has %q", name)
		}
	}

	for _, tc := range []struct {
		model  CtlModel
		want   []string
		absent []string
	}{
		{CtlStatusOnly, []string{"ctlModel"}, []string{"Oper", "SBO", "SBOw", "Cancel"}},
		{CtlDirectNormal, []string{"ctlModel", "Oper", "Cancel"}, []string{"SBO", "SBOw"}},
		{CtlSBONormal, []string{"ctlModel", "SBO", "Oper", "Cancel"}, []string{"SBOw"}},
		{CtlDirectEnhanced, []string{"ctlModel", "Oper", "Cancel"}, []string{"SBO", "SBOw"}},
		{CtlSBOEnhanced, []string{"ctlModel", "SBOw", "Oper", "Cancel"}, []string{"SBO"}},
	} {
		do := NewDataObject("SPCSO1", CDCSPC, WithControlModel(tc.model))
		for _, name := range tc.want {
			if !hasAttr(do, name) {
				t.Errorf("%s: missing %q (has %v)", tc.model, name, attrNames(do))
			}
		}
		for _, name := range tc.absent {
			if hasAttr(do, name) {
				t.Errorf("%s: unexpected %q", tc.model, name)
			}
		}
		if cm := findAttr(t, do, "ctlModel"); cm.FC != CF || CtlModel(cm.Value.Int64()) != tc.model {
			t.Errorf("%s: ctlModel = %v [%s]", tc.model, cm.Value, cm.FC)
		}
	}

	// The operate structure is the one IEC 61850-7-3 defines.
	spc := NewDataObject("SPCSO1", CDCSPC, WithControlModel(CtlSBOEnhanced))
	oper := findAttr(t, spc, "Oper")
	if oper.FC != CO || oper.Kind != mms.TypeStructure {
		t.Fatalf("Oper = %s [%s], want a structure [CO]", oper.Kind, oper.FC)
	}
	var members []string
	for _, m := range oper.Children {
		members = append(members, m.Name)
		if m.FC != CO {
			t.Errorf("Oper.%s [%s], want [CO]", m.Name, m.FC)
		}
	}
	want := []string{"ctlVal", "origin", "ctlNum", "T", "Test", "Check"}
	if len(members) != len(want) {
		t.Fatalf("Oper members = %v, want %v", members, want)
	}
	for i := range want {
		if members[i] != want[i] {
			t.Errorf("Oper member %d = %q, want %q", i, members[i], want[i])
		}
	}
	// Cancel repeats them without the check bits.
	cancel := findAttr(t, spc, "Cancel")
	if len(cancel.Children) != 5 || cancel.Children[4].Name != "Test" {
		t.Errorf("Cancel members = %d, ending %q; want 5 ending Test",
			len(cancel.Children), cancel.Children[len(cancel.Children)-1].Name)
	}
	if origin := oper.Children[1]; len(origin.Children) != 2 ||
		origin.Children[0].Name != "orCat" || origin.Children[1].Name != "orIdent" {
		t.Errorf("origin members = %+v, want orCat and orIdent", origin.Children)
	}
	if ctlNum := oper.Children[2]; ctlNum.Kind != mms.TypeUnsigned {
		t.Errorf("ctlNum = %s, want unsigned", ctlNum.Kind)
	}

	if _, err := NewDataObject("X", CDCSPC, WithControlModel(CtlDirectNormal), WithoutCancel()), error(nil); err != nil {
		t.Fatal(err)
	}
	if noCancel := NewDataObject("X", CDCSPC, WithControlModel(CtlDirectNormal), WithoutCancel()); hasAttr(noCancel, "Cancel") {
		t.Error("WithoutCancel still built Cancel")
	}
}

// The control value type is the one the class controls, not always a
// boolean.
func TestNewDataObjectControlValueTypes(t *testing.T) {
	for _, tc := range []struct {
		cdc  CDC
		kind mms.Type
	}{
		{CDCSPC, mms.TypeBoolean},
		{CDCDPC, mms.TypeBoolean},
		{CDCINC, mms.TypeInteger},
		{CDCENC, mms.TypeInteger},
		{CDCBSC, mms.TypeInteger},
		{CDCAPC, mms.TypeStructure}, // an AnalogueValue
	} {
		do := NewDataObject("C", tc.cdc, WithControlModel(CtlDirectNormal))
		oper := findAttr(t, do, "Oper")
		ctlVal := oper.Children[0]
		if ctlVal.Name != "ctlVal" {
			t.Fatalf("%s: first Oper member = %q", tc.cdc, ctlVal.Name)
		}
		if ctlVal.Kind != tc.kind {
			t.Errorf("%s ctlVal = %s, want %s", tc.cdc, ctlVal.Kind, tc.kind)
		}
		if spec, ok := CDCControlValue(tc.cdc); !ok || spec.Kind != tc.kind {
			t.Errorf("CDCControlValue(%s) = %+v, %v", tc.cdc, spec, ok)
		}
	}
	// A non-controllable class has no control value.
	if _, ok := CDCControlValue(CDCSPS); ok {
		t.Error("SPS reported a control value")
	}
	// An APC's control value is an AnalogueValue like its measurement.
	apc := NewDataObject("AnOut1", CDCAPC, WithControlModel(CtlDirectNormal))
	ctlVal := findAttr(t, apc, "Oper").Children[0]
	if len(ctlVal.Children) != 1 || ctlVal.Children[0].Name != "f" {
		t.Errorf("APC ctlVal members = %+v, want f", ctlVal.Children)
	}
}

func TestNewDataObjectSettings(t *testing.T) {
	spg := NewDataObject("StrVal", CDCSPG)
	if v := findAttr(t, spg, "setVal"); v.FC != SP || v.Kind != mms.TypeBoolean {
		t.Errorf("SPG setVal = %s [%s], want boolean [SP]", v.Kind, v.FC)
	}
	// A setting that belongs to a setting group is served under SG.
	sg := NewDataObject("StrVal", CDCING, WithSettingFC(SG))
	if v := findAttr(t, sg, "setVal"); v.FC != SG {
		t.Errorf("ING setVal [%s], want [SG]", v.FC)
	}
	// Configuration attributes keep their own FC.
	sg = NewDataObject("StrVal", CDCING, WithSettingFC(SG), WithOptional("minVal"))
	if v := findAttr(t, sg, "minVal"); v.FC != CF {
		t.Errorf("ING minVal [%s], want [CF]", v.FC)
	}
	asg := NewDataObject("Setting", CDCASG)
	if v := findAttr(t, asg, "setMag"); v.FC != SP || len(v.Children) != 1 {
		t.Errorf("ASG setMag = [%s] with %d members", v.FC, len(v.Children))
	}
}

func TestNewDataObjectNamePlates(t *testing.T) {
	lpl := NewDataObject("NamPlt", CDCLPL, WithOptional("configRev", "ldNs"))
	for _, name := range []string{"vendor", "swRev", "configRev", "ldNs"} {
		a := findAttr(t, lpl, name)
		if a.Kind != mms.TypeVisibleString {
			t.Errorf("LPL %s = %s, want a visible string", name, a.Kind)
		}
	}
	if ldNs := findAttr(t, lpl, "ldNs"); ldNs.FC != EX {
		t.Errorf("ldNs [%s], want [EX]", ldNs.FC)
	}
	if dpl := NewDataObject("NamPlt", CDCDPL); !hasAttr(dpl, "vendor") {
		t.Error("DPL has no vendor")
	}
}

// The tables are readable from outside, so a caller can see what a class
// holds before building it.
func TestCDCTablesAreQueryable(t *testing.T) {
	attrs := CDCAttributes(CDCMV)
	if len(attrs) == 0 {
		t.Fatal("MV has no attribute table")
	}
	var mandatory []string
	for _, a := range attrs {
		if !a.Optional {
			mandatory = append(mandatory, a.Name)
		}
	}
	if len(mandatory) != 3 {
		t.Errorf("MV mandatory attributes = %v, want mag, q, t", mandatory)
	}
	if CDCAttributes("NOPE") != nil {
		t.Error("an unknown class returned a table")
	}
	if subs := CDCSubObjects(CDCWYE); len(subs) != 6 {
		t.Errorf("WYE sub-objects = %d, want 6 (three mandatory, three optional)", len(subs))
	}
	if CDCSubObjects(CDCSPS) != nil {
		t.Error("SPS reported sub-objects")
	}
	if len(KnownCDCs()) != len(cdcTable) {
		t.Error("KnownCDCs does not cover the table")
	}

	// The returned table is a copy.
	attrs[0].Name = "mutated"
	if CDCAttributes(CDCMV)[0].Name == "mutated" {
		t.Error("CDCAttributes handed out the table itself")
	}
}

func TestNewDataObjectUnknownClassPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("an unknown class did not panic")
		}
	}()
	NewDataObject("X", CDC("NOPE"))
}

// Every class in the table builds, and every leaf it produces has a value
// the server can serve.
func TestEveryCDCBuilds(t *testing.T) {
	var check func(t *testing.T, path string, das []*DataAttribute)
	check = func(t *testing.T, path string, das []*DataAttribute) {
		for _, da := range das {
			p := path + "." + da.Name
			if da.Kind == mms.TypeStructure {
				if len(da.Children) == 0 {
					t.Errorf("%s is an empty structure", p)
				}
				check(t, p, da.Children)
				continue
			}
			if da.Value == nil {
				t.Errorf("%s has no value", p)
			}
			if da.FC == FCNone {
				t.Errorf("%s has no functional constraint", p)
			}
		}
	}
	for _, cdc := range KnownCDCs() {
		var names []string
		for _, a := range CDCAttributes(cdc) {
			names = append(names, a.Name)
		}
		for _, sub := range CDCSubObjects(cdc) {
			names = append(names, sub.Name)
		}
		// Build with every optional attribute asked for, which is the
		// widest tree a class can produce.
		do := NewDataObject("X", cdc, WithControlModel(CtlSBOEnhanced), WithOptional(names...))
		check(t, string(cdc), do.Attributes)
		for _, sub := range do.Objects {
			check(t, string(cdc)+"."+sub.Name, sub.Attributes)
		}
	}
}
