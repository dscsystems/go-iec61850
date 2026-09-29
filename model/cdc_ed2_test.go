package model

import (
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
)

// The classes Edition 2 added that the library used to lack: each builds
// its 7-3 attribute set, and the options that shape it work.

func TestHistogramArrays(t *testing.T) {
	hst := NewDataObject("Hst", CDCHST, WithMaxPts(4))
	hv := findAttr(t, hst, "hstVal")
	if hv.Kind != mms.TypeArray || hv.Count != 4 || hv.Value == nil || hv.Value.Len() != 4 {
		t.Errorf("hstVal = %s of %d, want an array of 4", hv.Kind, hv.Count)
	}
	if hv.TrgOps != TrgDataChange|TrgDataUpdate {
		t.Errorf("hstVal TrgOps = %v, want dchg|dupd", hv.TrgOps)
	}
	rc := findAttr(t, hst, "hstRangeC")
	if rc.Kind != mms.TypeArray || rc.Count != 4 || rc.Value != nil || rc.Child("xStart") == nil {
		t.Errorf("hstRangeC = %s of %d with %d members, want an array of 4 Cells",
			rc.Kind, rc.Count, len(rc.Children))
	}
	if mp := findAttr(t, hst, "maxPts"); mp.Value.Uint64() != 4 {
		t.Errorf("maxPts = %v, want 4", mp.Value)
	}
	for _, name := range []string{"numPts", "xUnits", "xD", "q", "t"} {
		findAttr(t, hst, name)
	}
	// Without WithMaxPts the arrays have one element.
	if hv := findAttr(t, NewDataObject("Hst", CDCHST), "hstVal"); hv.Count != 1 {
		t.Errorf("default hstVal count = %d, want 1", hv.Count)
	}
}

func TestBinaryControlledAnalogue(t *testing.T) {
	bac := NewDataObject("ColChg", CDCBAC, WithControlModel(CtlDirectNormal))
	if mx := findAttr(t, bac, "mxVal"); mx.FC != MX || len(mx.Children) != 1 || mx.Children[0].Name != "f" {
		t.Errorf("mxVal = [%s] %+v, want an AnalogueValue [MX]", mx.FC, mx.Children)
	}
	if p := findAttr(t, bac, "persistent"); p.FC != CF || p.Kind != mms.TypeBoolean {
		t.Errorf("persistent = %s [%s], want boolean [CF]", p.Kind, p.FC)
	}
	ctlVal := findAttr(t, bac, "Oper").Child("ctlVal")
	if ctlVal == nil || ctlVal.Kind != mms.TypeBitString || ctlVal.Value.BitLen() != 2 {
		t.Errorf("Oper.ctlVal = %+v, want a 2-bit Tcmd", ctlVal)
	}
	if hasAttr(bac, "opRcvd") {
		t.Error("BAC built opRcvd unasked")
	}
	// The substituted value is an AnalogueValue, like mxVal.
	sub := NewDataObject("ColChg", CDCBAC, WithOptional("subVal"))
	if sv := findAttr(t, sub, "subVal"); sv.FC != SV || sv.Kind != mms.TypeStructure {
		t.Errorf("subVal = %s [%s], want a structure [SV]", sv.Kind, sv.FC)
	}
}

func TestIntegerControlledStep(t *testing.T) {
	isc := NewDataObject("TapChg", CDCISC, WithControlModel(CtlSBOEnhanced))
	v := findAttr(t, isc, "valWTr")
	if v.Child("posVal") == nil || v.Child("transInd") == nil {
		t.Errorf("valWTr members = %+v, want posVal and transInd", v.Children)
	}
	if c := findAttr(t, isc, "SBOw").Child("ctlVal"); c == nil || c.Kind != mms.TypeInteger {
		t.Errorf("SBOw.ctlVal = %+v, want an integer", c)
	}
}

func TestObjectReferenceSetting(t *testing.T) {
	org := NewDataObject("InRef1", CDCORG)
	if a := findAttr(t, org, "setSrcRef"); a.FC != SP || a.Kind != mms.TypeVisibleString {
		t.Errorf("setSrcRef = %s [%s], want a visible string [SP]", a.Kind, a.FC)
	}
	if hasAttr(org, "setTstRef") || hasAttr(org, "tstEna") {
		t.Errorf("ORG built the test group unasked: %v", attrNames(org))
	}
	// setTstRef and tstEna come together (7-3 AllOrNonePerGroup).
	withTest := NewDataObject("InRef1", CDCORG, WithOptional("tstEna"))
	if !hasAttr(withTest, "setTstRef") || !hasAttr(withTest, "tstEna") {
		t.Errorf("asking for tstEna built %v, want setTstRef too", attrNames(withTest))
	}
	// Asking for one member does not leak into a sibling object built with
	// the same options.
	o1 := WithOptional("setTstRef")
	NewDataObject("A", CDCORG, o1)
	if other := NewDataObject("B", CDCSPS, o1); hasAttr(other, "tstEna") {
		t.Error("the group resolution changed the shared option set")
	}
}

func TestTimeSettingOneOf(t *testing.T) {
	tsg := NewDataObject("StrTm", CDCTSG)
	if !hasAttr(tsg, "setTm") || hasAttr(tsg, "setCal") {
		t.Errorf("TSG = %v, want setTm alone by default", attrNames(tsg))
	}
	cal := NewDataObject("StrTm", CDCTSG, WithOptional("setCal"))
	if hasAttr(cal, "setTm") {
		t.Errorf("TSG with setCal = %v, want setTm left out", attrNames(cal))
	}
	sc := findAttr(t, cal, "setCal")
	for _, m := range []string{"occ", "occType", "occPer", "weekDay", "month", "day", "hr", "mn"} {
		if sc.Child(m) == nil {
			t.Errorf("setCal has no %s", m)
		}
	}
	both := NewDataObject("StrTm", CDCTSG, WithOptional("setTm", "setCal"))
	if !hasAttr(both, "setTm") || !hasAttr(both, "setCal") {
		t.Errorf("TSG with both asked = %v", attrNames(both))
	}
}

func TestStringAndCurrencySettings(t *testing.T) {
	cug := NewDataObject("Cur", CDCCUG, WithSettingFC(SG))
	if a := findAttr(t, cug, "cur"); a.FC != SG || a.Kind != mms.TypeVisibleString {
		t.Errorf("CUG cur = %s [%s], want a visible string [SG]", a.Kind, a.FC)
	}
	vsg := NewDataObject("Txt", CDCVSG)
	if a := findAttr(t, vsg, "setVal"); a.FC != SP || a.Kind != mms.TypeVisibleString {
		t.Errorf("VSG setVal = %s [%s], want a visible string [SP]", a.Kind, a.FC)
	}
}

func TestCurveShapeSetting(t *testing.T) {
	csg := NewDataObject("Crv", CDCCSG, WithMaxPts(10), WithSettingFC(SG))
	pts := findAttr(t, csg, "crvPts")
	if pts.Kind != mms.TypeArray || pts.Count != 10 || pts.FC != SG {
		t.Errorf("crvPts = %s of %d [%s], want an array of 10 [SG]", pts.Kind, pts.Count, pts.FC)
	}
	if pts.Child("xVal") == nil || pts.Child("yVal") == nil || pts.Child("zVal") != nil {
		t.Errorf("crvPts element = %+v, want xVal and yVal", pts.Children)
	}
	if a := findAttr(t, csg, "numPts"); a.FC != SG {
		t.Errorf("numPts [%s], want [SG]", a.FC)
	}
	for _, name := range []string{"xUnits", "yUnits", "maxPts"} {
		if a := findAttr(t, csg, name); a.FC != CF {
			t.Errorf("%s [%s], want [CF]", name, a.FC)
		}
	}
}

func TestHarmonicSubObjectArrays(t *testing.T) {
	hmv := NewDataObject("Har", CDCHMV, WithMaxPts(3))
	if len(hmv.Objects) != 3 {
		t.Fatalf("HMV has %d harmonics, want 3", len(hmv.Objects))
	}
	for i, want := range []string{"har(1)", "har(2)", "har(3)"} {
		if hmv.Objects[i].Name != want || hmv.Objects[i].CDC != "CMV" {
			t.Errorf("harmonic %d = %s (%s), want %s (CMV)", i, hmv.Objects[i].Name, hmv.Objects[i].CDC, want)
		}
	}
	hwye := NewDataObject("HA", CDCHWYE, WithMaxPts(2), WithOptional("phsBHar"))
	if len(hwye.Objects) != 4 {
		t.Errorf("HWYE with phsBHar has %d objects, want 4", len(hwye.Objects))
	}
}

func TestServiceTracking(t *testing.T) {
	cts := NewDataObject("SpcTrk", CDCCTS)
	if c := findAttr(t, cts, "ctlVal"); c.Kind != mms.TypeBoolean || c.FC != SR {
		t.Errorf("CTS ctlVal = %s [%s], want boolean [SR]", c.Kind, c.FC)
	}
	if o := findAttr(t, cts, "objRef"); o.TrgOps != TrgDataUpdate {
		t.Errorf("objRef TrgOps = %v, want dupd", o.TrgOps)
	}
	apc := NewDataObject("ApcTrk", CDCCTS, WithTrackedControl(CDCAPC))
	c := findAttr(t, apc, "ctlVal")
	if c.Kind != mms.TypeStructure || c.FC != SR || len(c.Children) != 1 || c.Children[0].FC != SR {
		t.Errorf("CTS ctlVal tracking APC = %s [%s] %+v, want an AnalogueValue [SR]", c.Kind, c.FC, c.Children)
	}
	gts := NewDataObject("GocbTrk", CDCGTS)
	dst := findAttr(t, gts, "dstAddress")
	for _, m := range []string{"Addr", "PRIORITY", "VID", "APPID"} {
		if dst.Child(m) == nil {
			t.Errorf("dstAddress has no %s", m)
		}
	}
	if ParseFCLenient("sr") != SR || SR.String() != "SR" {
		t.Error("SR does not round-trip through its mnemonic")
	}
	if NewDataObject("X", CDCNTS, WithOptional("certIssuer")).Attribute("certIssuer") != nil {
		t.Error("NTS has no certIssuer in 7-2")
	}
}

// Every Edition 2 class the library once lacked is in the table now.
func TestEdition2ClassesKnown(t *testing.T) {
	for _, cdc := range []CDC{CDCHST, CDCBAC, CDCORG, CDCTSG, CDCCUG, CDCVSG, CDCCSG,
		CDCSEQ, CDCHMV, CDCHWYE, CDCHDEL, CDCISC, CDCCURVE, CDCCSD, CDCVSD, CDCORS, CDCTCS,
		CDCCST, CDCBTS, CDCUTS, CDCLTS, CDCGTS, CDCMTS, CDCNTS, CDCSTS, CDCCTS} {
		if !KnownCDC(string(cdc)) {
			t.Errorf("%s has no template", cdc)
		}
	}
}

// A value in a setting group triggers nothing (the SG and SE variants of
// the 7-3 setting classes have no trigger options), whether its SP form's
// options are derived from its name or set by the table; the SP form and
// the configuration attributes keep theirs.
func TestSettingGroupValuesTriggerNothing(t *testing.T) {
	for _, fc := range []FC{SG, SE} {
		asg := NewDataObject("StrVal", CDCASG, WithSettingFC(fc), WithOptional("units"))
		mag := findAttr(t, asg, "setMag")
		if mag.TrgOps != 0 {
			t.Errorf("ASG setMag [%s] TrgOps = %v, want none", fc, mag.TrgOps)
		}
		for _, c := range mag.Children {
			if c.TrgOps != 0 {
				t.Errorf("ASG setMag.%s [%s] TrgOps = %v, want none", c.Name, fc, c.TrgOps)
			}
		}
		if u := findAttr(t, asg, "units"); u.TrgOps != TrgDataChange {
			t.Errorf("ASG units [CF] TrgOps = %v, want dchg", u.TrgOps)
		}
		csg := NewDataObject("Crv", CDCCSG, WithSettingFC(fc))
		for _, name := range []string{"crvPts", "numPts"} {
			if a := findAttr(t, csg, name); a.TrgOps != 0 {
				t.Errorf("CSG %s [%s] TrgOps = %v, want none", name, fc, a.TrgOps)
			}
		}
	}
	if mag := findAttr(t, NewDataObject("StrVal", CDCASG), "setMag"); mag.TrgOps != TrgDataChange {
		t.Errorf("ASG setMag [SP] TrgOps = %v, want dchg", mag.TrgOps)
	}
	// An attribute whose table sets its options keeps them outside a group.
	if v := findAttr(t, NewDataObject("X", CDCINS), "stVal"); v.TrgOps != TrgDataChange|TrgDataUpdate {
		t.Errorf("INS stVal TrgOps = %v, want dchg|dupd", v.TrgOps)
	}
}
