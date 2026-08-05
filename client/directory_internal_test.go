package client

import (
	"slices"
	"testing"
)

// A name list as an IED presents it: the bare node, the FC entries, the
// objects and every leaf below them, plus a neighbouring node.
var sampleNames = []string{
	"LLN0",
	"LLN0$ST",
	"LLN0$ST$Mod",
	"LLN0$ST$Mod$stVal",
	"LLN0$ST$Mod$q",
	"LLN0$CF$Mod$ctlModel",
	"LLN0$SP$SGCB",
	"LLN0$SP$SGCB$NumOfSG",
	"LLN0$SP$SGCB$ActSG",
	"LLN0$SP$StrVal",
	"LLN0$SP$StrVal$setMag",
	"LLN0$RP$urcb01",
	"LLN0$RP$urcb01$RptID",
	"LLN0$RP$urcb02",
	"LLN0$BR$brcb01",
	"LLN0$BR$brcb01$EntryID",
	"LLN0$LG$lcb01",
	"LLN0$GO$gcb01",
	"LLN0$GS$gscb01",
	"LLN0$MS$msvcb01",
	"LLN0$US$usvcb01",
	"GGIO1$ST$Ind1",       // another logical node
	"LLN0$ZZ$Bogus",       // unknown functional constraint
	"LLN0$",               // malformed
	"$ST$Mod",             // malformed
	"LLN0$ST$Mod$stVal$x", // deeper leaf, same object
}

func TestObjectsOfClass(t *testing.T) {
	for _, tc := range []struct {
		class ACSIClass
		want  []string
	}{
		{ACSIDataObject, []string{"Mod", "StrVal"}},
		{ACSIURCB, []string{"urcb01", "urcb02"}},
		{ACSIBRCB, []string{"brcb01"}},
		{ACSILCB, []string{"lcb01"}},
		{ACSIGoCB, []string{"gcb01"}},
		{ACSIGsCB, []string{"gscb01"}},
		{ACSIMSVCB, []string{"msvcb01"}},
		{ACSIUSVCB, []string{"usvcb01"}},
		{ACSISGCB, []string{"SGCB"}},
		// Data sets and logs come from other name lists entirely, so no
		// variable can satisfy them.
		{ACSIDataSet, nil},
		{ACSILog, nil},
	} {
		got := objectsOfClass(sampleNames, "LLN0", tc.class)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s = %v, want %v", tc.class, got, tc.want)
		}
	}
}

// The setting group control block is an SP-constrained variable like any
// set point, told apart only by its name.
func TestSGCBIsNotADataObject(t *testing.T) {
	data := objectsOfClass(sampleNames, "LLN0", ACSIDataObject)
	if slices.Contains(data, "SGCB") {
		t.Errorf("SGCB reported as a data object: %v", data)
	}
	if !slices.Contains(data, "StrVal") {
		t.Errorf("the set point StrVal was dropped with it: %v", data)
	}
}

func TestNamesUnder(t *testing.T) {
	lists := []string{"LLN0$Events", "LLN0$Measurements", "GGIO1$Other", "LLN0", "LLN0$", "$X", "LLN0$Events"}
	got := namesUnder(lists, "LLN0")
	if want := []string{"Events", "Measurements"}; !slices.Equal(got, want) {
		t.Errorf("namesUnder = %v, want %v", got, want)
	}
	if got := namesUnder(lists, "NOSUCH"); len(got) != 0 {
		t.Errorf("namesUnder(unknown LN) = %v, want empty", got)
	}
}

func TestACSIClassString(t *testing.T) {
	if got := ACSIURCB.String(); got != "URCB" {
		t.Errorf("URCB.String() = %q", got)
	}
	if got := ACSIDataObject.String(); got != "DATA" {
		t.Errorf("DATA.String() = %q", got)
	}
	if got := ACSIClass(200).String(); got != "ACSIClass(200)" {
		t.Errorf("unknown class String() = %q", got)
	}
}
