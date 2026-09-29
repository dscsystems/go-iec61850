package scl_test

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
)

func itoa(n int) string               { return strconv.Itoa(n) }
func mmsFloat32(v float32) *mms.Value { return mms.NewFloat32(v) }

// ed21Fixture is a synthetic IEC 61850-6:2009+AMD1 (Edition 2.1, SCL
// 2007B4) CID exercising the constructs an Ed 1 or Ed 2.0 file usually
// does not use. See the comment in the file itself.
const ed21Fixture = "../testdata/ed21_diverse.cid"

func loadEd21(t *testing.T, opts ...scl.Option) (*scl.SCL, *model.Model) {
	t.Helper()
	s, err := scl.ParseFile(ed21Fixture)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	m, err := scl.BuildModel(s, opts...)
	if err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
	return s, m
}

func TestEditionDetection(t *testing.T) {
	s, _ := loadEd21(t)
	e := s.Edition()
	if !e.Known() {
		t.Errorf("Edition %v reported as not known", e)
	}
	if got := e.String(); got != "2007B4" {
		t.Errorf("Edition.String() = %q, want 2007B4", got)
	}
	if !e.AtLeastEd2() || e.IsEd1() {
		t.Errorf("Edition %v: AtLeastEd2=%v IsEd1=%v, want true/false", e, e.AtLeastEd2(), e.IsEd1())
	}
}

// The Ed 1 fixture declares no version at all, which the schema permits.
// It must load as before rather than being reported as an unknown edition.
func TestEditionAbsentIsNotAnError(t *testing.T) {
	s, err := scl.ParseFile("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if e := s.Edition(); e.Version != "" {
		t.Errorf("Edition.Version = %q, want empty", e.Version)
	}
	if _, err := scl.BuildModel(s); err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
}

func TestEditionUnknownIsReported(t *testing.T) {
	const doc = `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2099" revision="Z" release="9">
	  <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0"/></Server></AccessPoint></IED>
	</SCL>`
	s, err := scl.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if s.Edition().Known() {
		t.Error("a version of 2099/Z/9 should not be reported as known")
	}
	_, err = scl.BuildModel(s, scl.Strict(true))
	if err == nil {
		t.Fatal("Strict build should fail on an unknown edition")
	}
	if !strings.Contains(err.Error(), "2099") {
		t.Errorf("error %q should name the version", err)
	}
}

// A vendor namespace is not an error either: elements are matched by local
// name, so the document still parses and the namespace is reported.
func TestVendorNamespaceIsReported(t *testing.T) {
	const doc = `<SCL xmlns="http://example.com/scl" version="2007" revision="B" release="4">
	  <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0"/></Server></AccessPoint></IED>
	</SCL>`
	s, err := scl.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scl.BuildModel(s, scl.Strict(true)); err == nil {
		t.Fatal("Strict build should report a vendor namespace")
	}
}

// An unrecognised element takes its whole subtree with it, so the audit
// reports where it was rather than only its name.
func TestDroppedElementReportsItsPath(t *testing.T) {
	const doc = `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
	  <Communication><SubNetworks name="x"><ConnectedAP iedName="I" apName="A"/></SubNetworks></Communication>
	</SCL>`
	s, err := scl.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	dropped := s.Dropped()
	paths, ok := dropped["SubNetworks"]
	if !ok {
		t.Fatalf("SubNetworks not reported as dropped; got %v", s.DroppedNames())
	}
	if len(paths) == 0 || !strings.Contains(paths[0], "SubNetworks") {
		t.Errorf("dropped path %v should locate the element", paths)
	}
	_, err = scl.BuildModel(s, scl.Strict(true))
	if err == nil {
		t.Fatal("Strict build should report the dropped element")
	}
}

// A known-but-unused element is not reported as unknown, or the audit would
// be noise.
func TestFixtureDropsNothing(t *testing.T) {
	s, _ := loadEd21(t)
	if names := s.DroppedNames(); len(names) != 0 {
		t.Errorf("DroppedNames() = %v, want none", names)
	}
}

// An unknown basic type keeps the attribute in the tree: the object must
// stay browsable and the datasets that name it must still resolve.
func TestUnknownBasicTypeLoads(t *testing.T) {
	_, m := loadEd21(t)
	ggio := m.Device("ED21LD0").Node("GGIO1")
	vendor := ggio.Object("VendorDO")
	if vendor == nil {
		t.Fatal("VendorDO missing from the model")
	}
	stVal := vendor.Attribute("stVal")
	if stVal == nil {
		t.Fatal("VendorDO.stVal missing")
	}
	if stVal.Value != nil {
		t.Errorf("an unknown basic type should have no value, got %v", stVal.Value)
	}
	assertDiagnostic(t, m, `basic type "VendorType7"`)
}

// The two Ed 2.1 option bit strings are real types and must be served.
func TestEd21OptionBitStrings(t *testing.T) {
	_, m := loadEd21(t)
	vendor := m.Device("ED21LD0").Node("GGIO1").Object("VendorDO")
	for _, name := range []string{"opts", "lgOpts"} {
		da := vendor.Attribute(name)
		if da == nil || da.Value == nil {
			t.Fatalf("%s missing or valueless", name)
		}
		if got := da.Value.BitLen(); got != 10 {
			t.Errorf("%s bit length = %d, want 10", name, got)
		}
	}
}

// PhyComAddr is the physical communication address of Ed 2 and is common in
// protection IEDs. It used to fail the whole load, and then loaded as an
// octet string; IEC 61850-8-1 maps it to the structure a GoCB's DstAddress
// is served as.
func TestPhyComAddrLoads(t *testing.T) {
	_, m := loadEd21(t)
	phy := m.Device("ED21LD0").Node("PHC1").Object("PhyCom")
	if phy == nil {
		t.Fatal("PhyCom missing")
	}
	da := phy.Attribute("PhyComAddr")
	if da == nil {
		t.Fatal("PhyComAddr missing")
	}
	if da.Kind != mms.TypeStructure {
		t.Fatalf("PhyComAddr kind = %v, want a structure", da.Kind)
	}
	for _, c := range []struct {
		name string
		kind mms.Type
	}{{"Addr", mms.TypeOctetString}, {"PRIORITY", mms.TypeUnsigned}, {"VID", mms.TypeUnsigned}, {"APPID", mms.TypeUnsigned}} {
		m := da.Child(c.name)
		if m == nil || m.Kind != c.kind || m.Value == nil || m.FC != model.CF {
			t.Errorf("PhyComAddr.%s = %+v, want a valued %v [CF]", c.name, m, c.kind)
		}
	}
	if addr := da.Child("Addr"); addr != nil && len(addr.Value.Bytes()) != 6 {
		t.Errorf("PhyComAddr.Addr is %d octets, want 6", len(addr.Value.Bytes()))
	}
}

// An SDO with a count becomes that many instances, named so that the
// references a dataset spells with array notation resolve.
func TestArraySubObjectInstances(t *testing.T) {
	_, m := loadEd21(t)
	anIn3 := m.Device("ED21LD0").Node("GGIO1").Object("AnIn3")
	if len(anIn3.Objects) != 5 {
		t.Fatalf("AnIn3 has %d sub-objects, want 5", len(anIn3.Objects))
	}
	for i, sub := range anIn3.Objects {
		if want := "phsA(" + itoa(i+1) + ")"; sub.Name != want {
			t.Errorf("sub-object %d named %q, want %q", i, sub.Name, want)
		}
	}
	// The instances must have independent values.
	anIn3.Objects[0].Attribute("mag").Child("f").Value = mmsFloat32(1)
	if got := anIn3.Objects[1].Attribute("mag").Child("f").Value.Float32(); got != 0 {
		t.Errorf("array instances share a value: element 2 is %v, want 0", got)
	}
}

// An unknown functional constraint is carried verbatim, so the object stays
// visible and the item ID uses the mnemonic the document used.
func TestUnknownFunctionalConstraint(t *testing.T) {
	_, m := loadEd21(t)
	ln := m.Device("ED21LD0").Node("GGIO1")
	da := ln.Object("Beh").Attribute("vendorFCAttr")
	if da == nil {
		t.Fatal("an attribute under an unknown FC is missing from the model")
	}
	if da.FC != model.FCUnknown {
		t.Errorf("FC = %v, want FCUnknown", da.FC)
	}
	if got := model.FCText(da.FC, da.FCName); got != "ZX" {
		t.Errorf("FCText = %q, want ZX", got)
	}
	// The node composes the item ID from the verbatim mnemonic.
	if got := ln.Object("Beh").FCText(da.FC); got != "ZX" {
		t.Errorf("DataObject.FCText = %q, want ZX", got)
	}
	assertDiagnostic(t, m, `functional constraint "ZX"`)
}

// FCDA@ix and array notation both name the member of an array.
func TestDataSetArrayMembers(t *testing.T) {
	_, m := loadEd21(t)
	ds := m.Device("ED21LD0").Node("LLN0").DataSet("Measurements")
	if ds == nil {
		t.Fatal("Measurements dataset missing")
	}
	want := []string{
		"ED21LD0/MMXU1.TotW.mag.f",
		"ED21LD0/GGIO1.AnIn3.phsA(2).mag.f",
		"ED21LD0/GGIO1.AnIn1.phsAngRef(2)",
		"ED21LD0/GGIO1.AnIn1.mag.f", // under an FC this library does not know
	}
	if len(ds.Entries) != len(want) {
		t.Fatalf("dataset has %d members, want %d", len(ds.Entries), len(want))
	}
	for i, e := range ds.Entries {
		if got := string(e.Ref); got != want[i] {
			t.Errorf("member %d = %q, want %q", i, got, want[i])
		}
	}
}

// A dataset member under an unknown FC is kept, with its mnemonic.
func TestDataSetUnknownFC(t *testing.T) {
	_, m := loadEd21(t)
	ds := m.Device("ED21LD0").Node("LLN0").DataSet("Measurements")
	last := ds.Entries[len(ds.Entries)-1]
	if last.FC != model.FCUnknown {
		t.Errorf("FC = %v, want FCUnknown", last.FC)
	}
	if got := last.FCText(); got != "ZX" {
		t.Errorf("FCText = %q, want ZX", got)
	}
}

// Val@sGroup gives a distinct value per setting group, and the device
// serves the group its SettingControl declares active.
func TestSettingGroups(t *testing.T) {
	_, m := loadEd21(t)
	if len(m.SettingGroups) != 2 {
		t.Fatalf("%d setting groups, want 2", len(m.SettingGroups))
	}
	g := m.SettingGroups[0]
	if g.Number != 1 || g.LD != "ED21LD0" {
		t.Errorf("group 0 = %+v, want number 1 on ED21LD0", g)
	}
	if got := g.Values["ED21LD0/GGIO1.IntRange.setVal"]; got == nil || got.Float32() != 50.5 {
		t.Errorf("group 1 setVal = %v, want 50.5", got)
	}
	if got := g.Values["ED21LD0/GGIO1.IntRange.setMag.f"]; got == nil || got.Float32() != -1.5 {
		t.Errorf("group 1 setMag.f = %v, want -1.5", got)
	}
	g2 := m.SettingGroups[1]
	if got := g2.Values["ED21LD0/GGIO1.IntRange.setVal"]; got == nil || got.Float32() != 60.5 {
		t.Errorf("group 2 setVal = %v, want 60.5", got)
	}
	// actSG="1", so the object carries group 1's values.
	ir := m.Device("ED21LD0").Node("GGIO1").Object("IntRange")
	if got := ir.Attribute("setVal").Value.Float32(); got != 50.5 {
		t.Errorf("IntRange.setVal = %v, want the active group's 50.5", got)
	}
	if got := ir.Attribute("setMag").Child("f").Value.Float32(); got != -1.5 {
		t.Errorf("IntRange.setMag.f = %v, want the active group's -1.5", got)
	}
}

// A DAI sAddr addresses one element of an array attribute.
func TestDaiSAddr(t *testing.T) {
	_, m := loadEd21(t)
	mag := m.Device("ED21LD0").Node("GGIO1").Object("AnIn1").Attribute("mag")
	arr := mag.Child("phsAngRef")
	if arr == nil || arr.Count != 3 {
		t.Fatalf("phsAngRef = %v, want a 3-element array", arr)
	}
	if got := arr.Elem(0).Float32(); got != 11.5 {
		t.Errorf("phsAngRef[1] = %v, want 11.5", got)
	}
	if got := arr.Elem(1).Float32(); got != 22.5 {
		t.Errorf("phsAngRef[2] = %v, want 22.5", got)
	}
	if got := arr.Elem(2).Float32(); got != 0 {
		t.Errorf("phsAngRef[3] = %v, want the untouched default 0", got)
	}
	if got := mag.Child("f").Value.Float32(); got != 33.5 {
		t.Errorf("mag.f = %v, want 33.5", got)
	}
}

// An SDI ix addresses an element of an array-valued sub-object.
func TestSdiIx(t *testing.T) {
	_, m := loadEd21(t)
	anIn3 := m.Device("ED21LD0").Node("GGIO1").Object("AnIn3")
	if got := anIn3.Objects[2].Attribute("mag").Child("f").Value.Float32(); got != 99.5 {
		t.Errorf("phsA(3).mag.f = %v, want 99.5", got)
	}
	if got := anIn3.Objects[0].Attribute("mag").Child("f").Value.Float32(); got != 0 {
		t.Errorf("phsA(1).mag.f = %v, want 0", got)
	}
}

// SmvOpts and smpMod are Ed 2.1 fields of the sampled-value control block.
func TestSampledValueOpts(t *testing.T) {
	_, m := loadEd21(t)
	ln := m.Device("ED21LD0").Node("LLN0")
	if len(ln.SVControls) != 2 {
		t.Fatalf("%d SV control blocks, want 2", len(ln.SVControls))
	}
	byName := map[string]*model.SVControl{}
	for _, sc := range ln.SVControls {
		byName[sc.Name] = sc
	}
	mcast := byName["msvcb01"]
	if mcast.SmpMod != model.SmpPerSec {
		t.Errorf("msvcb01 SmpMod = %v, want SmpPerSec", mcast.SmpMod)
	}
	if !mcast.Multicast {
		t.Error("msvcb01 should be multicast")
	}
	if mcast.SvType != "MSV" {
		t.Errorf("msvcb01 SvType = %q, want MSV, trimmed", mcast.SvType)
	}
	if !mcast.Opts.SampleSynchronized || !mcast.Opts.SynchSourceID {
		t.Errorf("msvcb01 SmvOpts = %+v, want sampleSynchronized and synchSourceId set", mcast.Opts)
	}
	if mcast.Opts.DataSet || mcast.Opts.Security {
		t.Errorf("msvcb01 SmvOpts = %+v, want dataSet and security clear", mcast.Opts)
	}
	// The unicast block carries the R-SV profile, which the loader reports
	// rather than implementing.
	ucast := byName["usvcb01"]
	if ucast.Multicast {
		t.Error("usvcb01 should be unicast")
	}
	if ucast.SvType != "" {
		t.Errorf("usvcb01 SvType = %q, want empty for an absent attribute", ucast.SvType)
	}
	if ucast.Protocol != "R-SV" {
		t.Errorf("usvcb01 Protocol = %q, want R-SV", ucast.Protocol)
	}
	if !ucast.Opts.DataSet || !ucast.Opts.Security {
		t.Errorf("usvcb01 SmvOpts = %+v, want dataSet and security set", ucast.Opts)
	}
}

// A GSSE control block is told apart from a GOOSE one, and R-GOOSE is
// carried as the block's protocol.
func TestGSEControlVariants(t *testing.T) {
	_, m := loadEd21(t)
	ln := m.Device("ED21LD0").Node("LLN0")
	byName := map[string]*model.GSEControl{}
	for _, gc := range ln.GSEControls {
		byName[gc.Name] = gc
	}
	if got := byName["gcb01"].Type; got != model.GOOSE {
		t.Errorf("gcb01 type = %v, want GOOSE", got)
	}
	if got := byName["gcb01"].Protocol; got != "R-GOOSE" {
		t.Errorf("gcb01 protocol = %q, want R-GOOSE", got)
	}
	if got := byName["gscb01"].Type; got != model.GSSE {
		t.Errorf("gscb01 type = %v, want GSSE", got)
	}
	// fixedOffs is the encoding flag on the control block. It is carried
	// as configured and reported, since the encoding is not implemented.
	if !byName["gcb01"].FixedOffs || byName["gscb01"].FixedOffs {
		t.Errorf("FixedOffs = %v/%v, want true for gcb01 only",
			byName["gcb01"].FixedOffs, byName["gscb01"].FixedOffs)
	}
	assertDiagnostic(t, m, "fixed-offset")
	assertDiagnostic(t, m, "GSSE")
}

// The GOOSE retransmission timing comes from the Communication section.
func TestGSECommunicationTiming(t *testing.T) {
	_, m := loadEd21(t)
	for _, gc := range m.Device("ED21LD0").Node("LLN0").GSEControls {
		if gc.Name != "gcb01" {
			continue
		}
		if gc.MinTime != 20 || gc.MaxTime != 1000 {
			t.Errorf("timing = %d..%d ms, want 20..1000", gc.MinTime, gc.MaxTime)
		}
		if gc.DstMAC != [6]byte{1, 0x0c, 0xcd, 3, 0, 1} {
			t.Errorf("DstMAC = %x, want 010ccd030001", gc.DstMAC)
		}
		if gc.AppID != 0x2000 {
			t.Errorf("AppID = %04x, want 2000", gc.AppID)
		}
		return
	}
	t.Fatal("gcb01 missing")
}

// A log control block naming its own logical node, with the Ed 2 buffer
// period and the reasonCode default.
func TestLogControlFields(t *testing.T) {
	_, m := loadEd21(t)
	lcs := m.Device("ED21LD0").Node("LLN0").LogControls
	if len(lcs) != 1 {
		t.Fatalf("%d log control blocks, want 1", len(lcs))
	}
	lc := lcs[0]
	if !lc.LogEna || !lc.ReasonCode || lc.BufTime != 500 {
		t.Errorf("lcb01 = %+v, want enabled, reasonCode, bufTime 500", *lc)
	}
}

// The Ed 2.1 reservation time of the setting group control block.
func TestSettingControlResvTms(t *testing.T) {
	_, m := loadEd21(t)
	sc := m.Device("ED21LD0").Node("LLN0").SettingControl
	if sc == nil {
		t.Fatal("no SettingControl")
	}
	if sc.NumOfSGs != 2 || sc.ActSG != 1 || sc.ResvTms != 30000 {
		t.Errorf("SGCB = %+v, want 2 groups, active 1, resvTms 30000", *sc)
	}
}

// bufOvfl defaults to true in the schema, so an OptFields element that does
// not mention it still requests it.
func TestOptFieldsBufOvflDefault(t *testing.T) {
	_, m := loadEd21(t)
	for _, rc := range m.Device("ED21LD0").Node("LLN0").ReportControls {
		if rc.Name != "brcb01" {
			continue
		}
		if rc.OptFlds&model.OptBufOvfl == 0 {
			t.Error("bufOvfl should default to true")
		}
		if rc.OptFlds&model.OptSegmentation != 0 {
			t.Error("segmentation was not requested by the document")
		}
		if rc.OptFlds&model.OptEntryID == 0 {
			t.Error("entryID was requested but is not set")
		}
		return
	}
	t.Fatal("brcb01 missing")
}

// RptEnabled beyond the 99 two-digit instance names is capped and reported
// rather than producing 1000 unnamed blocks.
func TestRptEnabledIsCapped(t *testing.T) {
	const doc = `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
	  <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0">
	    <LN0 lnClass="LLN0" inst="" lnType="LLN0T">
	      <ReportControl name="urcb" rptID="r" confRev="1" buffered="false">
	        <RptEnabled max="1000"/>
	      </ReportControl>
	    </LN0>
	  </LDevice></Server></AccessPoint></IED>
	  <DataTypeTemplates>
	    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="Mod" type="INC"/></LNodeType>
	    <DOType id="INC" cdc="INC"><DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/></DOType>
	  </DataTypeTemplates>
	</SCL>`
	s, err := scl.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	m, err := scl.BuildModel(s)
	if err != nil {
		t.Fatal(err)
	}
	rc := m.Device("ILD0").Node("LLN0").ReportControls[0]
	if rc.RptEnabled != 99 {
		t.Errorf("RptEnabled = %d, want it capped at 99", rc.RptEnabled)
	}
	assertDiagnostic(t, m, "capped")
}

// The count a document asks for is bounded, so a corrupt or hostile value
// cannot make the loader allocate without limit.
func TestArrayCountIsBounded(t *testing.T) {
	const doc = `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
	  <IED name="I"><AccessPoint name="A"><Server><LDevice inst="LD0">
	    <LN0 lnClass="LLN0" inst="" lnType="LLN0T"/>
	  </LDevice></Server></AccessPoint></IED>
	  <DataTypeTemplates>
	    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="AnIn3" type="WYE"/></LNodeType>
	    <DOType id="WYE" cdc="WYE"><SDO name="phsA" type="CMV" count="200000000"/></DOType>
	    <DOType id="CMV" cdc="CMV"><DA name="mag" bType="FLOAT32" fc="MX" dchg="true"/></DOType>
	  </DataTypeTemplates>
	</SCL>`
	s, err := scl.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	m, err := scl.BuildModel(s)
	if err != nil {
		t.Fatal(err)
	}
	anIn3 := m.Device("ILD0").Node("LLN0").Object("AnIn3")
	if len(anIn3.Objects) != 0 {
		t.Errorf("%d instances created from an out-of-range count, want 0", len(anIn3.Objects))
	}
}

// Strict turns the collected diagnostics into an error; the permissive
// build returns the same model.
func TestStrictOption(t *testing.T) {
	s, err := scl.ParseFile(ed21Fixture)
	if err != nil {
		t.Fatal(err)
	}
	permissive, err := scl.BuildModel(s)
	if err != nil {
		t.Fatalf("permissive build failed: %v", err)
	}
	if len(permissive.Diagnostics) == 0 {
		t.Fatal("expected diagnostics from this fixture")
	}
	if _, err := scl.BuildModel(s, scl.Strict(true)); err == nil {
		t.Fatal("strict build should fail on the same document")
	}
}

// OnWarn streams the same diagnostics as they are raised.
func TestOnWarn(t *testing.T) {
	s, err := scl.ParseFile(ed21Fixture)
	if err != nil {
		t.Fatal(err)
	}
	var seen []scl.Diagnostic
	m, err := scl.BuildModel(s, scl.OnWarn(func(d scl.Diagnostic) { seen = append(seen, d) }))
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(m.Diagnostics) {
		t.Errorf("OnWarn saw %d diagnostics, the model carries %d", len(seen), len(m.Diagnostics))
	}
}

// A corrupt or truncated document is still a hard error: permissiveness is
// about unrecognised constructs, not about malformed XML.
func TestMalformedDocumentFails(t *testing.T) {
	for _, doc := range []string{
		`<SCL><IED name="I"`,
		`<NotSCL/>`,
		``,
	} {
		if _, err := scl.Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("Parse(%q) should fail", doc)
		}
	}
}

// A LNodeType is identified by (id, lnClass), so a document that reuses an
// id across node classes resolves each to its own template.
func TestLNodeTypeIdentityIsIdAndClass(t *testing.T) {
	_, m := loadEd21(t)
	ggio1 := m.Device("ED21LD0").Node("GGIO1")
	if ggio1.Object("AnIn1") == nil {
		t.Error("GGIO1 built from the wrong LNodeType: AnIn1 missing")
	}
	if ggio1.Object("AnIn9") != nil {
		t.Error("GGIO1 should not carry AnIn9, which belongs to the GGIO_2 template")
	}
}

// The audit must not cost a second decode of the document for the common
// case, and must not blow up on deeply nested input.
func TestAuditIsDepthBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4"><Unknown>`)
	for i := 0; i < 5000; i++ {
		sb.WriteString(`<Unknown>`)
	}
	for i := 0; i < 5000; i++ {
		sb.WriteString(`</Unknown>`)
	}
	sb.WriteString(`</Unknown></SCL>`)
	s, err := scl.Parse(strings.NewReader(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	paths := s.Dropped()["Unknown"]
	if len(paths) == 0 {
		t.Fatal("deeply nested unknown elements not reported")
	}
	for _, p := range paths {
		if len(p) > 1<<10 {
			t.Errorf("recorded path of %d bytes is not bounded", len(p))
		}
	}
}

func TestFixtureIsPresent(t *testing.T) {
	if _, err := os.Stat(ed21Fixture); err != nil {
		t.Fatalf("Edition 2.1 fixture missing: %v", err)
	}
}

func assertDiagnostic(t *testing.T, m *model.Model, substr string) {
	t.Helper()
	for _, d := range m.Diagnostics {
		if strings.Contains(d.Message, substr) {
			return
		}
	}
	var all []string
	for _, d := range m.Diagnostics {
		all = append(all, d.String())
	}
	t.Errorf("no diagnostic containing %q; got:\n  %s", substr, strings.Join(all, "\n  "))
}

// A ClientLN reserves the instance at its position for the client IED it
// names, identified by the IP address of that IED's access point. One whose
// IED has no address cannot be enforced, so its instance stays free and
// the document is told why.
func TestClientLNReservations(t *testing.T) {
	_, m := loadEd21(t)
	ln := m.Device("ED21LD0").Node("LLN0")
	var urcb, brcb *model.ReportControl
	for _, rc := range ln.ReportControls {
		switch rc.Name {
		case "urcb01":
			urcb = rc
		case "brcb01":
			brcb = rc
		}
	}
	if urcb == nil || brcb == nil {
		t.Fatal("report controls missing from the fixture")
	}
	if len(urcb.Reservations) != 1 || urcb.Reservations[0] == nil ||
		!urcb.Reservations[0].IP.Equal(net.ParseIP("192.168.1.11")) {
		t.Errorf("urcb01 reservations = %+v, want instance 1 for 192.168.1.11", urcb.Reservations)
	}
	if len(brcb.Reservations) != 2 {
		t.Fatalf("brcb01 has %d reservations, want 2", len(brcb.Reservations))
	}
	if r := brcb.Reservations[0]; r == nil || r.IEDName != "HMI" || !r.IP.Equal(net.ParseIP("10.0.0.50")) {
		t.Errorf("brcb01 instance 1 = %+v, want HMI at 10.0.0.50", r)
	}
	if r := brcb.Reservations[1]; r != nil {
		t.Errorf("brcb01 instance 2 = %+v, want it unreserved", r)
	}
	assertDiagnostic(t, m, `"GHOST"`)
}

// A routable control block's destination is the IP address of its GSE or
// SMV address, which the model carries for opening an R-GOOSE or R-SV
// session (package rsession).
func TestRoutableDestination(t *testing.T) {
	_, m := loadEd21(t)
	lln0 := m.Device("ED21LD0").Node("LLN0")
	var gcb *model.GSEControl
	for _, g := range lln0.GSEControls {
		if g.Name == "gcb01" {
			gcb = g
		}
	}
	if gcb == nil || gcb.Protocol != "R-GOOSE" || !gcb.DstIP.Equal(net.ParseIP("239.192.0.1")) {
		t.Errorf("gcb01 = %+v, want R-GOOSE to 239.192.0.1", gcb)
	}
	var usv *model.SVControl
	for _, s := range lln0.SVControls {
		if s.Name == "usvcb01" {
			usv = s
		}
	}
	if usv == nil || !usv.DstIP.Equal(net.ParseIP("2001:db8::10")) {
		t.Errorf("usvcb01 = %+v, want 2001:db8::10", usv)
	}
	for _, s := range lln0.SVControls {
		if s.Name == "msvcb01" && s.DstIP != nil {
			t.Errorf("msvcb01 has a destination IP %v it was not given", s.DstIP)
		}
	}
}

// A routable block is reported only when it cannot be sent routably: when
// its address has no IP destination.
func TestRoutableWithoutDestination(t *testing.T) {
	_, m := loadEd21(t)
	for _, d := range m.Diagnostics {
		if strings.Contains(d.Message, "R-GOOSE") || strings.Contains(d.Message, "R-SV") {
			t.Errorf("a routable block with a destination was reported: %s", d)
		}
	}
	raw, err := os.ReadFile(ed21Fixture)
	if err != nil {
		t.Fatal(err)
	}
	noIP := strings.Replace(string(raw), `<P type="IP">239.192.0.1</P>`, "", 1)
	s, err := scl.Parse(strings.NewReader(noIP))
	if err != nil {
		t.Fatal(err)
	}
	m2, err := scl.BuildModel(s)
	if err != nil {
		t.Fatal(err)
	}
	assertDiagnostic(t, m2, "Protocol is R-GOOSE but the GSE address has no IP")
}
