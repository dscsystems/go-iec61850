package scl_test

import (
	"strings"
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
)

// load builds a model from an inline SCL document, failing the test if the
// document does not load. The point of every test here is what happens after
// a load, so the documents are written to load cleanly.
func load(t *testing.T, doc string) *model.Model {
	t.Helper()
	s, err := scl.Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, err := scl.BuildModel(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return m
}

const twoLDHeader = `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0">
      <LN0 lnClass="LLN0" inst="" lnType="LLN0T">
        <SettingControl numOfSGs="2" actSG="2"/>`

// A setting-group value belongs to the logical device that declares it. An
// IED usually has several devices and they can have differently named
// settings, so keying the recorded groups on the group number alone applied
// one device's value to another's same-named attribute — a device serving a
// setting value its own document never mentions.
func TestSettingGroupsDoNotLeakBetweenLogicalDevices(t *testing.T) {
	doc := twoLDHeader + `
        <DOI name="IntRange">
          <DAI name="setVal"><Val sGroup="2">111</Val></DAI>
        </DOI>
      </LN0>
      <LN lnClass="GGIO" inst="1" lnType="GGT">
        <DOI name="IntRange">
          <DAI name="setVal"><Val sGroup="2">222</Val></DAI>
        </DOI>
      </LN>
    </LDevice>
    <LDevice inst="LD1">
      <LN0 lnClass="LLN0" inst="" lnType="LLN0T">
        <SettingControl numOfSGs="2" actSG="2"/>
      </LN0>
      <LN lnClass="GGIO" inst="1" lnType="GGT">
        <DOI name="IntRange">
          <DAI name="setVal"><Val sGroup="2">333</Val></DAI>
        </DOI>
      </LN>
    </LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="IntRange" type="ASGT"/></LNodeType>
    <LNodeType id="GGT" lnClass="GGIO"><DO name="IntRange" type="ASGT"/></LNodeType>
    <DOType id="ASGT" cdc="ASG">
      <DA name="setVal" bType="FLOAT32" fc="SG" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
</SCL>`
	m := load(t, doc)

	// Each device serves the value its own document gives.
	// The document gives LLN0 and GGIO1 of LD0 different values, and LD1
	// a third, so a value crossing between devices is visible.
	for _, tc := range []struct {
		ln   string
		ld   string
		want float32
	}{
		{"GGIO1", "ILD0", 222}, {"LLN0", "ILD0", 111}, {"GGIO1", "ILD1", 333},
	} {
		got := m.Device(tc.ld).Node(tc.ln).Object("IntRange").Attribute("setVal").Value
		if got.Float32() != tc.want {
			t.Errorf("%s/%s.IntRange.setVal = %v, want %v", tc.ld, tc.ln, got, tc.want)
		}
	}
	// The group records name the device they belong to, and the groups of
	// both devices are reported separately.
	byLD := map[string]map[string]float32{}
	for _, g := range m.SettingGroups {
		byLD[g.LD] = map[string]float32{}
		for ref, v := range g.Values {
			byLD[g.LD][ref] = v.Float32()
		}
	}
	if len(m.SettingGroups) != 2 {
		t.Fatalf("%d setting groups, want one per device", len(m.SettingGroups))
	}
	for _, tc := range []struct {
		ld   string
		want map[string]float32
	}{
		{"ILD0", map[string]float32{
			"ILD0/GGIO1.IntRange.setVal": 222, "ILD0/LLN0.IntRange.setVal": 111}},
		{"ILD1", map[string]float32{
			"ILD1/GGIO1.IntRange.setVal": 333}},
	} {
		if len(byLD[tc.ld]) != len(tc.want) {
			t.Errorf("%s recorded %d values, want %d: %v",
				tc.ld, len(byLD[tc.ld]), len(tc.want), byLD[tc.ld])
		}
		for ref, want := range tc.want {
			if got := byLD[tc.ld][ref]; got != want {
				t.Errorf("%s group value %s = %v, want %v", tc.ld, ref, got, want)
			}
		}
	}
}

// An enum-typed attribute inside a multi-instance data object resolves a Val
// given as a literal name. The instances are clones of the template, and a
// clone without the template's enum binding rejected every literal — so
// phase directions silently stayed at ord 0, which is not a valid value of
// the enumeration.
func TestEnumBindingSurvivesArrayCloning(t *testing.T) {
	doc := `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <DOI name="AnIn3">
        <SDI name="phsA" ix="2">
          <DAI name="dirGeneral"><Val>forward</Val></DAI>
        </SDI>
      </DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="AnIn3" type="ACDC"/></LNodeType>
    <DOType id="ACDC" cdc="ACD"><SDO name="phsA" type="ACDT" count="3"/></DOType>
    <DOType id="ACDT" cdc="ACD">
      <DA name="general" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="dirGeneral" bType="Enum" type="Dir" fc="ST" dchg="true"/>
    </DOType>
    <EnumType id="Dir">
      <EnumVal ord="1">forward</EnumVal>
      <EnumVal ord="2">backward</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>`
	m := load(t, doc)
	anIn3 := m.Device("ILD0").Node("LLN0").Object("AnIn3")
	if len(anIn3.Objects) != 3 {
		t.Fatalf("%d instances, want 3", len(anIn3.Objects))
	}
	for i, sub := range anIn3.Objects {
		dir := sub.Attribute("dirGeneral")
		if dir == nil || dir.Value == nil {
			t.Fatalf("phsA(%d).dirGeneral missing", i+1)
		}
		// The document sets phsA(2) to "forward", ord 1. The others keep
		// the zero the template gives them, which is not a valid Dir: the
		// assertion that matters is that the literal resolved at all,
		// because an unresolved one also leaves 0.
		want := 0
		if i == 1 {
			want = 1
		}
		if got := dir.Value.Int64(); got != int64(want) {
			t.Errorf("phsA(%d).dirGeneral = %d, want %d (an unresolvable literal "+
				"would leave 0, which is not a valid Dir)", i+1, got, want)
		}
	}
}

// A DAI sAddr addressing an element of an array of Enums must resolve the
// literal too: the value is parsed against a stand-in attribute, and a
// stand-in that does not inherit the enum binding rejects every literal.
func TestEnumBindingSurvivesSAddrElement(t *testing.T) {
	doc := `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <DOI name="AnIn1">
        <DAI name="dirs" sAddr="2"><Val>backward</Val></DAI>
      </DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="AnIn1" type="MVT"/></LNodeType>
    <DOType id="MVT" cdc="MV">
      <DA name="dirs" bType="Enum" type="Dir" fc="MX" dchg="true" count="3"/>
    </DOType>
    <EnumType id="Dir">
      <EnumVal ord="1">forward</EnumVal>
      <EnumVal ord="2">backward</EnumVal>
    </EnumType>
  </DataTypeTemplates>
</SCL>`
	m := load(t, doc)
	dirs := m.Device("ILD0").Node("LLN0").Object("AnIn1").Attribute("dirs")
	if dirs == nil || dirs.Value == nil {
		t.Fatal("AnIn1.dirs missing")
	}
	if got := dirs.Elem(1).Int64(); got != 2 {
		t.Errorf("dirs[2] = %d, want 2", got)
	}
	// The elements the document did not mention keep the enumeration's
	// zero, which is not a valid Dir — a limitation of the schema, not a
	// bug, but worth pinning so a change to it is deliberate.
	if got := dirs.Elem(0).Int64(); got != 0 {
		t.Errorf("dirs[1] = %d, want the untouched default 0", got)
	}
}

// A Val with both an sAddr and an sGroup other than the active one defines
// that group and not the active group. Handling only the sAddr half leaked
// the value into the active group and recorded nothing, so it was both wrong
// and lost.
func TestSAddrWithSettingGroupIsRecordedNotLeaked(t *testing.T) {
	doc := `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <SettingControl numOfSGs="2" actSG="1"/>
      <DOI name="IntRange">
        <DAI name="setVals" sAddr="1"><Val sGroup="2">42.5</Val></DAI>
      </DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0"><DO name="IntRange" type="ASGT"/></LNodeType>
    <DOType id="ASGT" cdc="ASG">
      <DA name="setVals" bType="FLOAT32" fc="SG" dchg="true" count="3"/>
    </DOType>
  </DataTypeTemplates>
</SCL>`
	m := load(t, doc)
	ld := m.Device("ILD0")
	setVals := ld.Node("LLN0").Object("IntRange").Attribute("setVals")

	// Group 2 is not the active group (actSG="1"), so the served value
	// must be untouched.
	if got := setVals.Elem(0).Float32(); got != 0 {
		t.Errorf("setVals[1] = %v, want the active group's untouched 0; the "+
			"group-2 value leaked into the served array", got)
	}
	// And the value must be recorded for group 2.
	var found bool
	for _, g := range m.SettingGroups {
		if g.Number != 2 {
			continue
		}
		arr, ok := g.Values["ILD0/LLN0.IntRange.setVals"]
		if !ok {
			t.Errorf("group 2 has no setVals record: %v", g.Values)
			continue
		}
		if arr.Type() != mms.TypeArray {
			t.Errorf("group 2 setVals is %v, want an array", arr.Type())
			continue
		}
		if got := arr.Index(0).Float32(); got != 42.5 {
			t.Errorf("group 2 setVals[1] = %v, want 42.5", got)
		}
		found = true
	}
	if !found {
		t.Fatalf("no setting group 2 recorded; the value was both leaked and lost: %+v",
			m.SettingGroups)
	}
}

// A Val with sGroup on an attribute that is not a setting-group attribute
// is not a setting-group value and is recorded as nothing, but is still
// applied: the document set it, and there is no group to keep it out of.
func TestSettingGroupRecordOnlyAppliesToSGAndSE(t *testing.T) {
	doc := `<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B" release="4">
  <IED name="I" type="I"><AccessPoint name="A"><Server>
    <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0T">
      <SettingControl numOfSGs="2" actSG="2"/>
      <DOI name="SPS">
        <DAI name="stVal"><Val sGroup="2">true</Val></DAI>
      </DOI>
      <DOI name="IntRange">
        <DAI name="setVal"><Val sGroup="2">7.5</Val></DAI>
      </DOI>
    </LN0></LDevice>
  </Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0T" lnClass="LLN0">
      <DO name="SPS" type="SPST"/>
      <DO name="IntRange" type="ASGT"/>
    </LNodeType>
    <DOType id="SPST" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
    </DOType>
    <DOType id="ASGT" cdc="ASG">
      <DA name="setVal" bType="FLOAT32" fc="SG" dchg="true"/>
    </DOType>
  </DataTypeTemplates>
</SCL>`
	m := load(t, doc)
	ln := m.Device("ILD0").Node("LLN0")
	// A non-setting attribute keeps the value the document gave it.
	if !ln.Object("SPS").Attribute("stVal").Value.Bool() {
		t.Error("stVal = false, want the value the document gave it")
	}
	// Only the SG attribute is recorded as a setting-group value.
	for _, g := range m.SettingGroups {
		if _, ok := g.Values["ILD0/LLN0.SPS.stVal"]; ok {
			t.Error("an FC ST attribute was recorded as a setting-group value")
		}
		if v, ok := g.Values["ILD0/LLN0.IntRange.setVal"]; !ok || v.Float32() != 7.5 {
			t.Errorf("group %d IntRange.setVal = %v, want 7.5", g.Number, v)
		}
	}
}
