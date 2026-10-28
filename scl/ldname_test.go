package scl

import (
	"strings"
	"testing"

	"github.com/dscsystems/go-iec61850/model"
)

// ldNameSCL has two logical devices, the first renamed by ldName and the
// second named after the IED, with a dataset in each that points across.
const ldNameSCL = `<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="ldname"/>
  <IED name="TESTIED">
    <AccessPoint name="AP1">
      <Server>
        <LDevice inst="LD0" ldName="Bay1">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0type">
            <DataSet name="Own">
              <FCDA lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <DataSet name="Other">
              <FCDA ldInst="LD1" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIOtype"/>
        </LDevice>
        <LDevice inst="LD1">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0type">
            <DataSet name="Back">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
          </LN0>
          <LN lnClass="GGIO" inst="1" lnType="GGIOtype"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0type" lnClass="LLN0"/>
    <LNodeType id="GGIOtype" lnClass="GGIO">
      <DO name="Ind1" type="SPStype"/>
    </LNodeType>
    <DOType id="SPStype" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST"/>
    </DOType>
  </DataTypeTemplates>
</SCL>`

// With UseLDName, LDevice@ldName (Ed 2) replaces the IED name + inst as
// the device name, and every dataset member naming that device by ldInst
// follows it.
func TestLDeviceLdName(t *testing.T) {
	s, err := Parse(strings.NewReader(ldNameSCL))
	if err != nil {
		t.Fatal(err)
	}
	m, err := BuildModel(s, UseLDName(true))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ld := range m.Devices {
		names = append(names, ld.Name+":"+ld.Inst)
	}
	if got := strings.Join(names, " "); got != "Bay1:LD0 TESTIEDLD1:LD1" {
		t.Fatalf("devices = %s", got)
	}
	if m.Attribute("Bay1/GGIO1.Ind1.stVal", model.ST) == nil {
		t.Error("Bay1/GGIO1.Ind1.stVal not in the model")
	}
	members := map[string]string{}
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, ds := range ln.DataSets {
				members[ds.Name] = string(ds.Entries[0].Ref)
			}
		}
	}
	for ds, want := range map[string]string{
		"Own":   "Bay1/GGIO1.Ind1.stVal",
		"Other": "TESTIEDLD1/GGIO1.Ind1.stVal",
		"Back":  "Bay1/GGIO1.Ind1.stVal",
	} {
		if members[ds] != want {
			t.Errorf("dataset %s member = %q, want %q", ds, members[ds], want)
		}
	}
}

// Without UseLDName the attribute is ignored and the names stay IED + inst.
func TestLDeviceLdNameIgnoredByDefault(t *testing.T) {
	s, err := Parse(strings.NewReader(ldNameSCL))
	if err != nil {
		t.Fatal(err)
	}
	m, err := BuildModel(s)
	if err != nil {
		t.Fatal(err)
	}
	if m.Devices[0].Name != "TESTIEDLD0" {
		t.Errorf("device = %s, want TESTIEDLD0", m.Devices[0].Name)
	}
}
