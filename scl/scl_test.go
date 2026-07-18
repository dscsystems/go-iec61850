package scl_test

import (
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
)

const cidFile = "../testdata/simpleIO_direct_control.cid"

func TestParseRealCID(t *testing.T) {
	doc, err := scl.ParseFile(cidFile)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(doc.IEDs) == 0 {
		t.Fatal("no IEDs parsed")
	}
	if doc.IEDs[0].Name != "simpleIO" {
		t.Fatalf("IED name = %q, want simpleIO", doc.IEDs[0].Name)
	}
}

func TestBuildModelFromCID(t *testing.T) {
	m, err := scl.LoadModel(cidFile)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}

	// The libiec61850 basic_io model has one logical device whose MMS
	// domain is "simpleIOGenericIO" (IED name + LD inst).
	ld := m.Device("simpleIOGenericIO")
	if ld == nil {
		t.Fatalf("logical device simpleIOGenericIO not found; devices: %v", deviceNames(m))
	}

	ggio := ld.Node("GGIO1")
	if ggio == nil {
		t.Fatalf("GGIO1 not found; nodes: %v", nodeNames(ld))
	}

	// AnIn1.mag.f is a float32 measurand under FC MX.
	da := m.Attribute("simpleIOGenericIO/GGIO1.AnIn1.mag.f", model.MX)
	if da == nil {
		t.Fatalf("AnIn1.mag.f not found under MX\n%s", m.String())
	}
	if da.Kind != mms.TypeFloat32 {
		t.Errorf("AnIn1.mag.f kind = %s, want float32", da.Kind)
	}

	// SPCSO1.ctlModel is a config attribute; the direct-control model
	// ships ctlModel = 1 (direct-with-normal-security).
	cm := m.Attribute("simpleIOGenericIO/GGIO1.SPCSO1.ctlModel", model.CF)
	if cm == nil {
		t.Fatalf("SPCSO1.ctlModel not found\n%s", m.String())
	}
	if cm.Value != nil && cm.Value.Int64() != int64(model.CtlDirectNormal) {
		t.Logf("ctlModel initial value = %s (expected 1)", cm.Value)
	}
}

func TestDataSetsAndControlBlocks(t *testing.T) {
	m, err := scl.LoadModel(cidFile)
	if err != nil {
		t.Fatal(err)
	}
	ld := m.Device("simpleIOGenericIO")
	if ld == nil {
		t.Fatal("device missing")
	}
	lln0 := ld.Node("LLN0")
	if lln0 == nil {
		t.Fatal("LLN0 missing")
	}
	// The basic_io model defines Events, Events2 and Measurements datasets.
	if len(lln0.DataSets) == 0 {
		t.Errorf("no datasets on LLN0")
	}
	foundMeas := false
	for _, ds := range lln0.DataSets {
		if ds.Name == "Measurements" {
			foundMeas = true
			if len(ds.Entries) == 0 {
				t.Error("Measurements dataset has no entries")
			}
		}
	}
	if !foundMeas {
		t.Errorf("Measurements dataset not found; got %v", datasetNames(lln0))
	}
	// Report control blocks should be present.
	if len(lln0.ReportControls) == 0 {
		t.Errorf("no report control blocks on LLN0")
	}
}

func deviceNames(m *model.Model) []string {
	var out []string
	for _, d := range m.Devices {
		out = append(out, d.Name)
	}
	return out
}

func nodeNames(ld *model.LogicalDevice) []string {
	var out []string
	for _, n := range ld.Nodes {
		out = append(out, n.Name)
	}
	return out
}

func datasetNames(ln *model.LogicalNode) []string {
	var out []string
	for _, ds := range ln.DataSets {
		out = append(out, ds.Name)
	}
	return out
}

func FuzzParse(f *testing.F) {
	data := []byte(`<SCL xmlns="http://www.iec.ch/61850/2003/SCL"><IED name="x"/></SCL>`)
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		if doc, err := scl.Parse(bytesReader(data)); err == nil {
			scl.BuildModel(doc)
		}
	})
}

type byteReader struct {
	b []byte
	i int
}

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, errEOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

var errEOF = &eofError{}

type eofError struct{}

func (*eofError) Error() string { return "EOF" }
