package scl_test

import (
	"testing"

	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
)

// indexed="false" makes a report control block a single instance under
// its own name (IEC 61850-6); the default stays indexed.
func TestReportControlIndexed(t *testing.T) {
	doc, err := scl.ParseFile(cidFile)
	if err != nil {
		t.Fatal(err)
	}
	ln0 := doc.IEDs[0].AccessPoints[0].Server.LDevices[0].LN0
	for i := range ln0.ReportControls {
		if ln0.ReportControls[i].Name == "EventsRCB" {
			ln0.ReportControls[i].Indexed = "false"
		}
	}
	m, err := scl.BuildModel(doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, rc := range m.Devices[0].Node("LLN0").ReportControls {
		switch rc.Name {
		case "EventsRCB":
			if !rc.NotIndexed || rc.RptEnabled != 1 {
				t.Errorf("EventsRCB: NotIndexed=%v RptEnabled=%d, want true and 1", rc.NotIndexed, rc.RptEnabled)
			}
		case "EventsIndexed":
			if rc.NotIndexed {
				t.Error("indexed=\"true\" parsed as not indexed")
			}
		}
	}
}

// A DA's trigger options cover its components: the leaf an update writes,
// mag.f, triggers as mag does (IEC 61850-7-2).
func TestTriggerOptionsReachComponents(t *testing.T) {
	m, err := scl.LoadModel(cidFile)
	if err != nil {
		t.Fatal(err)
	}
	ld := m.Devices[0].Name
	mag := m.Attribute(model.ObjectReference(ld+"/GGIO1.AnIn1.mag"), model.MX)
	f := m.Attribute(model.ObjectReference(ld+"/GGIO1.AnIn1.mag.f"), model.MX)
	if mag == nil || f == nil {
		t.Fatal("AnIn1.mag.f not in the model")
	}
	if mag.TrgOps == 0 {
		t.Fatal("the demo model declares no trigger option on mag")
	}
	if f.TrgOps != mag.TrgOps {
		t.Errorf("mag.f TrgOps = %v, want mag's %v", f.TrgOps, mag.TrgOps)
	}
}
