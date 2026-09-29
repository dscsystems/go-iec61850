package scl_test

import (
	"strings"
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
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

// The Edition 2 and 2.1 classes of the fixture are shaped as IEC 61850-7-3
// defines them, so what the loader builds from the file and what
// model.NewDataObject builds from its template agree: every attribute the
// file declares is in the template under the same constraint and type, and
// every mandatory attribute of the template is in the file. A class the
// library has a template for is not reported as unknown.
func TestEd2ClassesMatchTemplates(t *testing.T) {
	_, m := loadEd21(t)
	ld := m.Device("ED21LD0")
	for _, lnName := range []string{"GAPC1", "LTRK1"} {
		ln := ld.Node(lnName)
		if ln == nil {
			t.Fatalf("%s missing", lnName)
		}
		for _, do := range ln.Objects {
			path := lnName + "." + do.Name
			if !model.KnownCDC(do.CDC) {
				t.Errorf("%s: class %q has no template", path, do.CDC)
				continue
			}
			for _, d := range m.Diagnostics {
				if strings.Contains(d.Path, path) && strings.Contains(d.Message, "attribute templates") {
					t.Errorf("%s reported as an unknown class: %s", path, d.Message)
				}
			}
			shape, optional := templateOptions(do)
			tmpl := model.NewDataObject(do.Name, model.CDC(do.CDC), append(shape, optional)...)
			compareToTemplate(t, path, do.Attributes, tmpl.Attributes)
			mandatory := model.NewDataObject(do.Name, model.CDC(do.CDC), shape...)
			for _, want := range mandatory.Attributes {
				if do.Attribute(want.Name) == nil {
					t.Errorf("%s.%s: mandatory in 7-3, missing from the file", path, want.Name)
				}
			}
		}
	}

	// A value the file gives reaches the object.
	if v := ld.Node("GAPC1").Object("Cur").Attribute("cur").Value.Text(); v != "EUR" {
		t.Errorf("Cur.cur = %q, want EUR", v)
	}
}

// templateOptions asks the template for what the loaded object has: the
// length of its arrays and a control model when it is controllable (shape),
// and its optional attributes, at any depth (optional).
func templateOptions(do *model.DataObject) (shape []model.CDCOption, optional model.CDCOption) {
	var names []string
	var collect func(das []*model.DataAttribute)
	collect = func(das []*model.DataAttribute) {
		for _, da := range das {
			names = append(names, da.Name)
			collect(da.Children)
		}
	}
	collect(do.Attributes)
	for _, da := range do.Attributes {
		if da.Kind == mms.TypeArray && da.Count > 0 {
			shape = append(shape, model.WithMaxPts(da.Count))
		}
		if da.Name == "Oper" {
			shape = append(shape, model.WithControlModel(model.CtlDirectNormal), model.WithoutCancel())
		}
	}
	return shape, model.WithOptional(names...)
}

func compareToTemplate(t *testing.T, path string, got, want []*model.DataAttribute) {
	t.Helper()
	byName := map[string]*model.DataAttribute{}
	pos := map[string]int{}
	for i, w := range want {
		byName[w.Name] = w
		pos[w.Name] = i
	}
	// MMS structures are positional: within one functional constraint the
	// members the file has must come in the template's order.
	last := map[model.FC]int{}
	for _, g := range got {
		if i, ok := pos[g.Name]; ok {
			if l, seen := last[g.FC]; seen && i < l {
				t.Errorf("%s.%s: out of the 7-3 order", path, g.Name)
			}
			last[g.FC] = i
		}
	}
	for _, g := range got {
		p := path + "." + g.Name
		w, ok := byName[g.Name]
		if !ok {
			t.Errorf("%s: in the file, not in the 7-3 template", p)
			continue
		}
		if g.FC != w.FC {
			t.Errorf("%s: FC %s, the template has %s", p, g.FC, w.FC)
		}
		if g.Kind != w.Kind {
			t.Errorf("%s: %v, the template has %v", p, g.Kind, w.Kind)
		}
		if g.Kind == mms.TypeArray && g.Count != w.Count {
			t.Errorf("%s: %d elements, the template has %d", p, g.Count, w.Count)
		}
		if g.Value != nil && w.Value != nil && g.Kind == mms.TypeBitString && g.Value.BitLen() != w.Value.BitLen() {
			t.Errorf("%s: %d bits, the template has %d", p, g.Value.BitLen(), w.Value.BitLen())
		}
		compareToTemplate(t, p, g.Children, w.Children)
	}
}

// A loaded model can be checked against the 7-4 logical node classes. The
// Edition 2.1 fixture is synthetic and breaks 7-4 in known ways; the
// check finds exactly those, and the loader itself reports none of them.
func TestLNClassCheckOnFixtures(t *testing.T) {
	_, m := loadEd21(t)
	var got []string
	for _, d := range m.CheckLNClasses() {
		got = append(got, d.String())
	}
	want := []string{
		"ED21LD0/LLN0: mandatory data object NamPlt (LPL) of LLN0 is missing",
		"ED21LD0/MMXU1: mandatory data object Beh (ENS) of MMXU is missing",
		"ED21LD0/GGIO1.AnIn3: data object of class WYE, IEC 61850-7-4 gives GGIO.AnIn the class MV",
		"ED21LD0/GAPC1: mandatory data object Beh (ENS) of GAPC is missing",
		"ED21LD0/LTRK1: mandatory data object Beh (ENS) of LTRK is missing",
		"ED21LD0/GGIO2.AnIn3: data object of class WYE, IEC 61850-7-4 gives GGIO.AnIn the class MV",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("CheckLNClasses =\n  %s\nwant\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	for _, d := range m.Diagnostics {
		if strings.Contains(d.Message, "7-4") || strings.Contains(d.Message, "mandatory data object") {
			t.Errorf("the loader reported a 7-4 finding: %s", d)
		}
	}

	// A conventional Edition 2 model conforms.
	m2, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	if d := m2.CheckLNClasses(); len(d) != 0 {
		t.Errorf("simpleIO: %v", d)
	}
}
