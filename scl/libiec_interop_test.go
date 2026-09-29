package scl_test

import (
	"os"
	"testing"

	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
)

// TestLibiecServiceTrackingModel loads the service tracking model
// libiec61850 ships with its server_example_service_tracking, an Edition 2
// LTRK written independently of this library, and checks each tracking
// object against the template here: every attribute libiec61850 declares
// is in the template under the same constraint and type, and every
// attribute the template makes mandatory is in libiec61850's model. Set
// IEC61850_LIBIEC_LTRK_ICD to simpleIO_ltrk_tests.icd to enable it.
func TestLibiecServiceTrackingModel(t *testing.T) {
	path := os.Getenv("IEC61850_LIBIEC_LTRK_ICD")
	if path == "" {
		t.Skip("set IEC61850_LIBIEC_LTRK_ICD to libiec61850's simpleIO_ltrk_tests.icd")
	}
	s, err := scl.ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	m, err := scl.BuildModel(s)
	if err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
	var ltrk *model.LogicalNode
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			if ln.Class == "LTRK" {
				ltrk = ln
			}
		}
	}
	if ltrk == nil {
		t.Fatal("no LTRK in the model")
	}
	// The whole model conforms to the 7-4 classes templated here. Its LTRK
	// has an Edition 1 style Beh (INS), which the check accepts.
	if d := m.CheckLNClasses(); len(d) != 0 {
		t.Errorf("CheckLNClasses: %v", d)
	}
	tracked := map[string]model.CDC{"IncTrk": model.CDCINC, "BscTrk": model.CDCBSC}
	for _, do := range ltrk.Objects {
		if !model.KnownCDC(do.CDC) {
			t.Errorf("%s: class %q has no template", do.Name, do.CDC)
			continue
		}
		shape, optional := templateOptions(do)
		if cdc, ok := tracked[do.Name]; ok {
			shape = append(shape, model.WithTrackedControl(cdc))
		}
		// The description and namespace attributes (dU, cdcNs, cdcName,
		// dataNs) are general to every class and not in the tables.
		got := do.Attributes[:0:0]
		for _, da := range do.Attributes {
			switch da.Name {
			case "dU", "cdcNs", "cdcName", "dataNs":
				continue
			}
			got = append(got, da)
		}
		tmpl := model.NewDataObject(do.Name, model.CDC(do.CDC), append(shape, optional)...)
		compareToTemplate(t, "LTRK."+do.Name, got, tmpl.Attributes)
		for _, want := range model.NewDataObject(do.Name, model.CDC(do.CDC), shape...).Attributes {
			if do.Attribute(want.Name) == nil {
				t.Errorf("LTRK.%s.%s: mandatory here, not in libiec61850's model", do.Name, want.Name)
			}
		}
	}
}
