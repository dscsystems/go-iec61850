package client

import (
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"testing"
)

// Report DataRefs still identify sparse members when the dataset directory
// could not be fetched, for example when a peer's DatSet lacks the domain.
func TestReportDataRefsWithoutDirectory(t *testing.T) {
	inclusion := mms.NewBitString(3)
	inclusion.SetBit(2, true)
	ir := &mms.InformationReport{Values: []*mms.Value{
		mms.NewVisibleString("report"), (model.OptDataRef | model.OptReasonCode).Value(), inclusion,
		mms.NewVisibleString("IEDLD0/MMXU1$MX$PhV$phsA$cVal$mag$f"),
		mms.NewFloat32(230), model.ReasonGI.Value(),
	}}
	report := decodeReport(ir, &RCB{}, nil)
	if report == nil || len(report.Entries) != 1 {
		t.Fatalf("report=%+v", report)
	}
	e := report.Entries[0]
	if e.Index != 2 || e.Ref != "IEDLD0/MMXU1.PhV.phsA.cVal.mag.f" || e.FC != model.MX || e.Value.Float32() != 230 || e.Reason != model.ReasonGI {
		t.Fatalf("entry=%+v", e)
	}
}
