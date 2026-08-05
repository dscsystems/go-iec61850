package scl

import (
	"strings"
	"testing"
)

// maxBufSCL is a minimal document with one buffered and one unbuffered
// report control block, and a report-buffer capacity declared where the
// caller asks for it.
func maxBufSCL(iedServices, apServices string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="maxbuf"/>
  <IED name="TESTIED">
    ` + iedServices + `
    <AccessPoint name="AP1">
      ` + apServices + `
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0type">
            <DataSet name="Events">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
            </DataSet>
            <ReportControl name="BufRCB" rptID="buf" datSet="Events" confRev="1" buffered="true" bufTime="50">
              <TrgOps dchg="true"/>
              <RptEnabled max="1"/>
            </ReportControl>
            <ReportControl name="UnbufRCB" rptID="unbuf" datSet="Events" confRev="1" buffered="false" bufTime="50">
              <TrgOps dchg="true"/>
              <RptEnabled max="1"/>
            </ReportControl>
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
      <DA name="q" bType="Quality" fc="ST"/>
    </DOType>
  </DataTypeTemplates>
</SCL>`
}

func loadReportControls(t *testing.T, doc string) map[string]int {
	t.Helper()
	s, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	m, err := BuildModel(s)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	out := map[string]int{}
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, rc := range ln.ReportControls {
				out[rc.Name] = rc.MaxQueueSize
			}
		}
	}
	return out
}

// Services/ConfReportControl@maxBuf is the device's report-buffer capacity,
// and it has to reach the buffered control blocks — the server buffered a
// library constant instead.
func TestConfReportControlMaxBuf(t *testing.T) {
	const services = `<Services><ConfReportControl max="8" maxBuf="64"/></Services>`

	t.Run("declared on the IED", func(t *testing.T) {
		rcs := loadReportControls(t, maxBufSCL(services, ""))
		if got := rcs["BufRCB"]; got != 64 {
			t.Errorf("buffered RCB queue size = %d, want 64", got)
		}
		// An unbuffered block has no queue to size.
		if got := rcs["UnbufRCB"]; got != 0 {
			t.Errorf("unbuffered RCB queue size = %d, want 0", got)
		}
	})

	t.Run("declared on the access point", func(t *testing.T) {
		rcs := loadReportControls(t, maxBufSCL("", services))
		if got := rcs["BufRCB"]; got != 64 {
			t.Errorf("buffered RCB queue size = %d, want 64", got)
		}
	})

	t.Run("the access point wins", func(t *testing.T) {
		rcs := loadReportControls(t, maxBufSCL(
			`<Services><ConfReportControl maxBuf="16"/></Services>`,
			`<Services><ConfReportControl maxBuf="99"/></Services>`))
		if got := rcs["BufRCB"]; got != 99 {
			t.Errorf("buffered RCB queue size = %d, want the access point's 99", got)
		}
	})

	t.Run("undeclared leaves it to the server", func(t *testing.T) {
		rcs := loadReportControls(t, maxBufSCL("", ""))
		if got := rcs["BufRCB"]; got != 0 {
			t.Errorf("buffered RCB queue size = %d, want 0 (server default)", got)
		}
	})

	t.Run("a zero capacity is no capacity", func(t *testing.T) {
		rcs := loadReportControls(t, maxBufSCL(
			`<Services><ConfReportControl max="8" maxBuf="0"/></Services>`, ""))
		if got := rcs["BufRCB"]; got != 0 {
			t.Errorf("buffered RCB queue size = %d, want 0", got)
		}
	})
}
