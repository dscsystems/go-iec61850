package server_test

import (
	"context"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// cLogLD is the logical device the libiec61850 log client example is
// written against: it addresses "TestIEDGenericIO/LLN0$EventLog" and the
// log control block "TestIEDGenericIO/LLN0.EventLog".
const cLogLD = "TestIEDGenericIO"

// cLogModel is the part of the libiec61850 logging example's model the C
// log client uses: LLN0 with the log EventLog and the log control block of
// the same name over a dataset of status points, logging off until the
// client enables it.
func cLogModel() *model.Model {
	spc := func(name string) *model.DataObject {
		return &model.DataObject{Name: name, Attributes: []*model.DataAttribute{
			{Name: "stVal", FC: model.ST, Kind: mms.TypeBoolean, Value: mms.NewBool(false),
				TrgOps: model.TrgDataChange},
		}}
	}
	ggio := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{spc("SPCSO1"), spc("SPCSO2")}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0", Logs: []string{"EventLog"},
		DataSets: []*model.DataSet{{Name: "Events", Entries: []model.FCDA{
			{Ref: cLogLD + "/GGIO1.SPCSO1.stVal", FC: model.ST},
			{Ref: cLogLD + "/GGIO1.SPCSO2.stVal", FC: model.ST},
		}}},
		LogControls: []*model.LogControl{{
			Name: "EventLog", DataSet: "Events", LogName: "EventLog",
			TrgOps: model.TrgDataChange, ReasonCode: true,
		}},
	}
	ld := &model.LogicalDevice{Name: cLogLD, Inst: "GenericIO", Nodes: []*model.LogicalNode{lln0, ggio}}
	return &model.Model{Name: "TestIED", Devices: []*model.LogicalDevice{ld}}
}

// TestCLogClientInterop runs the libiec61850 log client example against
// our server: it lists the logs of LLN0, enables the log control block,
// reads it for the oldest entry and queries the log after that entry. Set
// IEC61850_C_LOG_CLIENT to the client_example_log binary to enable it.
func TestCLogClientInterop(t *testing.T) {
	bin := os.Getenv("IEC61850_C_LOG_CLIENT")
	if bin == "" {
		t.Skip("set IEC61850_C_LOG_CLIENT to the libiec61850 client_example_log binary")
	}
	addr, srv := startServerWith(t, cLogModel())
	host, port, _ := strings.Cut(addr, ":")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The client waits a second after enabling the log; change a status
	// point meanwhile so the log has entries for it to query.
	go func() {
		ref := model.ObjectReference(cLogLD + "/GGIO1.SPCSO1.stVal")
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		on := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				on = !on
				srv.Update(func(tx *server.Tx) { tx.SetBool(ref, on) })
			}
		}
	}()

	out, err := exec.CommandContext(ctx, "stdbuf", "-oL", bin, host, port).CombinedOutput()
	t.Logf("C log client output:\n%s", out)
	if err != nil {
		t.Fatalf("C log client: %v", err)
	}
	got := string(out)

	if !regexp.MustCompile(`(?m)^\s+EventLog$`).MatchString(got) {
		t.Errorf("the C client did not find EventLog among the logs of LLN0")
	}
	if !strings.Contains(got, "Enabled log.") {
		t.Errorf("the C client could not enable the log")
	}
	if strings.Contains(got, "Read LCB failed") {
		t.Fatalf("the C client could not read the log control block")
	}
	m := regexp.MustCompile(`Received (\d+) log entries`).FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("the C client's log query failed")
	}
	// The query is after the oldest entry, and the point changed about ten
	// times while the client waited.
	if n, _ := strconv.Atoi(m[1]); n < 2 {
		t.Errorf("the C client received %d entries, want the ones logged while it waited", n)
	}
	if !strings.Contains(got, "variable-tag: "+cLogLD+"/GGIO1$ST$SPCSO1$stVal") {
		t.Errorf("no logged value under its data reference")
	}
	if !strings.Contains(got, "variable-tag: ReasonCode") {
		t.Errorf("no reason code after the logged value")
	}
}
