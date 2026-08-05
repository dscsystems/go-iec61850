package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// doFCDAModel puts a data object in the dataset (an FCDA with no daName)
// alongside a leaf, so both member forms are exercised by one update.
func doFCDAModel() *model.Model {
	ggio := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{
		model.NewDataObject("Ind1", model.CDCSPS),
		model.NewDataObject("Ind2", model.CDCSPS),
		// A sibling whose name extends the first one's: a prefix match
		// that ignored the separator would confuse the two.
		model.NewDataObject("Ind1Extra", model.CDCSPS),
	}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0",
		DataSets: []*model.DataSet{{
			Name: "Events",
			Entries: []model.FCDA{
				{Ref: "DOIED/GGIO1.Ind1", FC: model.ST},       // the whole object
				{Ref: "DOIED/GGIO1.Ind2.stVal", FC: model.ST}, // one leaf
			},
		}},
		ReportControls: []*model.ReportControl{{
			Name:       "EventsRCB",
			RptID:      "Events",
			DataSet:    "Events",
			ConfRev:    1,
			TrgOps:     model.TrgDataChange | model.TrgGI,
			OptFlds:    model.OptSeqNum | model.OptReasonCode | model.OptDataSetName,
			RptEnabled: 1,
		}},
	}
	ld := &model.LogicalDevice{Name: "DOIED", Inst: "LD0", Nodes: []*model.LogicalNode{lln0, ggio}}
	return &model.Model{Name: "DOIED", Devices: []*model.LogicalDevice{ld}}
}

func startDOFCDAServer(t *testing.T) (string, *server.Server) {
	t.Helper()
	srv := server.New(doFCDAModel())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), srv
}

// enableEvents subscribes to the RCB and returns the report channel.
func enableEvents(t *testing.T, ctx context.Context, c *client.Client) chan *client.Report {
	t.Helper()
	rcb, err := c.GetRCB(ctx, "DOIED/LLN0.RP.EventsRCB01")
	if err != nil {
		t.Fatalf("GetRCB: %v", err)
	}
	reports := make(chan *client.Report, 8)
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) {
		select {
		case reports <- r:
		default:
		}
	})
	if err != nil {
		t.Fatalf("EnableReporting: %v", err)
	}
	t.Cleanup(func() { sub.Disable(context.Background()) })
	return reports
}

func waitReport(t *testing.T, reports chan *client.Report, what string) *client.Report {
	t.Helper()
	select {
	case r := <-reports:
		return r
	case <-time.After(3 * time.Second):
		t.Fatalf("no report for %s", what)
		return nil
	}
}

// A dataset member naming a data object must be reported when an attribute
// below it changes. The inclusion test only looked at a member's ancestors,
// so a DO-level member never fired: Update records the leaf it wrote, and
// the leaf is a descendant of the member, not an ancestor.
func TestDataChangeReportsDOLevelMember(t *testing.T) {
	addr, srv := startDOFCDAServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reports := enableEvents(t, ctx, c)

	// A change below the object-level member.
	srv.Update(func(tx *server.Tx) { tx.SetBool("DOIED/GGIO1.Ind1.stVal", true) })

	r := waitReport(t, reports, "a change under the data object member")
	if len(r.Entries) != 1 {
		t.Fatalf("report carried %d entries, want the one member that changed", len(r.Entries))
	}
	e := r.Entries[0]
	if e.Index != 0 {
		t.Errorf("entry index = %d, want 0 (the data object member)", e.Index)
	}
	if e.Reason&model.ReasonDataChange == 0 {
		t.Errorf("entry reason = %s, want a data change", e.Reason)
	}
	// The value of a data object member is the object: its attributes.
	if e.Value == nil || e.Value.Type() != mms.TypeStructure {
		t.Fatalf("entry value = %v, want the data object's structure", e.Value)
	}
	if e.Value.Index(0) == nil || !e.Value.Index(0).Bool() {
		t.Errorf("reported stVal = %v, want the new value true", e.Value.Index(0))
	}
}

// The leaf form still works, and the two members stay independent.
func TestDataChangeReportsLeafMember(t *testing.T) {
	addr, srv := startDOFCDAServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reports := enableEvents(t, ctx, c)

	srv.Update(func(tx *server.Tx) { tx.SetBool("DOIED/GGIO1.Ind2.stVal", true) })
	r := waitReport(t, reports, "a change to the leaf member")
	if len(r.Entries) != 1 || r.Entries[0].Index != 1 {
		t.Fatalf("report entries = %+v, want only the leaf member (index 1)", r.Entries)
	}
	if v := r.Entries[0].Value; v == nil || !v.Bool() {
		t.Errorf("reported value = %v, want true", v)
	}

	// Both at once: both members are included.
	srv.Update(func(tx *server.Tx) {
		tx.SetBool("DOIED/GGIO1.Ind1.stVal", true)
		tx.SetBool("DOIED/GGIO1.Ind2.stVal", false)
	})
	r = waitReport(t, reports, "a change to both members")
	if len(r.Entries) != 2 {
		t.Fatalf("report carried %d entries, want both members", len(r.Entries))
	}
}

// A change under a different object must not be attributed to a member
// whose name it merely starts with.
func TestDataChangeDoesNotMatchNamePrefix(t *testing.T) {
	addr, srv := startDOFCDAServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reports := enableEvents(t, ctx, c)

	// Ind1Extra is not below Ind1, and is not in the dataset at all.
	srv.Update(func(tx *server.Tx) { tx.SetBool("DOIED/GGIO1.Ind1Extra.stVal", true) })
	select {
	case r := <-reports:
		t.Fatalf("a change to Ind1Extra reported %d entries against the dataset", len(r.Entries))
	case <-time.After(500 * time.Millisecond):
	}

	// And the real member still reports afterwards.
	srv.Update(func(tx *server.Tx) { tx.SetBool("DOIED/GGIO1.Ind1.stVal", true) })
	if r := waitReport(t, reports, "the data object member"); len(r.Entries) != 1 {
		t.Errorf("report carried %d entries, want 1", len(r.Entries))
	}
}
