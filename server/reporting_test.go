package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

func TestReportingGIAndDataChange(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Discover a report control block on LLN0.
	lds, _ := c.LogicalDevices(ctx)
	ld := lds[0]
	names, _ := c.MMS().GetNameList(ctx, 0, ld)
	var rcbName string
	for _, n := range names {
		if len(n) > 8 && n[:8] == "LLN0$RP$" && countDollar(n) == 2 {
			rcbName = n[8:]
			break
		}
	}
	if rcbName == "" {
		t.Skip("no unbuffered RCB in demo model")
	}
	rcbRef := model.ObjectReference(ld + "/LLN0.RP." + rcbName)
	t.Logf("using RCB %s", rcbRef)

	rcb, err := c.GetRCB(ctx, rcbRef)
	if err != nil {
		t.Fatalf("GetRCB: %v", err)
	}
	if rcb.DataSet == "" {
		t.Fatalf("RCB has no dataset")
	}

	reports := make(chan *client.Report, 8)
	rcb.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptDataSetName | model.OptConfRev
	rcb.TrgOps = model.TrgDataChange | model.TrgGI
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) { reports <- r })
	if err != nil {
		t.Fatalf("EnableReporting: %v", err)
	}
	defer sub.Disable(context.Background())

	// General interrogation returns all members.
	if err := c.TriggerGI(ctx, rcb); err != nil {
		t.Fatalf("TriggerGI: %v", err)
	}
	select {
	case r := <-reports:
		if len(r.Entries) == 0 {
			t.Fatal("GI report had no entries")
		}
		t.Logf("GI report: %d entries, first = %s", len(r.Entries), r.Entries[0].Ref)
	case <-time.After(3 * time.Second):
		t.Fatal("no GI report received")
	}

	// A data change to a dataset member triggers a data-change report.
	first := firstDatasetMember(t, ctx, c, rcb)
	srv.Update(func(tx *server.Tx) {
		tx.SetBool(first, true)
	})
	select {
	case r := <-reports:
		found := false
		for _, e := range r.Entries {
			if e.Reason&model.ReasonDataChange != 0 {
				found = true
			}
		}
		if !found {
			t.Logf("data-change report entries: %+v", r.Entries)
		}
		t.Logf("dchg report: %d entries", len(r.Entries))
	case <-time.After(3 * time.Second):
		t.Fatal("no data-change report received")
	}
}

func firstDatasetMember(t *testing.T, ctx context.Context, c *client.Client, rcb *client.RCB) model.ObjectReference {
	t.Helper()
	ds, err := c.ReadDataSet(ctx, datasetRefFromMMS(rcb.DataSet))
	if err != nil || len(ds.Members) == 0 {
		t.Fatalf("dataset members: %v", err)
	}
	return ds.Members[0].Ref
}

// datasetRefFromMMS converts "LD/LN$DataSet" to "LD/LN.DataSet".
func datasetRefFromMMS(s string) model.ObjectReference {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			out = append(out, '.')
		} else {
			out = append(out, s[i])
		}
	}
	return model.ObjectReference(out)
}

func countDollar(s string) int {
	n := 0
	for _, c := range s {
		if c == '$' {
			n++
		}
	}
	return n
}
