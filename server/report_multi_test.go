package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
)

// Two report control blocks enabled on one connection must both deliver.
// The report handler used to be a single slot on mms.Conn, so the second
// EnableReporting silently unsubscribed the first.
func TestMultipleReportSubscriptionsCoexist(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	lds, _ := c.LogicalDevices(ctx)
	ld := lds[0]
	names, _ := c.MMS().GetNameList(ctx, 0, ld)

	// Collect two unbuffered RCBs that have a dataset to report on. Their
	// RptIDs must differ: reports carry no other identification, so RCBs
	// sharing an RptID cannot be told apart by a subscriber.
	var rcbs []*client.RCB
	seen := map[string]bool{}
	for _, n := range names {
		if !strings.HasPrefix(n, "LLN0$RP$") || countDollar(n) != 2 {
			continue
		}
		rcb, err := c.GetRCB(ctx, model.ObjectReference(ld+"/LLN0.RP."+n[len("LLN0$RP$"):]))
		if err != nil || rcb.DataSet == "" || rcb.RptID == "" || seen[rcb.RptID] {
			continue
		}
		seen[rcb.RptID] = true
		rcbs = append(rcbs, rcb)
		if len(rcbs) == 2 {
			break
		}
	}
	if len(rcbs) < 2 {
		t.Skip("demo model has fewer than two unbuffered RCBs with distinct RptIDs")
	}

	chans := make([]chan *client.Report, len(rcbs))
	for i, rcb := range rcbs {
		rcb.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptDataSetName | model.OptConfRev
		rcb.TrgOps = model.TrgDataChange | model.TrgGI
		ch := make(chan *client.Report, 4)
		chans[i] = ch
		sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) { ch <- r })
		if err != nil {
			t.Fatalf("EnableReporting %s: %v", rcb.Ref, err)
		}
		defer sub.Disable(context.Background())
	}

	// Interrogate both; each subscription must see its own report and only
	// its own.
	for i, rcb := range rcbs {
		if err := c.TriggerGI(ctx, rcb); err != nil {
			t.Fatalf("TriggerGI %s: %v", rcb.Ref, err)
		}
		select {
		case r := <-chans[i]:
			if r.RptID != rcb.RptID {
				t.Errorf("subscription %d got RptID %q, want %q", i, r.RptID, rcb.RptID)
			}
			if len(r.Entries) == 0 {
				t.Errorf("subscription %d: GI report had no entries", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("subscription %d (%s) received no GI report", i, rcb.Ref)
		}
		for j := range chans {
			if j == i {
				continue
			}
			select {
			case r := <-chans[j]:
				t.Errorf("subscription %d received report %q meant for %d", j, r.RptID, i)
			default:
			}
		}
	}
}
