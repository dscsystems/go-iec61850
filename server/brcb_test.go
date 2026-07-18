package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

func TestBufferedReporting(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Find a buffered RCB.
	lds, _ := c.LogicalDevices(ctx)
	ld := lds[0]
	names, _ := c.MMS().GetNameList(ctx, 0, ld)
	var brcb string
	for _, n := range names {
		if len(n) > 8 && n[:8] == "LLN0$BR$" && countDollar(n) == 2 {
			brcb = n[8:]
			break
		}
	}
	if brcb == "" {
		t.Skip("no buffered RCB in demo model")
	}
	ref := model.ObjectReference(ld + "/LLN0.BR." + brcb)
	t.Logf("using BRCB %s", ref)

	rcb, err := c.GetRCB(ctx, ref)
	if err != nil {
		t.Fatalf("GetRCB: %v", err)
	}
	if !rcb.Buffered {
		t.Fatalf("expected buffered RCB")
	}

	// Change a dataset member BEFORE enabling: the BRCB must buffer it.
	member := firstDatasetMember(t, ctx, c, rcb)
	srv.Update(func(tx *server.Tx) { tx.SetBool(member, true) })
	srv.Update(func(tx *server.Tx) { tx.SetBool(member, false) })

	reports := make(chan *client.Report, 16)
	rcb.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptEntryID | model.OptTimeOfEntry
	rcb.TrgOps = model.TrgDataChange
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) { reports <- r })
	if err != nil {
		t.Fatalf("EnableReporting: %v", err)
	}
	defer sub.Disable(context.Background())

	// The two buffered reports should arrive on enable, each with an EntryID.
	got := 0
	var lastEntry []byte
	deadline := time.After(3 * time.Second)
loop:
	for got < 2 {
		select {
		case r := <-reports:
			got++
			if len(r.EntryID) == 0 {
				t.Errorf("buffered report %d missing EntryID", got)
			} else {
				lastEntry = r.EntryID
			}
		case <-deadline:
			break loop
		}
	}
	if got < 2 {
		t.Fatalf("expected 2 buffered reports on enable, got %d", got)
	}
	t.Logf("received %d buffered reports; last EntryID = %x", got, lastEntry)

	// A live change after enable is delivered immediately.
	srv.Update(func(tx *server.Tx) { tx.SetBool(member, true) })
	var liveEntry []byte
	select {
	case r := <-reports:
		if len(r.Entries) == 0 {
			t.Fatal("live report had no entries")
		}
		liveEntry = r.EntryID
	case <-time.After(3 * time.Second):
		t.Fatal("no live report after enable")
	}

	// Resync: disable, buffer a new change, then re-enable resuming after
	// the last-seen EntryID. Only the new report should arrive.
	sub.Disable(context.Background())
	drain(reports)
	srv.Update(func(tx *server.Tx) { tx.SetBool(member, false) })

	rcb2, err := c.GetRCB(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	rcb2.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptEntryID
	rcb2.ResyncEntryID = liveEntry
	sub2, err := c.EnableReporting(ctx, rcb2, func(r *client.Report) { reports <- r })
	if err != nil {
		t.Fatalf("resync EnableReporting: %v", err)
	}
	defer sub2.Disable(context.Background())

	select {
	case r := <-reports:
		t.Logf("resync delivered report with EntryID %x (%d entries)", r.EntryID, len(r.Entries))
	case <-time.After(3 * time.Second):
		t.Fatal("no report after resync")
	}
}

func drain(ch chan *client.Report) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
