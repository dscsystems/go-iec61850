package client_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
)

// TestClientLogInterop queries the logs of the libiec61850 logging example
// server, which writes one entry at startup: an INT32 123 under the tag
// "simpleIOGenerioIO/GPIO1$ST$SPCSO1$stVal" (the example's own spelling),
// then a timestamp, each followed by its reason code. Enable with
// IEC61850_TEST_LOG_SERVER=host:port.
func TestClientLogInterop(t *testing.T) {
	addr := os.Getenv("IEC61850_TEST_LOG_SERVER")
	if addr == "" {
		t.Skip("set IEC61850_TEST_LOG_SERVER=host:port to run log interop tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	lds, err := c.LogicalDevices(ctx)
	if err != nil || len(lds) == 0 {
		t.Fatalf("LogicalDevices: %v %v", lds, err)
	}
	ld := lds[0]
	logRef := model.ObjectReference(ld + "/LLN0.EventLog")

	t.Run("Browse", func(t *testing.T) {
		names, err := c.LogicalNodeDirectory(ctx, model.ObjectReference(ld+"/LLN0"), client.ACSILog)
		if err != nil {
			t.Fatalf("LogicalNodeDirectory: %v", err)
		}
		if !contains(names, "EventLog") {
			t.Errorf("logs of LLN0 = %v, want EventLog among them", names)
		}
		entries, err := c.Browse(ctx, ld, client.ACSILog, client.ACSILCB)
		if err != nil {
			t.Fatalf("Browse: %v", err)
		}
		var log, lcb bool
		for _, e := range entries {
			log = log || (e.Class == client.ACSILog && e.Ref == logRef)
			lcb = lcb || (e.Class == client.ACSILCB && e.Ref == model.ObjectReference(ld+"/LLN0.LG.EventLog"))
		}
		if !log || !lcb {
			t.Errorf("Browse = %v, want the EventLog log and its control block", entries)
		}
	})

	var all []client.LogEntry
	t.Run("QueryByTime", func(t *testing.T) {
		all, err = c.QueryLogByTime(ctx, logRef, time.Now().Add(-time.Hour), time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("QueryLogByTime: %v", err)
		}
		if len(all) == 0 {
			t.Fatal("the log is empty; the example server writes an entry at startup")
		}
		first := all[0]
		if len(first.EntryID) != 8 {
			t.Errorf("EntryID %x is not 8 octets", first.EntryID)
		}
		if d := time.Since(first.OccurrenceTime); d < 0 || d > time.Hour {
			t.Errorf("occurrence time %v is not recent: the TimeOfDay decoding is off", first.OccurrenceTime)
		}
		var sawValue, sawReason bool
		for _, v := range first.Variables {
			if v.Tag == "simpleIOGenerioIO/GPIO1$ST$SPCSO1$stVal" && v.Value != nil && v.Value.Int64() == 123 {
				sawValue = true
			}
			sawReason = sawReason || v.Tag == "ReasonCode"
		}
		if !sawValue || !sawReason {
			t.Errorf("first entry variables = %+v, want the INT32 123 and a ReasonCode", first.Variables)
		}
	})

	t.Run("LCBAndQueryAfter", func(t *testing.T) {
		vals, err := c.MMS().Read(ctx, ld, "LLN0$LG$EventLog")
		if err != nil || len(vals) == 0 {
			t.Fatalf("read LCB: %v", err)
		}
		lcb := vals[0]
		// LogEna, LogRef, DatSet, OldEntrTm, NewEntrTm, OldEnt, NewEnt,
		// TrgOps, IntgPd: the IEC 61850-8-1 order this library serves too.
		if lcb.Len() != 9 {
			t.Fatalf("LCB has %d components, want 9", lcb.Len())
		}
		if got := lcb.Index(1).Text(); got != ld+"/LLN0$EventLog" {
			t.Errorf("LogRef = %q, want %s/LLN0$EventLog", got, ld)
		}
		oldEnt := lcb.Index(5).Bytes()
		if len(all) > 0 && !bytes.Equal(oldEnt, all[0].EntryID) {
			t.Errorf("OldEnt = %x, want the first entry %x", oldEnt, all[0].EntryID)
		}
		after, err := c.QueryLogAfter(ctx, logRef, lcb.Index(3).Time(), oldEnt)
		if err != nil {
			t.Fatalf("QueryLogAfter: %v", err)
		}
		for _, e := range after {
			if bytes.Equal(e.EntryID, oldEnt) {
				t.Errorf("QueryLogAfter returned the entry it was to start after")
			}
		}
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
