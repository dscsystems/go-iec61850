package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// These tests pin the report control block rules of IEC 61850-7-2 clause
// 17 against the demo model: EventsRCB01 is unbuffered and EventsBRCB01
// buffered, both over the Events dataset of four stVal members, both
// configured with TrgOps period only and a 50 ms buffer time.

const (
	demoLD  = "simpleIOGenericIO"
	urcb    = "LLN0$RP$EventsRCB01"
	brcb    = "LLN0$BR$EventsBRCB01"
	urcbRef = model.ObjectReference(demoLD + "/LLN0.RP.EventsRCB01")
	brcbRef = model.ObjectReference(demoLD + "/LLN0.BR.EventsBRCB01")
)

func member(n string) model.ObjectReference {
	return model.ObjectReference(demoLD + "/GGIO1." + n + ".stVal")
}

func dialDemo(t *testing.T, addr string, opts ...client.Option) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, append([]client.Option{client.WithTimeout(3 * time.Second)}, opts...)...)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// writeRCB writes one attribute of a control block and returns the
// server's per-item result.
func writeRCB(t *testing.T, c *client.Client, item, attr string, v *mms.Value) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := c.MMS().Write(ctx, demoLD, []string{item + "$" + attr}, []*mms.Value{v})
	if err != nil {
		t.Fatalf("write %s: %v", attr, err)
	}
	if len(res) > 0 {
		return res[0]
	}
	return nil
}

func readRCB(t *testing.T, c *client.Client, item, attr string) *mms.Value {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	vals, err := c.MMS().Read(ctx, demoLD, item+"$"+attr)
	if err != nil || len(vals) == 0 {
		t.Fatalf("read %s: %v", attr, err)
	}
	return vals[0]
}

// subscribe enables ref with the given triggers and fields and returns the
// stream of its reports.
func subscribe(t *testing.T, c *client.Client, ref model.ObjectReference, trg model.TrgOps, opt model.OptFlds, intg time.Duration) (<-chan *client.Report, *client.ReportSubscription) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rcb, err := c.GetRCB(ctx, ref)
	if err != nil {
		t.Fatalf("GetRCB: %v", err)
	}
	rcb.TrgOps, rcb.OptFlds, rcb.IntgPd = trg, opt, intg
	ch := make(chan *client.Report, 1024)
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) { ch <- r })
	if err != nil {
		t.Fatalf("EnableReporting: %v", err)
	}
	return ch, sub
}

func nextReport(t *testing.T, ch <-chan *client.Report) *client.Report {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("no report")
		return nil
	}
}

func noReport(t *testing.T, ch <-chan *client.Report, d time.Duration) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("unexpected report: seq %d, %d entries", r.SeqNum, len(r.Entries))
	case <-time.After(d):
	}
}

func setStVal(srv *server.Server, name string, on bool) {
	srv.Update(func(tx *server.Tx) { tx.SetBool(member(name), on) })
}

// The first client to write a block reserves it; nobody else may
// reconfigure, enable or interrogate it until the owner leaves.
func TestRCBReservedByFirstWriter(t *testing.T) {
	addr, _ := startServer(t)
	a, b := dialDemo(t, addr), dialDemo(t, addr)

	if err := writeRCB(t, a, urcb, "TrgOps", model.TrgDataChange.Value()); err != nil {
		t.Fatalf("owner write: %v", err)
	}
	if !readRCB(t, b, urcb, "Resv").Bool() {
		t.Error("Resv does not show the implicit reservation")
	}
	for _, w := range []struct {
		attr string
		v    *mms.Value
	}{
		{"TrgOps", model.TrgGI.Value()},
		{"RptEna", mms.NewBool(true)},
		{"Resv", mms.NewBool(false)},
	} {
		if err := writeRCB(t, b, urcb, w.attr, w.v); !errors.Is(err, mms.AccessTemporarilyUnavailable) {
			t.Errorf("second client writing %s: err = %v, want temporarily-unavailable", w.attr, err)
		}
	}

	// The reservation ends with the owner's association.
	a.Close()
	deadline := time.Now().Add(3 * time.Second)
	for writeRCB(t, b, urcb, "TrgOps", model.TrgGI.Value()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("reservation outlived its owner's association")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Settings are locked while the block is enabled; the server-maintained
// attributes are never writable.
func TestRCBSettingsLockedWhileEnabled(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr)
	_, sub := subscribe(t, c, urcbRef, model.TrgGI, model.OptSeqNum, 0)

	for _, w := range []struct {
		attr string
		v    *mms.Value
	}{
		{"IntgPd", mms.NewUint32(500)},
		{"DatSet", mms.NewVisibleString(demoLD + "/LLN0$Events2")},
		{"RptEna", mms.NewBool(true)},
	} {
		if err := writeRCB(t, c, urcb, w.attr, w.v); !errors.Is(err, mms.AccessTemporarilyUnavailable) {
			t.Errorf("writing %s while enabled: err = %v, want temporarily-unavailable", w.attr, err)
		}
	}
	sub.Disable(context.Background())
	for _, attr := range []string{"ConfRev", "SqNum"} {
		if err := writeRCB(t, c, urcb, attr, readRCB(t, c, urcb, attr)); !errors.Is(err, mms.AccessObjectAccessDenied) {
			t.Errorf("writing %s: err = %v, want object-access-denied", attr, err)
		}
	}
}

// A dataset reference must exist, and changing it changes ConfRev.
func TestRCBDatSetValidatedAndCountedInConfRev(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr)

	if err := writeRCB(t, c, urcb, "DatSet", mms.NewVisibleString(demoLD+"/LLN0$NoSuchSet")); !errors.Is(err, mms.AccessObjectValueInvalid) {
		t.Errorf("unknown dataset: err = %v, want object-value-invalid", err)
	}
	before := readRCB(t, c, urcb, "ConfRev").Uint64()
	if err := writeRCB(t, c, urcb, "DatSet", mms.NewVisibleString(demoLD+"/LLN0$Events2")); err != nil {
		t.Fatalf("DatSet: %v", err)
	}
	if after := readRCB(t, c, urcb, "ConfRev").Uint64(); after != before+1 {
		t.Errorf("ConfRev %d -> %d, want an increment", before, after)
	}
}

// Only the triggers in TrgOps produce reports; GI reads FALSE once done.
func TestRCBTriggerOptionsGateReports(t *testing.T) {
	addr, srv := startServer(t)
	c := dialDemo(t, addr)
	ch, _ := subscribe(t, c, urcbRef, model.TrgGI, model.OptReasonCode, 0)

	setStVal(srv, "SPCSO1", true)
	noReport(t, ch, 300*time.Millisecond) // dchg is not a trigger

	if err := writeRCB(t, c, urcb, "GI", mms.NewBool(true)); err != nil {
		t.Fatalf("GI: %v", err)
	}
	r := nextReport(t, ch)
	if len(r.Entries) != 4 || r.Entries[0].Reason != model.ReasonGI {
		t.Errorf("GI report: %d entries, reason %v", len(r.Entries), r.Entries[0].Reason)
	}
	if readRCB(t, c, urcb, "GI").Bool() {
		t.Error("GI still reads TRUE after the interrogation")
	}
}

// A quality change is reported as qchg, and rewriting an unchanged value
// is no data change.
func TestRCBQualityChangeReportsQchg(t *testing.T) {
	addr, srv := startServer(t)
	c := dialDemo(t, addr)
	// Events2 names whole data objects, so q is a member too.
	if err := writeRCB(t, c, urcb, "DatSet", mms.NewVisibleString(demoLD+"/LLN0$Events2")); err != nil {
		t.Fatal(err)
	}
	ch, _ := subscribe(t, c, urcbRef, model.TrgDataChange|model.TrgQualityChange, model.OptReasonCode, 0)

	q := model.ObjectReference(demoLD + "/GGIO1.SPCSO1.q")
	srv.Update(func(tx *server.Tx) {
		tx.SetQuality(q, model.ST, model.QualityGood.WithValidity(model.ValidityInvalid))
	})
	r := nextReport(t, ch)
	if len(r.Entries) != 1 || r.Entries[0].Reason != model.ReasonQualityChange {
		t.Fatalf("quality change: %d entries, reason %v, want one qchg", len(r.Entries), r.Entries[0].Reason)
	}

	setStVal(srv, "SPCSO2", false) // already false
	noReport(t, ch, 300*time.Millisecond)
}

// An unbuffered block's SqNum is INT8U: it wraps to 0 after 255, and the
// attribute follows the reports.
func TestURCBSqNumWrapsAt256(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr)
	ch, _ := subscribe(t, c, urcbRef, model.TrgGI, model.OptSeqNum, 0)

	for i := 0; i <= 256; i++ {
		if err := writeRCB(t, c, urcb, "GI", mms.NewBool(true)); err != nil {
			t.Fatalf("GI %d: %v", i, err)
		}
		if r := nextReport(t, ch); r.SeqNum != uint32(i%256) {
			t.Fatalf("report %d has SeqNum %d, want %d", i, r.SeqNum, i%256)
		}
	}
	if got := readRCB(t, c, urcb, "SqNum"); got.Uint64() != 1 {
		t.Errorf("SqNum attribute = %d, want 1 (the next report's)", got.Uint64())
	}
}

// Reports a buffered block has delivered are not delivered again when it
// is re-enabled, and a re-enabled block numbers from zero.
func TestBRCBDoesNotReplayDeliveredReports(t *testing.T) {
	addr, srv := startServer(t)
	c := dialDemo(t, addr)
	ch, sub := subscribe(t, c, brcbRef, model.TrgDataChange, model.OptSeqNum|model.OptEntryID, 0)

	setStVal(srv, "SPCSO1", true)
	nextReport(t, ch)
	sub.Disable(context.Background())

	ch2, _ := subscribe(t, c, brcbRef, model.TrgDataChange, model.OptSeqNum|model.OptEntryID, 0)
	noReport(t, ch2, 400*time.Millisecond)

	setStVal(srv, "SPCSO1", false)
	if r := nextReport(t, ch2); r.SeqNum != 0 {
		t.Errorf("first report after re-enable has SeqNum %d, want 0", r.SeqNum)
	}
}

// Resynchronisation needs an EntryID the buffer holds; all zeros asks for
// the whole buffer and is no overflow.
func TestBRCBResyncRules(t *testing.T) {
	addr, srv := startServer(t)
	c := dialDemo(t, addr)
	if err := writeRCB(t, c, brcb, "TrgOps", model.TrgDataChange.Value()); err != nil {
		t.Fatal(err)
	}
	setStVal(srv, "SPCSO1", true)
	setStVal(srv, "SPCSO2", true)
	time.Sleep(150 * time.Millisecond) // let the buffer time close

	bogus := mms.NewOctetString([]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa})
	if err := writeRCB(t, c, brcb, "EntryID", bogus); !errors.Is(err, mms.AccessObjectValueInvalid) {
		t.Errorf("unknown EntryID: err = %v, want object-value-invalid", err)
	}
	if err := writeRCB(t, c, brcb, "EntryID", mms.NewOctetString(make([]byte, 8))); err != nil {
		t.Fatalf("zero EntryID: %v", err)
	}
	ch, _ := subscribe(t, c, brcbRef, model.TrgDataChange, model.OptEntryID|model.OptBufOvfl, 0)
	r := nextReport(t, ch)
	if r.BufOvfl {
		t.Error("resync from the start claims a buffer overflow")
	}
}

// An empty RptID means the block's own reference, which the client
// matches its reports against.
func TestRCBEmptyRptIDUsesReference(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr)
	if err := writeRCB(t, c, urcb, "RptID", mms.NewVisibleString("")); err != nil {
		t.Fatal(err)
	}
	ch, _ := subscribe(t, c, urcbRef, model.TrgGI, model.OptSeqNum, 0)
	if err := writeRCB(t, c, urcb, "GI", mms.NewBool(true)); err != nil {
		t.Fatal(err)
	}
	if r := nextReport(t, ch); r.RptID != demoLD+"/"+urcb {
		t.Errorf("RptID = %q, want %q", r.RptID, demoLD+"/"+urcb)
	}
}

// Integrity reports need the integrity trigger as well as a period.
func TestRCBIntegrityNeedsTrigger(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr)
	ch, sub := subscribe(t, c, urcbRef, model.TrgGI, model.OptReasonCode, 100*time.Millisecond)
	noReport(t, ch, 400*time.Millisecond)
	sub.Disable(context.Background())

	ch2, _ := subscribe(t, c, urcbRef, model.TrgGI|model.TrgIntegrity, model.OptReasonCode, 100*time.Millisecond)
	if r := nextReport(t, ch2); r.Entries[0].Reason != model.ReasonIntegrity {
		t.Errorf("reason %v, want integrity", r.Entries[0].Reason)
	}
}

// Within the buffer time, changes of different members share one report;
// a member changing twice closes the window so neither value is lost.
func TestRCBBufTmCollectsEvents(t *testing.T) {
	addr, srv := startServer(t)
	c := dialDemo(t, addr)
	if err := writeRCB(t, c, urcb, "BufTm", mms.NewUint32(300)); err != nil {
		t.Fatal(err)
	}
	ch, _ := subscribe(t, c, urcbRef, model.TrgDataChange, model.OptReasonCode, 0)

	setStVal(srv, "SPCSO1", true)
	setStVal(srv, "SPCSO2", true)
	if r := nextReport(t, ch); len(r.Entries) != 2 {
		t.Errorf("one window: %d entries, want 2", len(r.Entries))
	}

	setStVal(srv, "SPCSO3", true)
	setStVal(srv, "SPCSO3", false)
	first, second := nextReport(t, ch), nextReport(t, ch)
	if !first.Entries[0].Value.Bool() || second.Entries[0].Value.Bool() {
		t.Errorf("repeated member: values %v then %v, want true then false",
			first.Entries[0].Value.Bool(), second.Entries[0].Value.Bool())
	}
}

// withMaxPDU proposes a small maximum MMS PDU size.
func withMaxPDU(n int32) client.Option {
	return func(o *mms.Options) {
		init := mms.DefaultInitiate()
		init.LocalDetail = n
		o.Initiate = &init
	}
}

// A report larger than the association's PDU size is segmented (IEC
// 61850-8-1): one SqNum, SubSeqNum counting up, MoreSegmentsFollow on all
// but the last.
func TestReportSegmentedToMaxPDU(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr, withMaxPDU(200))
	ch, _ := subscribe(t, c, urcbRef, model.TrgGI, model.OptSeqNum|model.OptDataRef|model.OptReasonCode|model.OptDataSetName, 0)
	if err := writeRCB(t, c, urcb, "GI", mms.NewBool(true)); err != nil {
		t.Fatal(err)
	}
	var segs []*client.Report
	for {
		r := nextReport(t, ch)
		segs = append(segs, r)
		if !r.MoreFollows {
			break
		}
	}
	if len(segs) < 2 {
		t.Fatalf("report was not segmented (%d segment)", len(segs))
	}
	entries := 0
	for i, s := range segs {
		if s.SeqNum != segs[0].SeqNum || s.SubSeqNum != uint32(i) {
			t.Errorf("segment %d: SeqNum %d SubSeqNum %d", i, s.SeqNum, s.SubSeqNum)
		}
		entries += len(s.Entries)
	}
	if entries != 4 {
		t.Errorf("segments carry %d entries in all, want 4", entries)
	}
}

// Operating a control reports the status change like any other.
func TestOperateReportsStatusChange(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr)
	ch, _ := subscribe(t, c, urcbRef, model.TrgDataChange, model.OptReasonCode, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	co, err := c.ControlFor(ctx, model.ObjectReference(demoLD+"/GGIO1.SPCSO1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("Operate: %v", err)
	}
	r := nextReport(t, ch)
	if len(r.Entries) != 1 || r.Entries[0].Index != 0 || !r.Entries[0].Value.Bool() {
		t.Errorf("report after operate: %+v", r.Entries)
	}
}
