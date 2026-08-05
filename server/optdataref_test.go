package server_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// rcbOnLLN0 finds an unbuffered report control block with a dataset.
func rcbOnLLN0(t *testing.T, ctx context.Context, c *client.Client) *client.RCB {
	t.Helper()
	lds, _ := c.LogicalDevices(ctx)
	if len(lds) == 0 {
		t.Fatal("no logical devices")
	}
	found, err := c.Browse(ctx, lds[0], client.ACSIURCB)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range found {
		rcb, err := c.GetRCB(ctx, e.Ref)
		if err == nil && rcb.DataSet != "" {
			return rcb
		}
	}
	t.Skip("no unbuffered RCB with a dataset")
	return nil
}

// A report whose OptFlds claims data-reference must actually carry one
// reference string per included member, before the values. The server used
// to echo the bit and send nothing, which shifts every field after the
// inclusion bitstring for any client that believes the flags.
func TestReportDataReferencesArePresent(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rcb := rcbOnLLN0(t, ctx, c)

	// The members, in dataset order, as the report should name them.
	ds, err := c.ReadDataSet(ctx, datasetRefFromMMS(rcb.DataSet))
	if err != nil {
		t.Fatalf("ReadDataSet: %v", err)
	}
	var wantRefs []string
	for _, m := range ds.Members {
		domain, item := m.Ref.ToMMS(m.FC)
		wantRefs = append(wantRefs, domain+"/"+item)
	}
	if len(wantRefs) == 0 {
		t.Skip("dataset has no members")
	}

	// Capture the undecoded report alongside the decoded one.
	raw := make(chan []*mms.Value, 4)
	remove := c.MMS().OnInformationReport(func(ir *mms.InformationReport) {
		select {
		case raw <- ir.Values:
		default:
		}
	})
	defer remove()

	rcb.OptFlds = model.OptSeqNum | model.OptDataSetName | model.OptConfRev |
		model.OptDataRef | model.OptReasonCode
	rcb.TrgOps = model.TrgDataChange | model.TrgGI
	reports := make(chan *client.Report, 4)
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) { reports <- r })
	if err != nil {
		t.Fatalf("EnableReporting: %v", err)
	}
	defer sub.Disable(context.Background())

	if err := c.TriggerGI(ctx, rcb); err != nil {
		t.Fatalf("TriggerGI: %v", err)
	}

	var values []*mms.Value
	select {
	case values = <-raw:
	case <-time.After(5 * time.Second):
		t.Fatal("no report received")
	}

	// RptID, OptFlds, SeqNum, DatSet, ConfRev, inclusion, then the
	// references.
	const inclusionAt = 5
	if len(values) <= inclusionAt {
		t.Fatalf("report has %d fields, want more than %d", len(values), inclusionAt)
	}
	opt := model.OptFldsFromValue(values[1])
	if opt&model.OptDataRef == 0 {
		t.Fatal("the report's OptFlds does not claim data-reference")
	}
	inclusion := values[inclusionAt]
	if inclusion.Type() != mms.TypeBitString {
		t.Fatalf("field %d is %s, want the inclusion bit string", inclusionAt, inclusion.Type())
	}
	var included int
	for b := 0; b < inclusion.BitLen(); b++ {
		if inclusion.Bit(b) {
			included++
		}
	}
	if included != len(wantRefs) {
		t.Fatalf("GI included %d of %d members", included, len(wantRefs))
	}

	refs := values[inclusionAt+1 : inclusionAt+1+included]
	for i, v := range refs {
		if v.Type() != mms.TypeVisibleString {
			t.Fatalf("data reference %d is %s, want a visible string", i, v.Type())
		}
		if v.Text() != wantRefs[i] {
			t.Errorf("data reference %d = %q, want %q", i, v.Text(), wantRefs[i])
		}
		if !strings.Contains(v.Text(), "/") || !strings.Contains(v.Text(), "$") {
			t.Errorf("data reference %q is not in MMS form LD/LN$FC$DA", v.Text())
		}
	}

	// And the fields after them still line up: the decoded report must
	// carry the same members with usable values.
	select {
	case rep := <-reports:
		if len(rep.Entries) != included {
			t.Fatalf("decoded %d entries, want %d", len(rep.Entries), included)
		}
		for i, e := range rep.Entries {
			if e.Value == nil {
				t.Errorf("entry %d (%s) has no value", i, e.Ref)
			}
			if e.Reason == 0 {
				t.Errorf("entry %d (%s) has no reason code: the trailing fields are misaligned", i, e.Ref)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("report did not decode")
	}
}

// OptFlds a report cannot honour must not be echoed either: an unbuffered
// report has no BufOvfl or EntryID, and this server never segments.
func TestReportOptFldsDescribeTheReport(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rcb := rcbOnLLN0(t, ctx, c)

	raw := make(chan []*mms.Value, 4)
	remove := c.MMS().OnInformationReport(func(ir *mms.InformationReport) {
		select {
		case raw <- ir.Values:
		default:
		}
	})
	defer remove()

	// Ask for everything, including fields an unbuffered report has not
	// got and segmentation the server does not do.
	rcb.OptFlds = model.OptSeqNum | model.OptTimeOfEntry | model.OptReasonCode |
		model.OptDataSetName | model.OptDataRef | model.OptBufOvfl |
		model.OptEntryID | model.OptConfRev | model.OptSegmentation
	rcb.TrgOps = model.TrgDataChange | model.TrgGI
	reports := make(chan *client.Report, 4)
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) { reports <- r })
	if err != nil {
		t.Fatalf("EnableReporting: %v", err)
	}
	defer sub.Disable(context.Background())

	if err := c.TriggerGI(ctx, rcb); err != nil {
		t.Fatalf("TriggerGI: %v", err)
	}

	select {
	case values := <-raw:
		opt := model.OptFldsFromValue(values[1])
		for _, unsupported := range []struct {
			bit  model.OptFlds
			name string
		}{
			{model.OptSegmentation, "segmentation"},
			{model.OptBufOvfl, "buffer overflow"},
			{model.OptEntryID, "entry id"},
		} {
			if opt&unsupported.bit != 0 {
				t.Errorf("unbuffered report claims %s", unsupported.name)
			}
		}
		// The fields it does claim are the ones it can produce.
		for _, want := range []model.OptFlds{
			model.OptSeqNum, model.OptTimeOfEntry, model.OptReasonCode,
			model.OptDataSetName, model.OptDataRef, model.OptConfRev,
		} {
			if opt&want == 0 {
				t.Errorf("report dropped a supported field: %v", want)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no report received")
	}

	select {
	case rep := <-reports:
		if len(rep.Entries) == 0 {
			t.Fatal("report decoded with no entries")
		}
		for i, e := range rep.Entries {
			if e.Value == nil || e.Reason == 0 {
				t.Errorf("entry %d (%s) misaligned: value=%v reason=%v", i, e.Ref, e.Value, e.Reason)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("report did not decode")
	}
}
