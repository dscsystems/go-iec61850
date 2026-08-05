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

// brcbModel is one buffered report control block over a single indication,
// with the queue depth the test wants.
func brcbModel(maxQueueSize int) *model.Model {
	ind := model.NewDataObject("Ind1", model.CDCSPS)
	ggio := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{ind}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0",
		DataSets: []*model.DataSet{{
			Name: "Events",
			Entries: []model.FCDA{
				{Ref: "BUFIED/GGIO1.Ind1.stVal", FC: model.ST},
			},
		}},
		ReportControls: []*model.ReportControl{{
			Name:         "EventsBRCB",
			RptID:        "Events",
			DataSet:      "Events",
			ConfRev:      1,
			Buffered:     true,
			TrgOps:       model.TrgDataChange | model.TrgGI,
			OptFlds:      model.OptSeqNum | model.OptReasonCode | model.OptEntryID | model.OptBufOvfl,
			RptEnabled:   1,
			MaxQueueSize: maxQueueSize,
		}},
	}
	ld := &model.LogicalDevice{Name: "BUFIED", Inst: "LD0", Nodes: []*model.LogicalNode{lln0, ggio}}
	return &model.Model{Name: "BUFIED", Devices: []*model.LogicalDevice{ld}}
}

func startBufServer(t *testing.T, m *model.Model, opts ...server.Option) (string, *server.Server) {
	t.Helper()
	srv := server.New(m, opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), srv
}

// bufferedReports counts what a BRCB delivers on enable after n changes
// were buffered with no subscriber, and reports whether an overflow was
// flagged.
func bufferedReports(t *testing.T, addr string, srv *server.Server, changes int) (int, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Buffer the changes with nobody enabled.
	for i := 0; i < changes; i++ {
		v := i%2 == 0
		srv.Update(func(tx *server.Tx) { tx.SetBool("BUFIED/GGIO1.Ind1.stVal", v) })
	}

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rcb, err := c.GetRCB(ctx, "BUFIED/LLN0.BR.EventsBRCB01")
	if err != nil {
		t.Fatalf("GetRCB: %v", err)
	}
	reports := make(chan *client.Report, 4096)
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) {
		select {
		case reports <- r:
		default:
		}
	})
	if err != nil {
		t.Fatalf("EnableReporting: %v", err)
	}
	defer sub.Disable(context.Background())

	// The flush is immediate; wait for it to go quiet.
	var got int
	var overflow bool
	deadline := time.After(5 * time.Second)
	for {
		select {
		case r := <-reports:
			got++
			if r.BufOvfl {
				overflow = true
			}
		case <-time.After(300 * time.Millisecond):
			return got, overflow
		case <-deadline:
			return got, overflow
		}
	}
}

// The depth a control block configures is the depth the server keeps. It
// used to buffer a library constant of 256 whatever the configuration said.
func TestBufferedReportDepthFromControlBlock(t *testing.T) {
	const depth = 5
	addr, srv := startBufServer(t, brcbModel(depth))

	got, overflow := bufferedReports(t, addr, srv, depth+20)
	if got != depth {
		t.Errorf("delivered %d buffered reports, want the configured %d", got, depth)
	}
	if !overflow {
		t.Error("the discarded reports were not flagged as a buffer overflow")
	}
}

// Under the depth, nothing is discarded and no overflow is claimed.
func TestBufferedReportDepthNotExceeded(t *testing.T) {
	const depth = 8
	addr, srv := startBufServer(t, brcbModel(depth))

	got, overflow := bufferedReports(t, addr, srv, depth-3)
	if got != depth-3 {
		t.Errorf("delivered %d buffered reports, want %d", got, depth-3)
	}
	if overflow {
		t.Error("an overflow was flagged although the buffer had room")
	}
}

// A block that configures no depth takes the server's default.
func TestBufferedReportDepthFromServerOption(t *testing.T) {
	const depth = 4
	addr, srv := startBufServer(t, brcbModel(0), server.WithReportBufferSize(depth))

	got, overflow := bufferedReports(t, addr, srv, depth+10)
	if got != depth {
		t.Errorf("delivered %d buffered reports, want the server default %d", got, depth)
	}
	if !overflow {
		t.Error("the discarded reports were not flagged as a buffer overflow")
	}
}

// The block's own depth wins over the server default.
func TestBufferedReportDepthControlBlockWins(t *testing.T) {
	const depth = 3
	addr, srv := startBufServer(t, brcbModel(depth), server.WithReportBufferSize(64))

	got, _ := bufferedReports(t, addr, srv, depth+10)
	if got != depth {
		t.Errorf("delivered %d buffered reports, want the block's %d", got, depth)
	}
}

// A depth of one keeps only the newest event, which is the degenerate case
// the trimming loop has to get right.
func TestBufferedReportDepthOne(t *testing.T) {
	addr, srv := startBufServer(t, brcbModel(1))

	got, overflow := bufferedReports(t, addr, srv, 6)
	if got != 1 {
		t.Errorf("delivered %d buffered reports, want 1", got)
	}
	if !overflow {
		t.Error("no overflow flagged after discarding five reports")
	}
}

// Without any configuration the library default still applies.
func TestBufferedReportDefaultDepth(t *testing.T) {
	addr, srv := startBufServer(t, brcbModel(0))

	// Fewer changes than the default: nothing may be discarded.
	got, overflow := bufferedReports(t, addr, srv, 12)
	if got != 12 {
		t.Errorf("delivered %d buffered reports, want 12", got)
	}
	if overflow {
		t.Error("the default buffer overflowed after 12 reports")
	}
}

// The value read back from the control block is unaffected: the depth is a
// server-side capacity, not an RCB attribute a client writes.
func TestBufferedReportDepthIsNotAnRCBAttribute(t *testing.T) {
	addr, _ := startBufServer(t, brcbModel(7))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	vals, err := c.MMS().Read(ctx, "BUFIED", "LLN0$BR$EventsBRCB01$RptID")
	if err != nil || len(vals) == 0 {
		t.Fatalf("read RptID: %v", err)
	}
	if _, isErr := vals[0].AccessError(); isErr {
		t.Fatalf("RptID unreadable: %v", vals[0])
	}
	if vals[0].Type() != mms.TypeVisibleString {
		t.Errorf("RptID = %s, want a visible string", vals[0].Type())
	}
}
