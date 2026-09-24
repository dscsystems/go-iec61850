package server_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

func demoModel(t *testing.T) *model.Model {
	t.Helper()
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Status is never writable, even when a server lists ST; configuration is
// when it opts in.
func TestWritePolicyNeverAllowsStatus(t *testing.T) {
	addr, srv := serveModel(t, demoModel(t), server.WithWritableFCs(model.ST, model.CF))
	c := dialDemo(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := c.Write(ctx, member("SPCSO1"), model.ST, mms.NewBool(true)); !errors.Is(err, mms.AccessObjectAccessDenied) {
		t.Errorf("write stVal: err = %v, want object-access-denied", err)
	}
	ctlModel := model.ObjectReference(demoLD + "/GGIO1.SPCSO1.ctlModel")
	if err := c.Write(ctx, ctlModel, model.CF, mms.NewInt32(4)); err != nil {
		t.Fatalf("write CF with CF writable: %v", err)
	}
	if got := srv.Read(ctlModel, model.CF); got.Int64() != 4 {
		t.Errorf("ctlModel = %v, want 4", got)
	}
}

// A value of another type is refused and leaves the attribute as it was.
func TestWriteTypeMustMatch(t *testing.T) {
	addr, srv := serveModel(t, demoModel(t), server.WithWritableFCs(model.CF))
	c := dialDemo(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctlModel := model.ObjectReference(demoLD + "/GGIO1.SPCSO1.ctlModel")
	before := srv.Read(ctlModel, model.CF)
	if err := c.Write(ctx, ctlModel, model.CF, mms.NewVisibleString("sbo")); !errors.Is(err, mms.AccessTypeInconsistent) {
		t.Errorf("err = %v, want type-inconsistent", err)
	}
	if got := srv.Read(ctlModel, model.CF); !got.Equal(before) {
		t.Errorf("refused write changed the value to %v", got)
	}
}

// A sized integer is refused outside its range.
func TestWriteSizedIntegerRange(t *testing.T) {
	ln := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{
		{Name: "Lim", CDC: "ING", Attributes: []*model.DataAttribute{
			{Name: "setVal", FC: model.SP, Kind: mms.TypeUnsigned, BType: "INT8U", Value: mms.NewUint8(0)},
		}},
	}}
	m := &model.Model{Name: "LIM", Devices: []*model.LogicalDevice{
		{Name: "LIM", Inst: "LD0", Nodes: []*model.LogicalNode{{Name: "LLN0", Class: "LLN0"}, ln}},
	}}
	addr, _ := serveModel(t, m)
	c := dialDemo(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ref := model.ObjectReference("LIM/GGIO1.Lim.setVal")
	if err := c.Write(ctx, ref, model.SP, mms.NewUint32(300)); !errors.Is(err, mms.AccessTypeInconsistent) {
		t.Errorf("300 into INT8U: err = %v, want type-inconsistent", err)
	}
	if err := c.Write(ctx, ref, model.SP, mms.NewUint32(200)); err != nil {
		t.Errorf("200 into INT8U: %v", err)
	}
}

// Setting group control block writes are validated before they are
// stored, and edit values are writable only while a group is edited.
func TestSGCBWritesValidated(t *testing.T) {
	addr, _ := serveModel(t, sgModel(), server.WithSettingGroups(3))
	c := dialDemo(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	sgcb := func(attr string) model.ObjectReference {
		return model.ObjectReference("DEMOPROT/LLN0.SGCB." + attr)
	}
	se := model.ObjectReference("DEMOPROT/PTOC1.OpDlTmms.setVal")

	if err := c.Write(ctx, sgcb("ActSG"), model.SP, mms.NewUint8(9)); !errors.Is(err, mms.AccessObjectValueInvalid) {
		t.Errorf("ActSG=9: err = %v, want object-value-invalid", err)
	}
	if v, _ := c.Read(ctx, sgcb("ActSG"), model.SP); v.Uint64() != 1 {
		t.Errorf("ActSG = %v after a refused write", v)
	}
	if err := c.Write(ctx, sgcb("NumOfSG"), model.SP, mms.NewUint8(5)); !errors.Is(err, mms.AccessObjectAccessDenied) {
		t.Errorf("NumOfSG: err = %v, want object-access-denied", err)
	}
	if err := c.Write(ctx, se, model.SE, mms.NewInt32(700)); !errors.Is(err, mms.AccessTemporarilyUnavailable) {
		t.Errorf("SE outside an edit: err = %v, want temporarily-unavailable", err)
	}
	if err := c.Write(ctx, sgcb("EditSG"), model.SP, mms.NewUint8(2)); err != nil {
		t.Fatalf("EditSG: %v", err)
	}
	if err := c.Write(ctx, se, model.SE, mms.NewInt32(700)); err != nil {
		t.Errorf("SE while editing: %v", err)
	}
}

// pduSizes records the length of every PDU the client's reader receives.
type pduSizes struct {
	mu  sync.Mutex
	max int64
}

func (p *pduSizes) Enabled(context.Context, slog.Level) bool { return true }
func (p *pduSizes) WithAttrs([]slog.Attr) slog.Handler       { return p }
func (p *pduSizes) WithGroup(string) slog.Handler            { return p }
func (p *pduSizes) Handle(_ context.Context, r slog.Record) error {
	if r.Message == "mms: rx PDU" {
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "len" {
				p.mu.Lock()
				p.max = max(p.max, a.Value.Int64())
				p.mu.Unlock()
			}
			return true
		})
	}
	return nil
}

// GetNameList pages to the association's PDU size, and the pages add up
// to the whole list.
func TestGetNameListPagesToMaxPDU(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	full, err := dialDemo(t, addr).MMS().GetNameList(ctx, mms.ClassNamedVariable, demoLD)
	if err != nil {
		t.Fatal(err)
	}
	sizes := &pduSizes{}
	init := mms.DefaultInitiate()
	init.LocalDetail = 300
	small, err := mms.Dial(ctx, addr, mms.Options{Initiate: &init, Logger: slog.New(sizes)})
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	paged, err := small.GetNameList(ctx, mms.ClassNamedVariable, demoLD)
	if err != nil {
		t.Fatal(err)
	}
	if len(paged) != len(full) {
		t.Fatalf("paged list has %d names, full list %d", len(paged), len(full))
	}
	for i := range full {
		if paged[i] != full[i] {
			t.Fatalf("name %d: %q, want %q", i, paged[i], full[i])
		}
	}
	if sizes.max > 300 {
		t.Errorf("largest PDU received was %d octets, over the negotiated 300", sizes.max)
	}
}

// A response that would exceed the PDU size is a resource error instead.
func TestOversizedResponseIsResourceError(t *testing.T) {
	addr, _ := startServer(t)
	c := dialDemo(t, addr, withMaxPDU(200))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Every status attribute of GGIO1 at once is far over 200 octets.
	_, err := c.MMS().Read(ctx, demoLD, "GGIO1$ST")
	var se *mms.ServiceError
	if !errors.As(err, &se) || se.Class != 3 {
		t.Fatalf("reading GGIO1$ST over a 200-octet association: %v, want a resource service error", err)
	}
}
