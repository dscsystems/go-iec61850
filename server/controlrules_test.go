package server_test

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// serveModel serves m and returns its address and the server.
func serveModel(t *testing.T, m *model.Model, opts ...server.Option) (string, *server.Server) {
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

// selModelWith is the SELIED model with extra CF attributes on SPCSO1.
func selModelWith(cm model.CtlModel, cf ...*model.DataAttribute) *model.Model {
	m := sboCheckModel(cm)
	spc := m.Devices[0].Node("GGIO1").Object("SPCSO1")
	spc.Attributes = append(spc.Attributes, cf...)
	return m
}

func cfMillis(name string, ms uint32) *model.DataAttribute {
	return &model.DataAttribute{Name: name, FC: model.CF, Kind: mms.TypeUnsigned, Value: mms.NewUint32(ms)}
}

func dialSel(t *testing.T, addr string) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// A status-only object refuses control, and says why in LastApplError,
// which names the control variable and the refused control number.
func TestStatusOnlyRefusesControl(t *testing.T) {
	c := dialSel(t, startSelectServer(t, model.CtlStatusOnly))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writeCtl(t, ctx, c, "Oper", true, 9); !errors.Is(err, mms.AccessObjectAccessDenied) {
		t.Fatalf("operate: err = %v, want object-access-denied", err)
	}
	e, ok := c.LastApplError()
	if !ok {
		t.Fatal("no LastApplError reported")
	}
	if e.AddCause != model.AddCauseNotSupported || e.CtlNum != 9 || e.CntrlObj != "SELIED/GGIO1$CO$SPCSO1$Oper" {
		t.Errorf("LastApplError = %+v", e)
	}
}

// SBOw belongs to SBO with enhanced security only.
func TestSBOwRefusedForDirectModel(t *testing.T) {
	c := dialSel(t, startSelectServer(t, model.CtlDirectEnhanced))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writeCtl(t, ctx, c, "SBOw", true, 1); err == nil {
		t.Fatal("SBOw accepted on a direct-control object")
	}
	if e, _ := c.LastApplError(); e.AddCause != model.AddCauseNotSupported {
		t.Errorf("AddCause = %s, want not-supported", e.AddCause)
	}
}

// A member of the control structure is not an operate.
func TestControlMemberWriteRefused(t *testing.T) {
	addr := startSelectServer(t, model.CtlDirectNormal)
	c := dialSel(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := c.MMS().Write(ctx, "SELIED", []string{"GGIO1$CO$SPCSO1$Oper$ctlVal"}, []*mms.Value{mms.NewBool(true)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) == 0 || !errors.Is(res[0], mms.AccessTypeInconsistent) {
		t.Fatalf("ctlVal write: %v, want type-inconsistent", res)
	}
	if v, _ := c.Read(ctx, "SELIED/GGIO1.SPCSO1.stVal", model.ST); v == nil || v.Bool() {
		t.Errorf("stVal = %v after a refused write", v)
	}
}

// pduOrder records the order of confirmed responses and unconfirmed PDUs
// as the client's reader receives them.
type pduOrder struct {
	mu   sync.Mutex
	tags []string
}

func (p *pduOrder) Enabled(context.Context, slog.Level) bool { return true }
func (p *pduOrder) WithAttrs([]slog.Attr) slog.Handler       { return p }
func (p *pduOrder) WithGroup(string) slog.Handler            { return p }
func (p *pduOrder) Handle(_ context.Context, r slog.Record) error {
	if r.Message != "mms: rx PDU" {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "tag" {
			p.mu.Lock()
			p.tags = append(p.tags, a.Value.String())
			p.mu.Unlock()
		}
		return true
	})
	return nil
}

// The CommandTermination of an enhanced operate follows the operate's
// response on the wire (IEC 61850-8-1).
func TestCommandTerminationFollowsResponse(t *testing.T) {
	addr := startSelectServer(t, model.CtlDirectEnhanced)
	order := &pduOrder{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mc, err := mms.Dial(ctx, addr, mms.Options{Logger: slog.New(order)})
	if err != nil {
		t.Fatal(err)
	}
	defer mc.Close()
	res, err := mc.Write(ctx, "SELIED", []string{"GGIO1$CO$SPCSO1$Oper"}, []*mms.Value{ctlStructValue(true, 4)})
	if err != nil || (len(res) > 0 && res[0] != nil) {
		t.Fatalf("operate: %v %v", err, res)
	}
	time.Sleep(200 * time.Millisecond)

	response, unconfirmed := asn1.ContextConstructed(1).String(), asn1.ContextConstructed(3).String()
	order.mu.Lock()
	defer order.mu.Unlock()
	ri, ui := -1, -1
	for i, tag := range order.tags {
		switch {
		case tag == response && ri < 0:
			ri = i
		case tag == unconfirmed && ui < 0:
			ui = i
		}
	}
	if ri < 0 || ui < 0 || ui < ri {
		t.Fatalf("PDU order %v: want the response before the CommandTermination", order.tags)
	}
}

// A handler that defers the termination can end the operate negatively;
// the client's Operate reports the cause.
func TestDeferredNegativeTermination(t *testing.T) {
	addr, srv := serveModel(t, sboCheckModel(model.CtlDirectEnhanced))
	srv.OnControl(selRef, func(cc *server.ControlCtx) model.AddCause {
		finish := cc.DeferTermination()
		go func() {
			time.Sleep(50 * time.Millisecond)
			finish(model.AddCauseBlockedByProcess)
		}()
		return model.AddCauseNone
	})
	c := dialSel(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	co, err := c.ControlFor(ctx, selRef)
	if err != nil {
		t.Fatal(err)
	}
	err = co.Operate(ctx, mms.NewBool(true))
	var ce *client.ControlError
	if !errors.As(err, &ce) || ce.Stage != "termination" || ce.AddCause != model.AddCauseBlockedByProcess {
		t.Fatalf("Operate: %v, want a termination failure blocked-by-process", err)
	}
}

// An operate whose deferred termination never comes ends with
// time-limit-over after operTimeout.
func TestOperTimeoutTerminatesNegatively(t *testing.T) {
	addr, srv := serveModel(t, selModelWith(model.CtlDirectEnhanced, cfMillis("operTimeout", 100)))
	srv.OnControl(selRef, func(cc *server.ControlCtx) model.AddCause {
		cc.DeferTermination() // and never finish
		return model.AddCauseNone
	})
	c := dialSel(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	co, err := c.ControlFor(ctx, selRef)
	if err != nil {
		t.Fatal(err)
	}
	var ce *client.ControlError
	if err := co.Operate(ctx, mms.NewBool(true)); !errors.As(err, &ce) || ce.AddCause != model.AddCauseTimeLimitOver {
		t.Fatalf("Operate: %v, want time-limit-over", err)
	}
}

// Without a deferral the server terminates positively at once.
func TestPositiveTerminationCompletesOperate(t *testing.T) {
	c := dialSel(t, startSelectServer(t, model.CtlDirectEnhanced))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	co, err := c.ControlFor(ctx, selRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("Operate: %v", err)
	}
}

// A selection lasts the object's sboTimeout.
func TestSelectExpiresAfterSboTimeout(t *testing.T) {
	addr, _ := serveModel(t, selModelWith(model.CtlSBOEnhanced, cfMillis("sboTimeout", 100)))
	c := dialSel(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := writeCtl(t, ctx, c, "SBOw", true, 5); err != nil {
		t.Fatalf("select: %v", err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := writeCtl(t, ctx, c, "Oper", true, 5); err == nil {
		t.Fatal("operate accepted after the selection expired")
	}
	if e, _ := c.LastApplError(); e.AddCause != model.AddCauseObjectNotSelected {
		t.Errorf("AddCause = %s, want object-not-selected", e.AddCause)
	}
}
