package server_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// svEvents records OnSVControl events.
type svEvents struct {
	mu  sync.Mutex
	evs []server.SVControlEvent
	ch  chan struct{}
}

func (r *svEvents) add(ev server.SVControlEvent) {
	r.mu.Lock()
	r.evs = append(r.evs, ev)
	r.mu.Unlock()
	r.ch <- struct{}{}
}

// next waits for the next event.
func (r *svEvents) next(t *testing.T) server.SVControlEvent {
	t.Helper()
	select {
	case <-r.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no OnSVControl event")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	ev := r.evs[0]
	r.evs = r.evs[1:]
	return ev
}

// A USVCB is reserved by one association at a time (IEC 61850-7-2
// clause 16, Resv): the others may read it but not change it, only
// SvEna and Resv are writable, the configuration not at all while the
// block is enabled, and the reservation and the stream end with the
// association.
func TestUSVCBReservation(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatal(err)
	}
	addr, srv := startServerWith(t, m)
	rec := &svEvents{ch: make(chan struct{}, 16)}
	srv.OnSVControl(rec.add)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func() *client.Client {
		c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	a, b := dial(), dial()
	const usvcb = model.ObjectReference("ED21LD0/LLN0.usvcb01")

	if err := a.ReserveUSVCB(ctx, usvcb, true); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	ev := rec.next(t)
	if !ev.Unicast || !ev.Reserved || ev.Enabled || ev.Conn == nil || ev.Block.Name != "usvcb01" || ev.Device.Name != "ED21LD0" {
		t.Errorf("reserve event = %+v", ev)
	}

	// Another association reads the reservation and is refused.
	if v, err := b.Read(ctx, usvcb+".Resv", model.US); err != nil || !v.Bool() {
		t.Errorf("Resv read by another client = %v, %v; want true", v, err)
	}
	for _, attr := range []string{"SvEna", "Resv"} {
		if err := b.Write(ctx, usvcb+model.ObjectReference("."+attr), model.US, mms.NewBool(true)); !errors.Is(err, mms.AccessTemporarilyUnavailable) {
			t.Errorf("%s written by another client: %v, want temporarily-unavailable", attr, err)
		}
	}

	// The configuration is not writable, and not at all while enabled.
	if err := a.Write(ctx, usvcb+".UsvID", model.US, mms.NewVisibleString("X")); !errors.Is(err, mms.AccessObjectAccessDenied) {
		t.Errorf("UsvID written: %v, want object-access-denied", err)
	}
	if err := a.Write(ctx, usvcb+".SvEna", model.US, mms.NewInt32(1)); !errors.Is(err, mms.AccessTypeInconsistent) {
		t.Errorf("SvEna written with an integer: %v, want type-inconsistent", err)
	}
	if err := a.EnableSVCB(ctx, usvcb, true, true); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if ev := rec.next(t); !ev.Enabled || !ev.Reserved {
		t.Errorf("enable event = %+v", ev)
	}
	if err := a.Write(ctx, usvcb+".SmpRate", model.US, mms.NewUint16(4000)); !errors.Is(err, mms.AccessTemporarilyUnavailable) {
		t.Errorf("SmpRate written while enabled: %v, want temporarily-unavailable", err)
	}
	// Writing what is already set changes nothing and reports nothing.
	if err := a.EnableSVCB(ctx, usvcb, true, true); err != nil {
		t.Fatal(err)
	}

	// The association ends: the block is released and disabled.
	a.Close()
	if ev := rec.next(t); ev.Enabled || ev.Reserved || ev.Conn != nil {
		t.Errorf("release event = %+v, want disabled and free", ev)
	}
	if v, err := b.Read(ctx, usvcb+".SvEna", model.US); err != nil || v.Bool() {
		t.Errorf("SvEna after the owner left = %v, %v", v, err)
	}
	if err := b.ReserveUSVCB(ctx, usvcb, true); err != nil {
		t.Errorf("reserving the released block: %v", err)
	}
	if ev := rec.next(t); !ev.Reserved {
		t.Errorf("second reservation event = %+v", ev)
	}
	if err := b.ReserveUSVCB(ctx, usvcb, false); err != nil {
		t.Errorf("releasing: %v", err)
	}
	if ev := rec.next(t); ev.Reserved || ev.Conn != nil {
		t.Errorf("release event = %+v", ev)
	}
}

// An MSVCB has no reservation: any client enables it.
func TestMSVCBEnable(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatal(err)
	}
	addr, srv := startServerWith(t, m)
	rec := &svEvents{ch: make(chan struct{}, 16)}
	srv.OnSVControl(rec.add)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const msvcb = model.ObjectReference("ED21LD0/LLN0.msvcb01")
	if err := c.EnableSVCB(ctx, msvcb, false, true); err != nil {
		t.Fatal(err)
	}
	if ev := rec.next(t); ev.Unicast || !ev.Enabled || ev.Reserved || ev.Block.Name != "msvcb01" {
		t.Errorf("event = %+v", ev)
	}
	if v, err := c.Read(ctx, msvcb+".SvEna", model.MS); err != nil || !v.Bool() {
		t.Errorf("SvEna = %v, %v", v, err)
	}
	c.Close()
	// Its stream is not the client's: it outlives the association.
	select {
	case <-rec.ch:
		t.Error("an MSVCB was disabled by the end of the association that enabled it")
	case <-time.After(200 * time.Millisecond):
	}
}
