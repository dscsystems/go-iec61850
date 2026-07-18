package server_test

import (
	"context"
	"math"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// TestScanAfterWarmup mirrors ied-server exactly (all controls registered,
// full 500 ms simulation of every measurand and status point, RCBs
// buffering) and lets it run before a client scans, to catch any stall
// that only appears once report buffers have filled.
func TestScanAfterWarmup(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m)
	// Register a control handler for every controllable, like ied-server.
	var walkCtl func(base model.ObjectReference, do *model.DataObject)
	walkCtl = func(base model.ObjectReference, do *model.DataObject) {
		ref := base.Child(do.Name)
		for _, fc := range do.FCs() {
			if fc == model.CO {
				srv.OnControl(ref, func(*server.ControlCtx) model.AddCause { return model.AddCauseNone })
				break
			}
		}
		for _, sub := range do.Objects {
			walkCtl(ref, sub)
		}
	}
	var floats, bools []model.ObjectReference
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, do := range ln.Objects {
				walkCtl(model.ObjectReference(ld.Name+"/"+ln.Name), do)
				base := model.ObjectReference(ld.Name + "/" + ln.Name + "." + do.Name)
				if m.Attribute(base.Child("mag").Child("f"), model.MX) != nil {
					floats = append(floats, base.Child("mag").Child("f"))
				}
				if m.Attribute(base.Child("stVal"), model.ST) != nil {
					bools = append(bools, base.Child("stVal"))
				}
			}
		}
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tk := time.NewTicker(500 * time.Millisecond)
		defer tk.Stop()
		var phase float64
		tick := 0
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				phase += 0.1
				tick++
				toggle := tick%6 == 0
				srv.Update(func(tx *server.Tx) {
					for i, r := range floats {
						tx.SetFloat32(r, float32(math.Sin(phase+float64(i))))
					}
					if toggle {
						for _, r := range bools {
							tx.Toggle(r, model.ST) // never srv.Read here: it would deadlock
						}
					}
				})
			}
		}
	}()

	// Let the simulation run so BRCB buffers fill.
	time.Sleep(4 * time.Second)

	c, err := client.Dial(context.Background(), ln.Addr().String(), client.WithTimeout(6*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Exactly what `scan` does, with a per-op deadline.
	do := func(name string, fn func(context.Context) error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		start := time.Now()
		if err := fn(ctx); err != nil {
			t.Fatalf("%s: %v (after %v)", name, err, time.Since(start))
		}
		t.Logf("%s ok in %v", name, time.Since(start))
	}
	do("Identify", func(ctx context.Context) error { _, _, _, e := c.MMS().Identify(ctx); return e })
	var lds []string
	do("LogicalDevices", func(ctx context.Context) error {
		var e error
		lds, e = c.LogicalDevices(ctx)
		return e
	})
	do("LogicalNodes", func(ctx context.Context) error {
		_, e := c.LogicalNodes(ctx, lds[0])
		return e
	})
}
