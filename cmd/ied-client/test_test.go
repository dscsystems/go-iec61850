package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// TestCmdTest runs the full ied-client self-test against an in-process
// server with simulated data, so it exercises every feature path
// (including reporting) and would deadlock/timeout here if the server or
// client stalled.
func TestCmdTest(t *testing.T) {
	m, err := scl.LoadModel("../../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m, server.WithIdentity(server.Identity{Vendor: "ACME", Model: m.Name, Revision: "0.1"}))
	// Accept controls.
	srv.OnControl(model.ObjectReference(m.Devices[0].Name+"/GGIO1.SPCSO1"),
		func(*server.ControlCtx) model.AddCause { return model.AddCauseNone })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	// Simulate: toggle a status point in the Events dataset so data-change
	// reports are produced.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tk := time.NewTicker(300 * time.Millisecond)
		defer tk.Stop()
		on := false
		ref := model.ObjectReference(m.Devices[0].Name + "/GGIO1.SPCSO1.stVal")
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				on = !on
				srv.Update(func(tx *server.Tx) { tx.SetBool(ref, on) })
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// cmdTest prints its own report; assert it completes and passes.
	if !cmdTest(c) {
		t.Fatal("cmdTest reported failures (see output above)")
	}
}
