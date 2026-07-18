package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// startServer loads the demo model, serves it on a random local port and
// returns the address and a cleanup function.
func startServer(t *testing.T) (string, *server.Server) {
	t.Helper()
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	srv := server.New(m, server.WithIdentity(server.Identity{
		Vendor: "ACME", Model: "go-iec61850 test", Revision: "0.1",
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), srv
}

func TestServerClientLoopback(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	t.Run("Identify", func(t *testing.T) {
		v, m, r, err := c.MMS().Identify(ctx)
		if err != nil {
			t.Fatalf("Identify: %v", err)
		}
		if v != "ACME" || m != "go-iec61850 test" || r != "0.1" {
			t.Fatalf("identity = %q/%q/%q", v, m, r)
		}
	})

	var ld string
	t.Run("Browse", func(t *testing.T) {
		lds, err := c.LogicalDevices(ctx)
		if err != nil || len(lds) == 0 {
			t.Fatalf("LogicalDevices: %v %v", lds, err)
		}
		ld = lds[0]
		lns, err := c.LogicalNodes(ctx, ld)
		if err != nil {
			t.Fatalf("LogicalNodes: %v", err)
		}
		if !contains(lns, "GGIO1") || !contains(lns, "LLN0") {
			t.Fatalf("expected GGIO1 and LLN0, got %v", lns)
		}
	})

	t.Run("ReadWrite", func(t *testing.T) {
		// Seed a known value from the process side, then read it back.
		ref := model.ObjectReference(ld + "/GGIO1.AnIn1.mag.f")
		srv.Update(func(tx *server.Tx) { tx.SetFloat32(ref, 123.5) })

		v, err := c.Read(ctx, ref, model.MX)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if v.Float32() != 123.5 {
			t.Fatalf("read back %v, want 123.5", v.Float32())
		}

		// Client write to a config attribute, then confirm server-side.
		ctlRef := model.ObjectReference(ld + "/GGIO1.SPCSO1.ctlModel")
		if err := c.Write(ctx, ctlRef, model.CF, mms.NewInt32(4)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got := srv.Read(ctlRef, model.CF); got == nil || got.Int64() != 4 {
			t.Fatalf("server-side ctlModel = %v, want 4", got)
		}
	})

	t.Run("RetrieveModel", func(t *testing.T) {
		m, err := c.RetrieveModel(ctx)
		if err != nil {
			t.Fatalf("RetrieveModel: %v", err)
		}
		da := m.Attribute(model.ObjectReference(ld+"/GGIO1.AnIn1.mag.f"), model.MX)
		if da == nil {
			t.Fatalf("AnIn1.mag.f missing from retrieved model:\n%s", m.String())
		}
		if da.Kind != mms.TypeFloat32 {
			t.Fatalf("mag.f kind = %s", da.Kind)
		}
	})

	t.Run("DataSet", func(t *testing.T) {
		ds, err := c.ReadDataSet(ctx, model.ObjectReference(ld+"/LLN0.Measurements"))
		if err != nil {
			t.Fatalf("ReadDataSet: %v", err)
		}
		if len(ds.Members) == 0 {
			t.Fatal("empty Measurements dataset")
		}
	})
}

func TestServerWriteHandler(t *testing.T) {
	addr, srv := startServer(t)
	srv.OnWrite(func(da *model.DataAttribute, v *mms.Value) error {
		if da.Name == "ctlModel" {
			return server.ErrAccessDenied
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	lds, _ := c.LogicalDevices(ctx)
	ref := model.ObjectReference(lds[0] + "/GGIO1.SPCSO1.ctlModel")
	err = c.Write(ctx, ref, model.CF, mms.NewInt32(2))
	if err == nil {
		t.Fatal("expected write to be denied")
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
