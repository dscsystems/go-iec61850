package client_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
)

// TestClientInterop exercises the ACSI client against a live server.
// Enable with IEC61850_TEST_SERVER=host:port.
func TestClientInterop(t *testing.T) {
	addr := os.Getenv("IEC61850_TEST_SERVER")
	if addr == "" {
		t.Skip("set IEC61850_TEST_SERVER=host:port to run client interop tests")
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

	lns, err := c.LogicalNodes(ctx, ld)
	if err != nil || len(lns) == 0 {
		t.Fatalf("LogicalNodes: %v %v", lns, err)
	}
	t.Logf("LD %s has LNs %v", ld, lns)

	t.Run("Read by reference", func(t *testing.T) {
		ref := model.ObjectReference(ld + "/GGIO1.SPCSO1.ctlModel")
		v, err := c.Read(ctx, ref, model.CF)
		if err != nil {
			t.Fatalf("Read %s: %v", ref, err)
		}
		t.Logf("%s = %s", ref, v)
	})

	t.Run("RetrieveModel", func(t *testing.T) {
		m, err := c.RetrieveModel(ctx)
		if err != nil {
			t.Fatalf("RetrieveModel: %v", err)
		}
		dev := m.Device(ld)
		if dev == nil {
			t.Fatalf("device %s missing from model", ld)
		}
		ggio := dev.Node("GGIO1")
		if ggio == nil {
			t.Fatal("GGIO1 missing")
		}
		// AnIn1.mag.f should resolve as a float under MX.
		da := m.Attribute(model.ObjectReference(ld+"/GGIO1.AnIn1.mag.f"), model.MX)
		if da == nil {
			t.Log("model tree:\n" + m.String())
			t.Fatal("AnIn1.mag.f not found in retrieved model")
		}
		t.Logf("retrieved %d LNs; AnIn1.mag.f kind=%s", len(dev.Nodes), da.Kind)
	})

	t.Run("DataSet", func(t *testing.T) {
		ref := model.ObjectReference(ld + "/LLN0.Measurements")
		ds, err := c.ReadDataSet(ctx, ref)
		if err != nil {
			t.Fatalf("ReadDataSet: %v", err)
		}
		if len(ds.Members) == 0 {
			t.Fatal("empty dataset")
		}
		for i, m := range ds.Members {
			if i >= 3 {
				break
			}
			t.Logf("  %s [%s] = %s", m.Ref, m.FC, m.Value)
		}
	})
}
