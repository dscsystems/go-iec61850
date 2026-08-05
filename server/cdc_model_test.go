package server_test

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// cdcModel is a device assembled entirely from the common data class
// helpers, the way a server author would write one by hand.
func cdcModel() *model.Model {
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0", Objects: []*model.DataObject{
		model.NewDataObject("NamPlt", model.CDCLPL, model.WithOptional("configRev")),
		model.NewDataObject("Mod", model.CDCINC, model.WithControlModel(model.CtlDirectNormal)),
	}}
	ggio := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{
		model.NewDataObject("Ind1", model.CDCSPS),
		model.NewDataObject("AnIn1", model.CDCMV, model.WithOptional("units", "db")),
		model.NewDataObject("SPCSO1", model.CDCSPC, model.WithControlModel(model.CtlSBOEnhanced)),
		model.NewDataObject("ISCSO1", model.CDCINC, model.WithControlModel(model.CtlDirectNormal)),
		model.NewDataObject("StrVal", model.CDCING),
	}}
	mmxu := &model.LogicalNode{Name: "MMXU1", Class: "MMXU", Objects: []*model.DataObject{
		model.NewDataObject("PhV", model.CDCWYE),
	}}
	ld := &model.LogicalDevice{
		Name: "CDCIED", Inst: "LD0",
		Nodes: []*model.LogicalNode{lln0, ggio, mmxu},
	}
	return &model.Model{Name: "CDCIED", Devices: []*model.LogicalDevice{ld}}
}

func startCDCServer(t *testing.T) (string, *server.Server) {
	t.Helper()
	srv := server.New(cdcModel())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), srv
}

// A model built from the helpers is browsable, readable and controllable
// over the wire — the trees are the ones the server expects.
func TestCDCBuiltModelIsServed(t *testing.T) {
	addr, srv := startCDCServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	t.Run("browse", func(t *testing.T) {
		dos, err := c.LogicalNodeDirectory(ctx, "CDCIED/GGIO1", client.ACSIDataObject)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Ind1", "AnIn1", "SPCSO1", "ISCSO1", "StrVal"} {
			if !slices.Contains(dos, want) {
				t.Errorf("data objects = %v, missing %q", dos, want)
			}
		}
		// The measurand's attributes and the one member of its
		// AnalogueValue.
		mx, err := c.DataDirectory(ctx, "CDCIED/GGIO1.AnIn1", model.MX)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"mag", "q", "t"} {
			if !slices.Contains(mx, want) {
				t.Errorf("AnIn1 [MX] = %v, missing %q", mx, want)
			}
		}
		mag, err := c.DataDirectory(ctx, "CDCIED/GGIO1.AnIn1.mag", model.MX)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(mag, []string{"f"}) {
			t.Errorf("mag members = %v, want [f]", mag)
		}
		// The configuration attributes asked for are served under CF.
		cf, err := c.DataDirectory(ctx, "CDCIED/GGIO1.AnIn1", model.CF)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"units", "db"} {
			if !slices.Contains(cf, want) {
				t.Errorf("AnIn1 [CF] = %v, missing %q", cf, want)
			}
		}
	})

	t.Run("read and update", func(t *testing.T) {
		v, err := c.Read(ctx, "CDCIED/GGIO1.Ind1.stVal", model.ST)
		if err != nil {
			t.Fatalf("read stVal: %v", err)
		}
		if v.Bool() {
			t.Error("a freshly built SPS is not false")
		}
		if q, err := c.Read(ctx, "CDCIED/GGIO1.Ind1.q", model.ST); err != nil || q.BitLen() != 13 {
			t.Errorf("read q = %v (%v), want a 13-bit string", q, err)
		}

		srv.Update(func(tx *server.Tx) {
			tx.SetBool("CDCIED/GGIO1.Ind1.stVal", true)
			tx.SetFloat32("CDCIED/GGIO1.AnIn1.mag.f", 12.5)
		})
		if v, err := c.Read(ctx, "CDCIED/GGIO1.Ind1.stVal", model.ST); err != nil || !v.Bool() {
			t.Errorf("stVal after update = %v (%v), want true", v, err)
		}
		f, err := c.Read(ctx, "CDCIED/GGIO1.AnIn1.mag.f", model.MX)
		if err != nil || f.Float64() != 12.5 {
			t.Errorf("mag.f after update = %v (%v), want 12.5", f, err)
		}

		// The name plate is a description, served under DC.
		if _, err := c.Read(ctx, "CDCIED/LLN0.NamPlt.vendor", model.DC); err != nil {
			t.Errorf("read vendor: %v", err)
		}
	})

	t.Run("nested measurands", func(t *testing.T) {
		// The phases of a WYE are nested data objects.
		if _, err := c.Read(ctx, "CDCIED/MMXU1.PhV.phsA.cVal.mag.f", model.MX); err != nil {
			t.Errorf("read phsA magnitude: %v", err)
		}
		srv.Update(func(tx *server.Tx) {
			tx.SetFloat32("CDCIED/MMXU1.PhV.phsB.cVal.mag.f", 230.1)
		})
		v, err := c.Read(ctx, "CDCIED/MMXU1.PhV.phsB.cVal.mag.f", model.MX)
		if err != nil || v.Float64() == 0 {
			t.Errorf("phsB magnitude = %v (%v), want 230.1", v, err)
		}
	})

	t.Run("control", func(t *testing.T) {
		// A select-before-operate control built by the helpers completes a
		// full sequence, which exercises SBOw, Oper and the server's
		// selection checking.
		co, err := c.ControlFor(ctx, "CDCIED/GGIO1.SPCSO1")
		if err != nil {
			t.Fatal(err)
		}
		if co.Model() != model.CtlSBOEnhanced {
			t.Fatalf("control model = %s, want sbo-enhanced", co.Model())
		}
		if kind, err := co.CtlValType(ctx); err != nil || kind != mms.TypeBoolean {
			t.Errorf("SPC ctlVal type = %s (%v), want boolean", kind, err)
		}
		if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
			t.Fatalf("Operate: %v", err)
		}
		if v, err := c.Read(ctx, "CDCIED/GGIO1.SPCSO1.stVal", model.ST); err != nil || !v.Bool() {
			t.Errorf("stVal after operate = %v (%v), want true", v, err)
		}

		// An integer control carries an integer control value.
		inc, err := c.ControlFor(ctx, "CDCIED/GGIO1.ISCSO1")
		if err != nil {
			t.Fatal(err)
		}
		if kind, err := inc.CtlValType(ctx); err != nil || kind != mms.TypeInteger {
			t.Errorf("INC ctlVal type = %s (%v), want integer", kind, err)
		}
		if err := inc.Operate(ctx, mms.NewInt32(7)); err != nil {
			t.Fatalf("INC Operate: %v", err)
		}
		if v, err := c.Read(ctx, "CDCIED/GGIO1.ISCSO1.stVal", model.ST); err != nil || v.Int64() != 7 {
			t.Errorf("INC stVal = %v (%v), want 7", v, err)
		}
	})

	t.Run("settings", func(t *testing.T) {
		if err := c.Write(ctx, "CDCIED/GGIO1.StrVal.setVal", model.SP, mms.NewInt32(42)); err != nil {
			t.Fatalf("write setting: %v", err)
		}
		if v, err := c.Read(ctx, "CDCIED/GGIO1.StrVal.setVal", model.SP); err != nil || v.Int64() != 42 {
			t.Errorf("setting = %v (%v), want 42", v, err)
		}
	})
}

// A dataset and a report over CDC-built objects: the values a report
// carries come out of the same trees.
func TestCDCBuiltModelReports(t *testing.T) {
	m := cdcModel()
	lln0 := m.Devices[0].Node("LLN0")
	lln0.DataSets = append(lln0.DataSets, &model.DataSet{
		Name: "Events",
		Entries: []model.FCDA{
			{Ref: "CDCIED/GGIO1.Ind1.stVal", FC: model.ST},
			{Ref: "CDCIED/GGIO1.Ind1.q", FC: model.ST},
		},
	})
	srv := server.New(m)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ds, err := c.ReadDataSet(ctx, "CDCIED/LLN0.Events")
	if err != nil {
		t.Fatalf("ReadDataSet: %v", err)
	}
	if len(ds.Members) != 2 {
		t.Fatalf("dataset members = %d, want 2", len(ds.Members))
	}
	if ds.Members[0].Value == nil || ds.Members[0].Value.Bool() {
		t.Errorf("first member = %v, want a false boolean", ds.Members[0].Value)
	}
	if ds.Members[1].Value == nil || ds.Members[1].Value.BitLen() != 13 {
		t.Errorf("second member = %v, want a 13-bit quality", ds.Members[1].Value)
	}
}
