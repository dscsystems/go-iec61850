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

func TestCtlValTypeOfSPC(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	co, err := c.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := co.CtlValType(ctx)
	if err != nil {
		t.Fatalf("CtlValType: %v", err)
	}
	if got != mms.TypeBoolean {
		t.Errorf("SPC ctlVal type = %s, want boolean", got)
	}

	// The type is static, so it is cached: closing the connection must not
	// stop a repeat call from answering.
	c.Close()
	again, err := co.CtlValType(context.Background())
	if err != nil {
		t.Fatalf("CtlValType from cache: %v", err)
	}
	if again != mms.TypeBoolean {
		t.Errorf("cached ctlVal type = %s, want boolean", again)
	}
}

// ctlValModel builds one controllable object per common control CDC, so the
// ctlVal type of each can be read back.
func ctlValModel() *model.Model {
	oper := func(ctlVal *model.DataAttribute) *model.DataAttribute {
		return &model.DataAttribute{Name: "Oper", FC: model.CO, Kind: mms.TypeStructure, Children: []*model.DataAttribute{
			ctlVal,
			{Name: "origin", FC: model.CO, Kind: mms.TypeStructure, Children: []*model.DataAttribute{
				{Name: "orCat", FC: model.CO, Kind: mms.TypeInteger, Value: mms.NewInt8(0)},
				{Name: "orIdent", FC: model.CO, Kind: mms.TypeOctetString, Value: mms.NewOctetString(nil)},
			}},
			{Name: "ctlNum", FC: model.CO, Kind: mms.TypeUnsigned, Value: mms.NewUint8(0)},
			{Name: "T", FC: model.CO, Kind: mms.TypeUTCTime, Value: mms.NewUTCTimeNow()},
			{Name: "Test", FC: model.CO, Kind: mms.TypeBoolean, Value: mms.NewBool(false)},
			{Name: "Check", FC: model.CO, Kind: mms.TypeBitString, Value: mms.NewBitString(2)},
		}}
	}
	do := func(name, cdc string, ctlVal *model.DataAttribute) *model.DataObject {
		return &model.DataObject{Name: name, CDC: cdc, Attributes: []*model.DataAttribute{
			{Name: "ctlModel", FC: model.CF, Kind: mms.TypeInteger, Value: mms.NewInt32(int32(model.CtlDirectNormal))},
			oper(ctlVal),
		}}
	}
	ln := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{
		do("SPC1", "SPC", &model.DataAttribute{
			Name: "ctlVal", FC: model.CO, Kind: mms.TypeBoolean, Value: mms.NewBool(false)}),
		do("DPC1", "DPC", &model.DataAttribute{
			Name: "ctlVal", FC: model.CO, Kind: mms.TypeBitString, Value: mms.NewBitString(2)}),
		do("INC1", "INC", &model.DataAttribute{
			Name: "ctlVal", FC: model.CO, Kind: mms.TypeInteger, Value: mms.NewInt32(0)}),
		do("APC1", "APC", &model.DataAttribute{
			Name: "ctlVal", FC: model.CO, Kind: mms.TypeStructure, Children: []*model.DataAttribute{
				{Name: "f", FC: model.CO, Kind: mms.TypeFloat32, Value: mms.NewFloat32(0)},
			}}),
		// A plain indication: no control at all.
		{Name: "Ind1", CDC: "SPS", Attributes: []*model.DataAttribute{
			{Name: "stVal", FC: model.ST, Kind: mms.TypeBoolean, Value: mms.NewBool(false)},
		}},
	}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0"}
	ld := &model.LogicalDevice{Name: "CTLIED", Inst: "LD0", Nodes: []*model.LogicalNode{lln0, ln}}
	return &model.Model{Name: "CTLIED", Devices: []*model.LogicalDevice{ld}}
}

func TestCtlValTypePerCDC(t *testing.T) {
	srv := server.New(ctlValModel())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, tc := range []struct {
		ref  model.ObjectReference
		want mms.Type
	}{
		{"CTLIED/GGIO1.SPC1", mms.TypeBoolean},
		{"CTLIED/GGIO1.DPC1", mms.TypeBitString},
		{"CTLIED/GGIO1.INC1", mms.TypeInteger},
		{"CTLIED/GGIO1.APC1", mms.TypeStructure},
	} {
		co, err := c.ControlFor(ctx, tc.ref)
		if err != nil {
			t.Fatalf("ControlFor %s: %v", tc.ref, err)
		}
		got, err := co.CtlValType(ctx)
		if err != nil {
			t.Fatalf("CtlValType %s: %v", tc.ref, err)
		}
		if got != tc.want {
			t.Errorf("%s ctlVal type = %s, want %s", tc.ref, got, tc.want)
		}
	}

	// An analogue control carries a structure; its members say what the
	// server accepts.
	apc, err := c.ControlFor(ctx, "CTLIED/GGIO1.APC1")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := apc.CtlValSpec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Components) != 1 || spec.Components[0].Name != "f" {
		t.Fatalf("APC ctlVal components = %+v, want one named f", spec.Components)
	}
	if got := spec.Components[0].Spec.Kind; got != mms.TypeFloat32 {
		t.Errorf("APC ctlVal.f = %s, want float32", got)
	}

	// A bit-string ctlVal reports its width, which is what a DPC caller
	// needs to build the value. The sign carries the server's declaration:
	// this one reports bit strings as variable up to n bits.
	dpc, _ := c.ControlFor(ctx, "CTLIED/GGIO1.DPC1")
	dspec, err := dpc.CtlValSpec(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if dspec.Size != -2 && dspec.Size != 2 {
		t.Errorf("DPC ctlVal bit width = %d, want 2 bits", dspec.Size)
	}

	// An object with no control reports an error rather than a type.
	ind, err := c.ControlFor(ctx, "CTLIED/GGIO1.Ind1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ind.CtlValType(ctx); err == nil {
		t.Errorf("CtlValType of a non-controllable object = %s, want an error", got)
	}
}
