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

// sboModel builds a controllable SPC with the sbo-with-normal-security
// control model (ctlModel = 2), including the SBO, Oper and stVal members.
func sboModel() *model.Model {
	operStruct := &model.DataAttribute{Name: "Oper", FC: model.CO, Kind: mms.TypeStructure, Children: []*model.DataAttribute{
		{Name: "ctlVal", FC: model.CO, Kind: mms.TypeBoolean, Value: mms.NewBool(false)},
		{Name: "origin", FC: model.CO, Kind: mms.TypeStructure, Children: []*model.DataAttribute{
			{Name: "orCat", FC: model.CO, Kind: mms.TypeInteger, Value: mms.NewInt8(0)},
			{Name: "orIdent", FC: model.CO, Kind: mms.TypeOctetString, Value: mms.NewOctetString(nil)},
		}},
		{Name: "ctlNum", FC: model.CO, Kind: mms.TypeUnsigned, Value: mms.NewUint8(0)},
		{Name: "T", FC: model.CO, Kind: mms.TypeUTCTime, Value: mms.NewUTCTimeNow()},
		{Name: "Test", FC: model.CO, Kind: mms.TypeBoolean, Value: mms.NewBool(false)},
		{Name: "Check", FC: model.CO, Kind: mms.TypeBitString, Value: mms.NewBitString(2)},
	}}
	spc := &model.DataObject{Name: "SPCSO1", CDC: "SPC", Attributes: []*model.DataAttribute{
		{Name: "stVal", FC: model.ST, Kind: mms.TypeBoolean, Value: mms.NewBool(false)},
		{Name: "ctlModel", FC: model.CF, Kind: mms.TypeInteger, Value: mms.NewInt32(int32(model.CtlSBONormal))},
		{Name: "SBO", FC: model.CO, Kind: mms.TypeVisibleString, Value: mms.NewVisibleString("")},
		operStruct,
	}}
	ln := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{spc}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0"}
	ld := &model.LogicalDevice{Name: "SBOIED", Inst: "LD0", Nodes: []*model.LogicalNode{lln0, ln}}
	return &model.Model{Name: "SBOIED", Devices: []*model.LogicalDevice{ld}}
}

func TestSBOSelectBeforeOperate(t *testing.T) {
	srv := server.New(sboModel())
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

	ref := model.ObjectReference("SBOIED/GGIO1.SPCSO1")
	co, err := c.ControlFor(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if co.Model() != model.CtlSBONormal {
		t.Fatalf("control model = %s, want sbo-normal", co.Model())
	}

	// Operate() for an SBO model selects then operates in one call.
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("Operate (select+operate): %v", err)
	}
	if v := srv.Read(ref.Child("stVal"), model.ST); v == nil || !v.Bool() {
		t.Fatalf("stVal after operate = %v, want true", v)
	}

	// A bare operate without a preceding select must be rejected.
	results, err := c.MMS().Write(ctx, "SBOIED",
		[]string{"GGIO1$CO$SPCSO1$Oper"},
		[]*mms.Value{buildBareOper()})
	if err != nil {
		t.Fatalf("write Oper: %v", err)
	}
	if len(results) == 0 || results[0] == nil {
		t.Fatal("operate without select should have been denied")
	}
	t.Logf("operate without select correctly denied: %v", results[0])
}

func buildBareOper() *mms.Value {
	return mms.NewStructure(
		mms.NewBool(true),
		mms.NewStructure(mms.NewInt8(2), mms.NewOctetString(nil)),
		mms.NewUint8(1),
		mms.NewUTCTimeNow(),
		mms.NewBool(false),
		mms.NewBitString(2),
	)
}
