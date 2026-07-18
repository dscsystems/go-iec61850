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

// sgModel builds a small protection model with a setting group: PTOC1 has
// OpDlTmms.setVal available under both SG (active) and SE (edit).
func sgModel() *model.Model {
	setVal := func(fc model.FC, v int32) *model.DataAttribute {
		return &model.DataAttribute{Name: "setVal", FC: fc, Kind: mms.TypeInteger, Value: mms.NewInt32(v)}
	}
	ptoc := &model.LogicalNode{Name: "PTOC1", Class: "PTOC", Objects: []*model.DataObject{
		{Name: "OpDlTmms", CDC: "ING", Attributes: []*model.DataAttribute{
			setVal(model.SG, 500),
			setVal(model.SE, 500),
		}},
	}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0"}
	ld := &model.LogicalDevice{Name: "DEMOPROT", Inst: "PROT", Nodes: []*model.LogicalNode{lln0, ptoc}}
	return &model.Model{Name: "DEMOPROT", Devices: []*model.LogicalDevice{ld}}
}

func TestSettingGroups(t *testing.T) {
	srv := server.New(sgModel(), server.WithSettingGroups(3))
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

	sgRef := model.ObjectReference("DEMOPROT/LLN0.SP.SGCB")
	setting := model.ObjectReference("DEMOPROT/PTOC1.OpDlTmms.setVal")

	sg, err := c.SettingGroups(ctx, sgRef)
	if err != nil {
		t.Fatalf("SettingGroups: %v", err)
	}
	if sg.NumOfSG != 3 || sg.ActSG != 1 {
		t.Fatalf("SGCB: NumOfSG=%d ActSG=%d", sg.NumOfSG, sg.ActSG)
	}

	// Edit group 2: select, change setVal, confirm.
	if err := sg.SelectEditSG(ctx, 2); err != nil {
		t.Fatalf("SelectEditSG: %v", err)
	}
	if err := sg.SetEditValue(ctx, setting, mms.NewInt32(1500)); err != nil {
		t.Fatalf("SetEditValue: %v", err)
	}
	if err := sg.ConfirmEdit(ctx); err != nil {
		t.Fatalf("ConfirmEdit: %v", err)
	}

	// Group 1 is still active, so the SG value is unchanged.
	v, err := c.Read(ctx, setting, model.SG)
	if err != nil || v.Int32() != 500 {
		t.Fatalf("active SG value = %v (err %v), want 500", v, err)
	}

	// Activate group 2: the SG value now reflects the edited value.
	if err := sg.SelectActiveSG(ctx, 2); err != nil {
		t.Fatalf("SelectActiveSG: %v", err)
	}
	v, err = c.Read(ctx, setting, model.SG)
	if err != nil || v.Int32() != 1500 {
		t.Fatalf("after activating group 2, SG value = %v (err %v), want 1500", v, err)
	}

	// Group 3 was never edited: still the default.
	if err := sg.SelectActiveSG(ctx, 3); err != nil {
		t.Fatalf("SelectActiveSG 3: %v", err)
	}
	v, _ = c.Read(ctx, setting, model.SG)
	if v.Int32() != 500 {
		t.Fatalf("group 3 SG value = %v, want 500", v)
	}
	t.Logf("setting groups: edited g2 -> 1500, g1/g3 remain 500")
}
