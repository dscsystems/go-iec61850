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

// sbowModel builds a controllable SPC with sbo-with-enhanced-security
// (ctlModel = 4), so both the select (SBOw) and the operate carry the full
// control structure and reach the control handler.
func sbowModel() *model.Model {
	operMembers := func(name string) *model.DataAttribute {
		return &model.DataAttribute{Name: name, FC: model.CO, Kind: mms.TypeStructure, Children: []*model.DataAttribute{
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
	}
	spc := &model.DataObject{Name: "SPCSO1", CDC: "SPC", Attributes: []*model.DataAttribute{
		{Name: "stVal", FC: model.ST, Kind: mms.TypeBoolean, Value: mms.NewBool(false)},
		{Name: "ctlModel", FC: model.CF, Kind: mms.TypeInteger, Value: mms.NewInt32(int32(model.CtlSBOEnhanced))},
		operMembers("SBOw"),
		operMembers("Oper"),
		operMembers("Cancel"),
	}}
	ln := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{spc}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0"}
	ld := &model.LogicalDevice{Name: "SBOWIED", Inst: "LD0", Nodes: []*model.LogicalNode{lln0, ln}}
	return &model.Model{Name: "SBOWIED", Devices: []*model.LogicalDevice{ld}}
}

func startSBOwServer(t *testing.T) (string, *server.Server) {
	t.Helper()
	srv := server.New(sbowModel())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), srv
}

// IEC 61850-7-2: ctlNum is incremented once per control sequence and is
// identical in the select and the operate of that sequence. The client used
// to increment it in every buildOper call, so the operate arrived with
// select's ctlNum + 1 — servers that check the pair reject that as
// inconsistent-parameters.
func TestCtlNumIsConstantWithinASequence(t *testing.T) {
	addr, srv := startSBOwServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ref := model.ObjectReference("SBOWIED/GGIO1.SPCSO1")
	type phase struct {
		selectPhase bool
		ctlNum      uint8
	}
	var phases []phase
	srv.OnControl(ref, func(cc *server.ControlCtx) model.AddCause {
		phases = append(phases, phase{cc.Select, cc.CtlNum})
		return model.AddCauseNone
	})

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	co, err := c.ControlFor(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if co.Model() != model.CtlSBOEnhanced {
		t.Fatalf("control model = %s, want sbo-enhanced", co.Model())
	}

	// Two complete sequences: select+operate, twice.
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("first Operate: %v", err)
	}
	first := co.CtlNum()
	if err := co.Operate(ctx, mms.NewBool(false)); err != nil {
		t.Fatalf("second Operate: %v", err)
	}
	second := co.CtlNum()

	if len(phases) != 4 {
		t.Fatalf("control handler saw %d requests, want 4: %+v", len(phases), phases)
	}
	if !phases[0].selectPhase || phases[1].selectPhase || !phases[2].selectPhase || phases[3].selectPhase {
		t.Fatalf("phases out of order: %+v", phases)
	}
	if phases[0].ctlNum != phases[1].ctlNum {
		t.Errorf("sequence 1: select ctlNum = %d, operate ctlNum = %d; they must match",
			phases[0].ctlNum, phases[1].ctlNum)
	}
	if phases[2].ctlNum != phases[3].ctlNum {
		t.Errorf("sequence 2: select ctlNum = %d, operate ctlNum = %d; they must match",
			phases[2].ctlNum, phases[3].ctlNum)
	}
	// A new sequence must not reuse the previous number.
	if phases[0].ctlNum == phases[2].ctlNum {
		t.Errorf("both sequences used ctlNum %d; it must be incremented per sequence", phases[0].ctlNum)
	}
	if first != phases[0].ctlNum || second != phases[2].ctlNum {
		t.Errorf("CtlNum() reported %d then %d, want %d then %d",
			first, second, phases[0].ctlNum, phases[2].ctlNum)
	}
}

// A separately driven select, cancel and operate must all stay on one
// control number until the sequence is closed.
func TestCtlNumSpansSelectCancelAndOperate(t *testing.T) {
	addr, srv := startSBOwServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ref := model.ObjectReference("SBOWIED/GGIO1.SPCSO1")
	var nums []uint8
	srv.OnControl(ref, func(cc *server.ControlCtx) model.AddCause {
		nums = append(nums, cc.CtlNum)
		return model.AddCauseNone
	})

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	co, err := c.ControlFor(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}

	// Select, then abandon the sequence with a cancel.
	if err := co.SelectWithValue(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("SelectWithValue: %v", err)
	}
	selected := co.CtlNum()
	if err := co.Cancel(ctx); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if co.CtlNum() != selected {
		t.Errorf("Cancel used ctlNum %d, want the selected %d", co.CtlNum(), selected)
	}

	// The cancel closed the sequence, so a fresh select+operate takes a new
	// number and keeps it across both requests.
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("Operate: %v", err)
	}
	if co.CtlNum() == selected {
		t.Errorf("the sequence after a cancel reused ctlNum %d", selected)
	}

	// The handler sees SBOw, SBOw, Oper — Cancel is answered by the server
	// without consulting the handler.
	if len(nums) != 3 {
		t.Fatalf("control handler saw %d requests, want 3: %v", len(nums), nums)
	}
	if nums[0] != selected {
		t.Errorf("select ctlNum = %d, want %d", nums[0], selected)
	}
	if nums[1] != nums[2] {
		t.Errorf("select/operate of the second sequence used %d and %d", nums[1], nums[2])
	}
	if nums[1] == selected {
		t.Errorf("second sequence reused the cancelled sequence's ctlNum %d", selected)
	}
}
