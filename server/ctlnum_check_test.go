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

// sboCheckModel is an sbo-with-enhanced-security control plus the
// LastApplError the server reports its diagnosis through.
func sboCheckModel(ctlModel model.CtlModel) *model.Model {
	ctlStruct := func(name string) *model.DataAttribute {
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
		{Name: "ctlModel", FC: model.CF, Kind: mms.TypeInteger, Value: mms.NewInt32(int32(ctlModel))},
		{Name: "SBO", FC: model.CO, Kind: mms.TypeVisibleString, Value: mms.NewVisibleString("")},
		ctlStruct("SBOw"),
		ctlStruct("Oper"),
		ctlStruct("Cancel"),
	}}
	lastApplError := &model.DataObject{Name: "LastApplError", CDC: "LastApplError", Attributes: []*model.DataAttribute{
		{Name: "Error", FC: model.ST, Kind: mms.TypeInteger, Value: mms.NewInt32(0)},
		{Name: "AddCause", FC: model.ST, Kind: mms.TypeInteger, Value: mms.NewInt32(0)},
	}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0", Objects: []*model.DataObject{lastApplError}}
	ln := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{spc}}
	ld := &model.LogicalDevice{Name: "SELIED", Inst: "LD0", Nodes: []*model.LogicalNode{lln0, ln}}
	return &model.Model{Name: "SELIED", Devices: []*model.LogicalDevice{ld}}
}

func startSelectServer(t *testing.T, ctlModel model.CtlModel) string {
	t.Helper()
	srv := server.New(sboCheckModel(ctlModel))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

const selRef = model.ObjectReference("SELIED/GGIO1.SPCSO1")

// ctlStructValue builds an Oper/SBOw/Cancel structure with a chosen ctlNum.
func ctlStructValue(ctlVal bool, ctlNum uint8) *mms.Value {
	return mms.NewStructure(
		mms.NewBool(ctlVal),
		mms.NewStructure(mms.NewInt8(2), mms.NewOctetString(nil)),
		mms.NewUint8(ctlNum),
		mms.NewUTCTimeNow(),
		mms.NewBool(false),
		mms.NewBitString(2),
	)
}

// writeCtl writes a control structure directly, bypassing the client's own
// sequence handling so the server's checking can be exercised.
func writeCtl(t *testing.T, ctx context.Context, c *client.Client, phase string, ctlVal bool, ctlNum uint8) error {
	t.Helper()
	results, err := c.MMS().Write(ctx, "SELIED",
		[]string{"GGIO1$CO$SPCSO1$" + phase}, []*mms.Value{ctlStructValue(ctlVal, ctlNum)})
	if err != nil {
		t.Fatalf("write %s: %v", phase, err)
	}
	if len(results) > 0 && results[0] != nil {
		return results[0]
	}
	return nil
}

func lastAddCause(t *testing.T, ctx context.Context, c *client.Client) model.AddCause {
	t.Helper()
	v, err := c.Read(ctx, "SELIED/LLN0.LastApplError.AddCause", model.ST)
	if err != nil {
		t.Fatalf("read LastApplError: %v", err)
	}
	return model.AddCause(v.Int64())
}

// An operate carrying a different ctlNum from the select belongs to another
// control sequence, and the server must refuse it rather than act on it.
func TestServerRejectsOperateWithMismatchedCtlNum(t *testing.T) {
	addr := startSelectServer(t, model.CtlSBOEnhanced)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := writeCtl(t, ctx, c, "SBOw", true, 7); err != nil {
		t.Fatalf("select: %v", err)
	}
	if err := writeCtl(t, ctx, c, "Oper", true, 8); err == nil {
		t.Fatal("operate with a foreign ctlNum was accepted")
	}
	if got := lastAddCause(t, ctx, c); got != model.AddCauseInconsistentParameters {
		t.Errorf("AddCause = %s, want inconsistent-parameters", got)
	}
	if v := c.MMS(); v == nil {
		t.Fatal("connection lost")
	}
	// The rejected operate must not have been applied.
	if v, err := c.Read(ctx, selRef.Child("stVal"), model.ST); err != nil || v.Bool() {
		t.Errorf("stVal = %v (err %v), want false: the operate was executed anyway", v, err)
	}

	// The selection survives a rejected operate, so the right ctlNum still
	// completes the sequence.
	if err := writeCtl(t, ctx, c, "Oper", true, 7); err != nil {
		t.Fatalf("operate with the selected ctlNum: %v", err)
	}
	if v, err := c.Read(ctx, selRef.Child("stVal"), model.ST); err != nil || !v.Bool() {
		t.Errorf("stVal = %v (err %v), want true", v, err)
	}
}

// An enhanced-security operate with no select at all used to be accepted:
// the selection check only ran for normal security.
func TestServerRequiresSelectForEnhancedOperate(t *testing.T) {
	addr := startSelectServer(t, model.CtlSBOEnhanced)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := writeCtl(t, ctx, c, "Oper", true, 1); err == nil {
		t.Fatal("operate without a select was accepted")
	}
	if got := lastAddCause(t, ctx, c); got != model.AddCauseObjectNotSelected {
		t.Errorf("AddCause = %s, want object-not-selected", got)
	}
	if v, err := c.Read(ctx, selRef.Child("stVal"), model.ST); err != nil || v.Bool() {
		t.Errorf("stVal = %v (err %v), want false", v, err)
	}
}

// Normal security selects with an SBO read, which carries no ctlNum: there
// is nothing to compare, and the operate must not be refused for it.
func TestServerNormalSecurityHasNoCtlNumToMatch(t *testing.T) {
	addr := startSelectServer(t, model.CtlSBONormal)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	co, err := c.ControlFor(ctx, selRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := co.Select(ctx); err != nil {
		t.Fatalf("Select: %v", err)
	}
	if err := writeCtl(t, ctx, c, "Oper", true, 42); err != nil {
		t.Fatalf("operate after an SBO select: %v", err)
	}
	if v, err := c.Read(ctx, selRef.Child("stVal"), model.ST); err != nil || !v.Bool() {
		t.Errorf("stVal = %v (err %v), want true", v, err)
	}
}

// A cancel names the sequence it ends: another client's cancel, or one
// with a foreign ctlNum, must leave the reservation alone.
func TestServerCancelChecksOwnershipAndCtlNum(t *testing.T) {
	addr := startSelectServer(t, model.CtlSBOEnhanced)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if err := writeCtl(t, ctx, a, "SBOw", true, 3); err != nil {
		t.Fatalf("select: %v", err)
	}

	// Another client cannot end A's sequence.
	if err := writeCtl(t, ctx, b, "Cancel", true, 3); err == nil {
		t.Error("a cancel from another connection was accepted")
	}
	// Nor can A with the wrong control number.
	if err := writeCtl(t, ctx, a, "Cancel", true, 4); err == nil {
		t.Error("a cancel with a foreign ctlNum was accepted")
	}
	if got := lastAddCause(t, ctx, a); got != model.AddCauseInconsistentParameters {
		t.Errorf("AddCause = %s, want inconsistent-parameters", got)
	}

	// A's selection is intact, so its operate still goes through.
	if err := writeCtl(t, ctx, a, "Oper", true, 3); err != nil {
		t.Fatalf("operate after the refused cancels: %v", err)
	}

	// And the matching cancel is accepted, ending the sequence.
	if err := writeCtl(t, ctx, a, "SBOw", true, 5); err != nil {
		t.Fatalf("second select: %v", err)
	}
	if err := writeCtl(t, ctx, a, "Cancel", true, 5); err != nil {
		t.Errorf("cancel of its own sequence: %v", err)
	}
	if err := writeCtl(t, ctx, a, "Oper", true, 5); err == nil {
		t.Error("operate after a cancel was accepted")
	}
}

// A select must not take an object another client is holding: the server
// used to overwrite the reservation, which handed the object over and left
// the first client's operate to fail with a confusing diagnosis.
func TestServerSelectDoesNotStealAnotherClientsReservation(t *testing.T) {
	addr := startSelectServer(t, model.CtlSBOEnhanced)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	if err := writeCtl(t, ctx, a, "SBOw", true, 1); err != nil {
		t.Fatalf("A select: %v", err)
	}
	if err := writeCtl(t, ctx, b, "SBOw", true, 9); err == nil {
		t.Fatal("B selected an object A holds")
	}
	if got := lastAddCause(t, ctx, b); got != model.AddCauseObjectAlreadySelected {
		t.Errorf("AddCause = %s, want object-already-selected", got)
	}
	// B's rejected select must not have disturbed A's reservation.
	if err := writeCtl(t, ctx, b, "Oper", true, 9); err == nil {
		t.Error("B operated on A's selection")
	}
	if err := writeCtl(t, ctx, a, "Oper", true, 1); err != nil {
		t.Fatalf("A operate after B's attempt: %v", err)
	}

	// A's operate ended the sequence and released the object, so B may
	// have it now.
	if err := writeCtl(t, ctx, b, "SBOw", false, 9); err != nil {
		t.Errorf("B select after A finished: %v", err)
	}
	if err := writeCtl(t, ctx, b, "Oper", false, 9); err != nil {
		t.Errorf("B operate: %v", err)
	}
	if v, err := a.Read(ctx, selRef.Child("stVal"), model.ST); err != nil || v.Bool() {
		t.Errorf("stVal = %v (err %v), want false after B's operate", v, err)
	}
}

// Re-selecting an object you already hold is not stealing: it starts a new
// sequence with a new control number.
func TestServerReselectByTheSameClient(t *testing.T) {
	addr := startSelectServer(t, model.CtlSBOEnhanced)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := writeCtl(t, ctx, c, "SBOw", true, 1); err != nil {
		t.Fatalf("select: %v", err)
	}
	if err := writeCtl(t, ctx, c, "SBOw", true, 2); err != nil {
		t.Fatalf("re-select: %v", err)
	}
	// The reservation now names the second sequence.
	if err := writeCtl(t, ctx, c, "Oper", true, 1); err == nil {
		t.Error("operate with the abandoned control number was accepted")
	}
	if err := writeCtl(t, ctx, c, "Oper", true, 2); err != nil {
		t.Errorf("operate with the current control number: %v", err)
	}
}

// The client drives a whole sequence with one control number, so nothing
// above has to change for it.
func TestClientSequenceStillPassesServerChecks(t *testing.T) {
	addr := startSelectServer(t, model.CtlSBOEnhanced)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	co, err := c.ControlFor(ctx, selRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("Operate: %v", err)
	}
	if v, err := c.Read(ctx, selRef.Child("stVal"), model.ST); err != nil || !v.Bool() {
		t.Errorf("stVal = %v (err %v), want true", v, err)
	}
	// A second sequence takes a new number and is accepted just the same.
	if err := co.Operate(ctx, mms.NewBool(false)); err != nil {
		t.Fatalf("second Operate: %v", err)
	}
}
