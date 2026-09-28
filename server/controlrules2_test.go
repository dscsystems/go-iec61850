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

// ruleFixture serves a device with one control object of each control model,
// recording every operate that reaches a handler.
type ruleFixture struct {
	addr  string
	got   []*server.ControlCtx
	cause map[model.ObjectReference]model.AddCause
}

const ruleDomain = "RULE"

// ruleModel builds a logical device with SPCSO1 (direct-normal), SPCSO2
// (SBO-enhanced) and SPCSO3 (direct-enhanced).
func ruleModel() *model.Model {
	structure := func(name string) *model.DataAttribute {
		return &model.DataAttribute{Name: name, FC: model.CO, Kind: mms.TypeStructure,
			Children: []*model.DataAttribute{
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
	spc := func(name string, cm model.CtlModel) *model.DataObject {
		do := &model.DataObject{Name: name, CDC: "SPC", Attributes: []*model.DataAttribute{
			{Name: "stVal", FC: model.ST, Kind: mms.TypeBoolean, Value: mms.NewBool(false)},
			{Name: "ctlModel", FC: model.CF, Kind: mms.TypeInteger, Value: mms.NewInt32(int32(cm))},
		}}
		if cm == model.CtlSBOEnhanced {
			do.Attributes = append(do.Attributes, structure("SBOw"))
		} else if cm == model.CtlSBONormal {
			do.Attributes = append(do.Attributes,
				&model.DataAttribute{Name: "SBO", FC: model.CO, Kind: mms.TypeVisibleString,
					Value: mms.NewVisibleString("")})
		}
		do.Attributes = append(do.Attributes, structure("Oper"), structure("Cancel"))
		return do
	}
	ln := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{
		spc("SPCSO1", model.CtlDirectNormal),
		spc("SPCSO2", model.CtlSBOEnhanced),
		spc("SPCSO3", model.CtlDirectEnhanced),
	}}
	ld := &model.LogicalDevice{Name: ruleDomain, Inst: "LD0", Nodes: []*model.LogicalNode{ln}}
	return &model.Model{Name: "RULE", Devices: []*model.LogicalDevice{ld}}
}

func newRuleFixture(t *testing.T) *ruleFixture {
	t.Helper()
	f := &ruleFixture{cause: map[model.ObjectReference]model.AddCause{}}
	srv := server.New(ruleModel())
	for _, ref := range []model.ObjectReference{
		"RULE/GGIO1.SPCSO1", "RULE/GGIO1.SPCSO2", "RULE/GGIO1.SPCSO3",
	} {
		ref := ref
		srv.OnControl(ref, func(cc *server.ControlCtx) model.AddCause {
			f.got = append(f.got, cc)
			if c, ok := f.cause[ref]; ok {
				return c
			}
			return model.AddCauseNone
		})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	f.addr = ln.Addr().String()
	return f
}

func (f *ruleFixture) dial(t *testing.T) *client.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, err := client.Dial(ctx, f.addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// operValue builds an Oper structure with the flags a rule test needs: the
// Test bit and the originator identifier length are what the rules look at.
func operValue(ctlNum uint8, test bool, orIdentLen int) *mms.Value {
	return mms.NewStructure(
		mms.NewBool(true),
		mms.NewStructure(
			mms.NewInt8(int8(model.OrCatStationControl)),
			mms.NewOctetString(make([]byte, orIdentLen)),
		),
		mms.NewUint8(ctlNum),
		mms.NewUTCTimeNow(),
		mms.NewBool(test),
		mms.NewBitString(2),
	)
}

// writeOper writes a control structure directly, so the server's own
// checking is exercised rather than the client's sequence handling.
func writeOper(t *testing.T, c *client.Client, obj string, v *mms.Value) error {
	t.Helper()
	results, err := c.MMS().Write(context.Background(), ruleDomain,
		[]string{"GGIO1$CO$" + obj + "$Oper"}, []*mms.Value{v})
	if err != nil {
		t.Fatalf("write Oper: %v", err)
	}
	if len(results) > 0 && results[0] != nil {
		return results[0]
	}
	return nil
}

// The operate timestamp reaches the handler. It is the client's statement of
// when it decided to operate, which an audit trail needs and which the
// server was silently discarding.
func TestOperateTimestampReachesTheHandler(t *testing.T) {
	f := newRuleFixture(t)
	c := f.dial(t)
	if err := writeOper(t, c, "SPCSO1", operValue(1, false, 4)); err != nil {
		t.Fatalf("operate refused: %v", err)
	}
	if len(f.got) != 1 {
		t.Fatalf("%d operates reached the handler, want 1", len(f.got))
	}
	got := f.got[0].T
	if time.Since(got) < -time.Minute || time.Since(got) > time.Hour {
		t.Errorf("operate timestamp %v is not near now", got)
	}
}

// A test-flagged operate on an enhanced-security object is refused. The Test
// flag would skip the CommandTermination the client relies on to confirm the
// command, which is the whole point of enhanced security.
func TestTestFlagIsRefusedOnEnhancedSecurity(t *testing.T) {
	for _, tc := range []struct {
		obj      string
		refuse   bool
		ctlModel model.CtlModel
	}{
		{"SPCSO2", true, model.CtlSBOEnhanced},
		{"SPCSO3", true, model.CtlDirectEnhanced},
		{"SPCSO1", false, model.CtlDirectNormal},
	} {
		f := newRuleFixture(t)
		c := f.dial(t)
		err := writeOper(t, c, tc.obj, operValue(1, true, 4))
		if tc.refuse && err == nil {
			t.Errorf("%v (%v): a test operate was accepted", tc.obj, tc.ctlModel)
		}
		if tc.refuse && len(f.got) != 0 {
			t.Errorf("%v: the test operate reached the handler", tc.obj)
		}
		if !tc.refuse {
			if err != nil {
				t.Errorf("%v (%v): a test operate was refused: %v", tc.obj, tc.ctlModel, err)
			}
			if len(f.got) != 1 {
				t.Errorf("%v: the test operate did not reach the handler", tc.obj)
			}
		}
	}
}

// The diagnosis for a refused test operate is the one 7-2 names.
func TestTestNotAllowedAddCause(t *testing.T) {
	f := newRuleFixture(t)
	c := f.dial(t)
	if err := writeOper(t, c, "SPCSO2", operValue(9, true, 4)); err == nil {
		t.Fatal("a test operate was accepted on an enhanced-security object")
	}
	cause := lastAddCause(t, context.Background(), c)
	if cause != model.AddCauseTestNotAllowed {
		t.Errorf("AddCause = %v, want test-not-allowed", cause)
	}
}

// The originator identifier is bounded to what the standard types it as:
// an OctetString(0..64).
func TestOriginatorLengthIsBounded(t *testing.T) {
	for _, tc := range []struct {
		n      int
		accept bool
	}{
		{0, true}, {1, true}, {32, true}, {64, true}, {65, false}, {200, false},
	} {
		f := newRuleFixture(t)
		c := f.dial(t)
		err := writeOper(t, c, "SPCSO1", operValue(1, false, tc.n))
		if tc.accept && err != nil {
			t.Errorf("%d-octet originator refused: %v", tc.n, err)
		}
		if !tc.accept {
			if err == nil {
				t.Errorf("%d-octet originator accepted, want refused", tc.n)
			}
			if len(f.got) != 0 {
				t.Errorf("%d-octet originator reached the handler", tc.n)
			}
		}
	}
}
