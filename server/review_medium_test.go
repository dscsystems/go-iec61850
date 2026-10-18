package server_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// An operate whose ctlVal does not have Oper.ctlVal's type is refused and
// leaves stVal as it was: it would otherwise enter the process image.
func TestOperateWithMistypedCtlValIsRefused(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	lds, _ := c.LogicalDevices(ctx)
	ref := model.ObjectReference(lds[0] + "/GGIO1.SPCSO1")
	co, err := c.ControlFor(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	before := srv.Read(ref.Child("stVal"), model.ST)
	if err := co.Operate(ctx, mms.NewInt32(5)); err == nil {
		t.Fatal("an INT32 ctlVal for a BOOLEAN control was accepted")
	}
	after := srv.Read(ref.Child("stVal"), model.ST)
	if after.Type() != mms.TypeBoolean || after.Bool() != before.Bool() {
		t.Errorf("stVal = %s after the refused operate, was %s", after, before)
	}
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("a well-typed operate: %v", err)
	}
	if v := srv.Read(ref.Child("stVal"), model.ST); !v.Bool() {
		t.Errorf("stVal = %s after operating true", v)
	}
}

// Client-defined datasets outlive their association, so the server bounds
// how many there are.
func TestDynamicDataSetsAreBounded(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	lds, _ := c.LogicalDevices(ctx)
	member := []mms.VarRef{{Domain: lds[0], Item: "GGIO1$ST$SPCSO1$stVal"}}
	for i := 0; ; i++ {
		err := c.MMS().DefineNamedVariableList(ctx, lds[0], fmt.Sprintf("LLN0$dyn%d", i), member)
		if err != nil {
			var se *mms.ServiceError
			if !asServiceError(err, &se) || se.Class != 3 || se.Code != 4 {
				t.Fatalf("dataset %d refused with %v, want resource capability-unavailable", i+1, err)
			}
			if i == 0 {
				t.Fatal("no dataset could be defined")
			}
			return
		}
		if i > 1000 {
			t.Fatal("no bound on client-defined datasets")
		}
	}
}

func asServiceError(err error, target **mms.ServiceError) bool {
	se, ok := err.(*mms.ServiceError)
	if ok {
		*target = se
	}
	return ok
}
