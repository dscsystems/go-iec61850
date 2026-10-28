package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// A control write to an object that has no control service — no Oper,
// SBOw or Cancel under FC CO — names a variable that does not exist. It
// was taken for a direct control because ctlModel was absent too, and
// applied to stVal: a write of status (FC ST) past WithWritableFCs and
// OnWrite, on any status object (issue #35).
func TestForgedControlWriteRefused(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	const st = "simpleIOGenericIO/GGIO1.Beh.stVal"
	before := srv.Read(st, model.ST)
	if before == nil {
		t.Fatalf("%s not in the model", st)
	}
	for _, phase := range []string{"Oper", "SBOw", "Cancel"} {
		err := c.Write(ctx, model.ObjectReference("simpleIOGenericIO/GGIO1.Beh."+phase), model.CO,
			mms.NewStructure(mms.NewInt8(int8(before.Int64()+1))))
		var dae mms.DataAccessError
		if !errors.As(err, &dae) || dae != mms.AccessObjectNonExistent {
			t.Errorf("write Beh.%s[CO]: %v, want object-non-existent", phase, err)
		}
	}
	if after := srv.Read(st, model.ST); after.Int64() != before.Int64() {
		t.Errorf("%s changed from %v to %v through a forged control write", st, before, after)
	}

	// A real control object is still operated.
	co, err := c.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO1")
	if err != nil {
		t.Fatal(err)
	}
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("operate SPCSO1: %v", err)
	}
	if v := srv.Read("simpleIOGenericIO/GGIO1.SPCSO1.stVal", model.ST); v == nil || !v.Bool() {
		t.Errorf("SPCSO1.stVal = %v after operate true", v)
	}
}
