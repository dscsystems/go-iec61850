package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

func TestControlOperate(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var gotCtx *server.ControlCtx
	spcso1 := model.ObjectReference("simpleIOGenericIO/GGIO1.SPCSO1")
	srv.OnControl(spcso1, func(cc *server.ControlCtx) model.AddCause {
		gotCtx = cc
		return model.AddCauseNone // accept
	})

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	co, err := c.ControlFor(ctx, spcso1)
	if err != nil {
		t.Fatalf("ControlFor: %v", err)
	}

	if err := co.Operate(ctx, mms.NewBool(true),
		client.WithOriginator(model.OrCatStationControl, "scada-1")); err != nil {
		t.Fatalf("Operate: %v", err)
	}

	if gotCtx == nil {
		t.Fatal("control handler not invoked")
	}
	if !gotCtx.Value.Bool() || gotCtx.OrIdent != "scada-1" || gotCtx.Origin != model.OrCatStationControl {
		t.Fatalf("control ctx wrong: %+v", gotCtx)
	}
	// stVal should reflect the operate.
	if v := srv.Read(spcso1.Child("stVal"), model.ST); v == nil || !v.Bool() {
		t.Fatalf("stVal not updated: %v", v)
	}

	// Read back over the wire too.
	rv, err := c.Read(ctx, spcso1.Child("stVal"), model.ST)
	if err != nil || !rv.Bool() {
		t.Fatalf("read stVal: %v %v", rv, err)
	}
}

func TestControlDenied(t *testing.T) {
	addr, srv := startServer(t)
	spcso2 := model.ObjectReference("simpleIOGenericIO/GGIO1.SPCSO2")
	srv.OnControl(spcso2, func(cc *server.ControlCtx) model.AddCause {
		return model.AddCauseBlockedByInterlocking
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	co, err := c.ControlFor(ctx, spcso2)
	if err != nil {
		t.Fatal(err)
	}
	err = co.Operate(ctx, mms.NewBool(true))
	if err == nil {
		t.Fatal("expected control to be denied")
	}
	t.Logf("denied as expected: %v", err)
}
