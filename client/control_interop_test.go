package client_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// TestClientControlInterop runs the control services against a live server
// with the objects of the reference control example: SPCSO3 direct and
// SPCSO4 SBO with enhanced security, and SPCSO9 direct-enhanced whose
// execution fails. Enable with IEC61850_TEST_CONTROL_SERVER=host:port.
func TestClientControlInterop(t *testing.T) {
	addr := os.Getenv("IEC61850_TEST_CONTROL_SERVER")
	if addr == "" {
		t.Skip("set IEC61850_TEST_CONTROL_SERVER=host:port to run control interop tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	lds, err := c.LogicalDevices(ctx)
	if err != nil || len(lds) == 0 {
		t.Fatalf("LogicalDevices: %v %v", lds, err)
	}
	obj := func(name string) model.ObjectReference {
		return model.ObjectReference(lds[0] + "/GGIO1." + name)
	}
	control := func(name string) *client.ControlObject {
		t.Helper()
		co, err := c.ControlFor(ctx, obj(name))
		if err != nil {
			t.Fatalf("ControlFor %s: %v", name, err)
		}
		return co
	}
	// Each operate gets its own deadline, so a missing CommandTermination
	// shows as that operate's failure rather than a hang.
	operate := func(co *client.ControlObject, opts ...client.ControlOption) error {
		octx, ocancel := context.WithTimeout(ctx, 3*time.Second)
		defer ocancel()
		return co.Operate(octx, mms.NewBool(true), opts...)
	}

	t.Run("DirectEnhancedTerminates", func(t *testing.T) {
		if err := operate(control("SPCSO3")); err != nil {
			t.Fatalf("Operate: %v", err)
		}
	})
	t.Run("SBOEnhancedTerminates", func(t *testing.T) {
		if err := operate(control("SPCSO4")); err != nil {
			t.Fatalf("Operate: %v", err)
		}
	})
	t.Run("OperateWithoutSelectReportsCause", func(t *testing.T) {
		co := control("SPCSO4")
		err := operate(co, client.WithModel(model.CtlDirectEnhanced)) // skips the select
		var ce *client.ControlError
		if !errors.As(err, &ce) || ce.Stage != "operate" {
			t.Fatalf("Operate without select: %v, want a refused operate", err)
		}
		if ce.AddCause == model.AddCauseUnknown {
			t.Errorf("AddCause unknown: the LastApplError was not received")
		}
		t.Logf("refused with %s", ce.AddCause)
	})
	t.Run("FailedExecutionTerminatesNegatively", func(t *testing.T) {
		err := operate(control("SPCSO9"))
		var ce *client.ControlError
		if !errors.As(err, &ce) || ce.Stage != "termination" || ce.Err != nil {
			t.Fatalf("Operate: %v, want a CommandTermination-", err)
		}
		t.Logf("terminated with %s", ce.AddCause)
	})
}
