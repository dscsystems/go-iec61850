package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
)

// TestVariableAccessLevels checks that getVariableAccessAttributes returns
// structures at logical-node and functional-constraint level (as
// conformant servers do), and that a non-existent variable yields a
// well-formed ConfirmedErrorPDU that the client decodes as an access error
// rather than hanging.
func TestVariableAccessLevels(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	mc := c.MMS()
	const dom = "simpleIOGenericIO"

	// Logical-node level: a structure with one member per FC.
	ln, err := mc.GetVariableAccessAttributes(ctx, dom, "GGIO1")
	if err != nil {
		t.Fatalf("LN type spec: %v", err)
	}
	if ln.Kind != mms.TypeStructure || len(ln.Components) == 0 {
		t.Fatalf("LN spec = %v with %d components", ln.Kind, len(ln.Components))
	}

	// FC level: a structure with one member per data object.
	fc, err := mc.GetVariableAccessAttributes(ctx, dom, "GGIO1$MX")
	if err != nil {
		t.Fatalf("FC type spec: %v", err)
	}
	if fc.Kind != mms.TypeStructure || len(fc.Components) == 0 {
		t.Fatalf("FC spec = %v with %d components", fc.Kind, len(fc.Components))
	}

	// Non-existent variable: a routed access error, not a timeout.
	deadline, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()
	_, err = mc.GetVariableAccessAttributes(deadline, dom, "DoesNotExist")
	if err == nil {
		t.Fatal("expected an error for a non-existent variable")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("error PDU was not routed (client timed out) — malformed error PDU")
	}
	var se *mms.ServiceError
	if !errors.As(err, &se) {
		t.Fatalf("expected *mms.ServiceError, got %T: %v", err, err)
	}
	if se.Class != 7 { // access
		t.Fatalf("error class = %d, want 7 (access)", se.Class)
	}
	t.Logf("non-existent -> %v", err)
}
