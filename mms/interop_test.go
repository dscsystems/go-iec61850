package mms_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
)

// TestInterop exercises the MMS client against a live IEC 61850 server.
// Set IEC61850_TEST_SERVER=host:port (for example the libiec61850
// server_example_basic_io on 127.0.0.1:10102) to enable it; the test is
// skipped otherwise so CI without a server stays green. A dedicated
// docker-based interop harness runs this in the full pipeline.
func TestInterop(t *testing.T) {
	addr := os.Getenv("IEC61850_TEST_SERVER")
	if addr == "" {
		t.Skip("set IEC61850_TEST_SERVER=host:port to run MMS interop tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := mms.Dial(ctx, addr, mms.Options{ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	t.Run("Identify", func(t *testing.T) {
		vendor, model, rev, err := c.Identify(ctx)
		if err != nil {
			t.Fatalf("Identify: %v", err)
		}
		if vendor == "" && model == "" && rev == "" {
			t.Fatal("Identify returned all-empty")
		}
		t.Logf("vendor=%q model=%q rev=%q", vendor, model, rev)
	})

	var domain string
	t.Run("GetNameList domains", func(t *testing.T) {
		domains, err := c.GetNameList(ctx, mms.ClassDomain, "")
		if err != nil {
			t.Fatalf("GetNameList domains: %v", err)
		}
		if len(domains) == 0 {
			t.Fatal("no domains")
		}
		domain = domains[0]
		t.Logf("domains=%v", domains)
	})

	var firstVar string
	t.Run("GetNameList variables", func(t *testing.T) {
		vars, err := c.GetNameList(ctx, mms.ClassNamedVariable, domain)
		if err != nil {
			t.Fatalf("GetNameList vars: %v", err)
		}
		if len(vars) == 0 {
			t.Fatal("no variables")
		}
		// Find a leaf variable to read (contains an FC separator).
		for _, v := range vars {
			if len(v) > 4 && contains(v, "$") {
				firstVar = v
			}
		}
		t.Logf("%d variables, sample leaf=%q", len(vars), firstVar)
	})

	t.Run("Read", func(t *testing.T) {
		vals, err := c.Read(ctx, domain, "GGIO1$CF$SPCSO1$ctlModel")
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(vals) != 1 {
			t.Fatalf("expected 1 value, got %d", len(vals))
		}
		if vals[0].Type() != mms.TypeInteger {
			t.Fatalf("ctlModel type = %v", vals[0].Type())
		}
		t.Logf("ctlModel = %s", vals[0])
	})

	t.Run("GetVariableAccessAttributes", func(t *testing.T) {
		ts, err := c.GetVariableAccessAttributes(ctx, domain, "GGIO1$MX$AnIn1")
		if err != nil {
			t.Fatalf("GetVariableAccessAttributes: %v", err)
		}
		if ts.Kind != mms.TypeStructure {
			t.Fatalf("AnIn1 should be a structure, got %v", ts.Kind)
		}
		t.Logf("AnIn1 has %d components", len(ts.Components))
	})

	t.Run("DataSet round trip", func(t *testing.T) {
		// libiec61850 basic_io ships a Measurements dataset.
		vals, err := c.ReadNamedVariableList(ctx, domain, "LLN0$Measurements")
		if err != nil {
			t.Fatalf("ReadNamedVariableList: %v", err)
		}
		t.Logf("Measurements dataset has %d members", len(vals))

		refs, err := c.GetNamedVariableListAttributes(ctx, domain, "LLN0$Measurements")
		if err != nil {
			t.Fatalf("GetNamedVariableListAttributes: %v", err)
		}
		if len(refs) != len(vals) {
			t.Fatalf("member count mismatch: attrs=%d values=%d", len(refs), len(vals))
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
