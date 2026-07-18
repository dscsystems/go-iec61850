package server_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// TestCClientInterop runs the real libiec61850 client example against our
// Go server. Set IEC61850_C_CLIENT to the client_example1 binary to
// enable it; skipped otherwise so CI without the C toolchain stays green.
func TestCClientInterop(t *testing.T) {
	bin := os.Getenv("IEC61850_C_CLIENT")
	if bin == "" {
		t.Skip("set IEC61850_C_CLIENT to the libiec61850 client_example1 binary")
	}
	addr, srv := startServer(t)
	host, port, _ := strings.Cut(addr, ":")
	if host == "" {
		host = "127.0.0.1"
	}

	// The client waits ~60 s after enabling reporting; give it a few
	// seconds to connect, read, enable and receive the GI report, then
	// stop it. stdbuf line-buffers so output flushes before the kill.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	// Change a status point periodically so a data-change report is emitted
	// to the C client in addition to the GI report.
	go func() {
		ref := model.ObjectReference("simpleIOGenericIO/GGIO1.SPCSO1.stVal")
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		on := false
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				on = !on
				srv.Update(func(tx *server.Tx) { tx.SetBool(ref, on) })
			}
		}
	}()

	cmd := exec.CommandContext(ctx, "stdbuf", "-oL", bin, host, port)
	out, _ := cmd.CombinedOutput()
	t.Logf("C client output:\n%s", out)

	got := string(out)
	if !strings.Contains(got, "Connected") {
		t.Fatalf("C client did not connect:\n%s", got)
	}
	if !strings.Contains(got, "read float value") {
		t.Fatalf("C client did not read a float:\n%s", got)
	}
	if strings.Contains(got, "failed to read dataset") {
		t.Errorf("C client failed to read dataset:\n%s", got)
	}
	if !strings.Contains(got, "received report") {
		t.Errorf("C client did not receive a report:\n%s", got)
	}
}
