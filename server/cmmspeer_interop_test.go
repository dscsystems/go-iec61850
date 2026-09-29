package server_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/server"
)

// TestCMMSPeerServices runs libiec61850's client (interop/c/mms_peer.c)
// against the server: password authentication, Status, SetFile (the
// server reads the file back from the C client with obtainFile), the file
// directory, DeleteFile, release and abort. Set IEC61850_C_MMS_PEER to the
// mms_peer binary to enable it.
func TestCMMSPeerServices(t *testing.T) {
	bin := os.Getenv("IEC61850_C_MMS_PEER")
	if bin == "" {
		t.Skip("set IEC61850_C_MMS_PEER to the mms_peer binary")
	}
	storeDir := t.TempDir()
	store, err := server.DirFS(storeDir)
	if err != nil {
		t.Fatal(err)
	}
	addr, srv := startServerWith(t, simpleIO(t), server.WithFileStore(store), server.WithPassword("s3cret"))
	closed := make(chan struct{}, 8)
	srv.OnConnection(func(ev server.ConnectionEvent) {
		if ev.State == server.ConnectionClosed {
			closed <- struct{}{}
		}
	})
	host, port, _ := strings.Cut(addr, ":")

	// The C client serves the file SetFile sends from its own file store,
	// ./vmd-filestore/ under its working directory.
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "vmd-filestore"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("libiec61850 SetFile "), 3000)
	if err := os.WriteFile(filepath.Join(work, "vmd-filestore", "upload.src"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, append([]string{host, port}, args...)...)
		cmd.Dir = work
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := run("-p", "s3cret", "status", "setfile", "upload.src", "upload.bin", "dir", "deletefile", "upload.bin", "release")
	t.Logf("mms_peer:\n%s", out)
	if err != nil {
		t.Fatalf("mms_peer: %v", err)
	}
	for _, want := range []string{"connect err=0", "status logical=0 physical=0 err=0", "setfile err=0",
		"file upload.bin 60000", "deletefile err=0", "release err=0"} {
		if !strings.Contains(out, want) {
			t.Errorf("mms_peer output lacks %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(storeDir, "upload.bin")); !os.IsNotExist(err) {
		t.Error("upload.bin is still in the store after DeleteFile")
	}

	// A wrong password is refused.
	out, err = run("-p", "guess", "status")
	if err == nil || strings.Contains(out, "connect err=0") {
		t.Errorf("wrong password accepted:\n%s", out)
	}

	// An abort from the C client ends the association here.
	for len(closed) > 0 {
		<-closed
	}
	if out, err := run("-p", "s3cret", "abort"); err != nil {
		t.Fatalf("abort: %v\n%s", err, out)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Error("the server did not end the aborted association")
	}
}
