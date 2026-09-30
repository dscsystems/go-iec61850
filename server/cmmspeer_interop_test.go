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

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/scl"
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

// TestCMMSPeerSVCB runs libiec61850's client against the sampled-value
// control blocks: ClientSVControlBlock tells the USVCB from the MSVCB by
// their functional constraints and reads them, a USVCB reserved by another
// association refuses the C client, and one the C client reserves and
// enables is released and disabled when it leaves. Set IEC61850_C_MMS_PEER
// to the mms_peer binary to enable it.
func TestCMMSPeerSVCB(t *testing.T) {
	bin := os.Getenv("IEC61850_C_MMS_PEER")
	if bin == "" {
		t.Skip("set IEC61850_C_MMS_PEER to the mms_peer binary")
	}
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatal(err)
	}
	addr, srv := startServerWith(t, m)
	rec := &svEvents{ch: make(chan struct{}, 16)}
	srv.OnSVControl(rec.add)
	host, port, _ := strings.Cut(addr, ":")
	run := func(args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, bin, append([]string{host, port}, args...)...).CombinedOutput()
		return string(out), err
	}
	const usvcb, msvcb = "ED21LD0/LLN0.usvcb01", "ED21LD0/LLN0.msvcb01"

	// Reserved here, the C client reads the block and is refused it.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.ReserveUSVCB(ctx, usvcb, true); err != nil {
		t.Fatal(err)
	}
	rec.next(t)
	out, _ := run("svcb", usvcb, "svcb", msvcb, "svresv", usvcb, "1")
	t.Logf("mms_peer:\n%s", out)
	for _, want := range []string{
		"svcb " + usvcb + " multicast=0 svena=0 resv=1 id=ED21USVCB01 err=0",
		"svcb " + msvcb + " multicast=1 svena=0 resv=0 id=ED21MSVCB01 err=0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("mms_peer output lacks %q", want)
		}
	}
	// 26 is IED_ERROR_TEMPORARILY_UNAVAILABLE.
	if !strings.Contains(out, "svresv err=26") {
		t.Error("the C client was not refused, as temporarily unavailable, a block another association holds")
	}
	if err := c.ReserveUSVCB(ctx, usvcb, false); err != nil {
		t.Fatal(err)
	}
	rec.next(t)

	// Free, the C client reserves and enables it, and leaving ends both.
	out, err = run("svresv", usvcb, "1", "svena", usvcb, "1", "svcb", usvcb)
	t.Logf("mms_peer:\n%s", out)
	if err != nil {
		t.Fatalf("mms_peer: %v", err)
	}
	if !strings.Contains(out, "svcb "+usvcb+" multicast=0 svena=1 resv=1 id=ED21USVCB01 err=0") {
		t.Errorf("the C client's block does not read enabled and reserved")
	}
	if ev := rec.next(t); !ev.Reserved || ev.Enabled || ev.Conn == nil {
		t.Errorf("reserve event = %+v", ev)
	}
	if ev := rec.next(t); !ev.Enabled {
		t.Errorf("enable event = %+v", ev)
	}
	if ev := rec.next(t); ev.Enabled || ev.Reserved {
		t.Errorf("event at the C client's departure = %+v, want disabled and free", ev)
	}
}
