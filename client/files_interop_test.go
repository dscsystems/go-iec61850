package client_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
)

// TestFilesInteropWithLibiecServer runs this client against libiec61850's
// server_example_files: MMS Status, SetFile (the server reads the file
// back from this client with obtainFile), GetFile, DeleteFile — including
// the server's refusal to delete IEDSERVER.BIN — release and abort. Set
// IEC61850_C_FILE_SERVER to the server_example_files binary and
// IEC61850_C_FILE_SERVER_STORE to its vmd-filestore directory.
func TestFilesInteropWithLibiecServer(t *testing.T) {
	bin := os.Getenv("IEC61850_C_FILE_SERVER")
	src := os.Getenv("IEC61850_C_FILE_SERVER_STORE")
	if bin == "" || src == "" {
		t.Skip("set IEC61850_C_FILE_SERVER and IEC61850_C_FILE_SERVER_STORE")
	}
	work := t.TempDir()
	store := filepath.Join(work, "vmd-filestore")
	if err := os.CopyFS(store, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, strconv.Itoa(port))
	cmd.Dir = work
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var c *client.Client
	for i := 0; i < 50; i++ {
		if c, err = client.Dial(ctx, addr, client.WithTimeout(2*time.Second)); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	st, err := c.ServerStatus(ctx, false)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	t.Logf("status: logical %d physical %d", st.Logical, st.Physical)

	data := bytes.Repeat([]byte("go-iec61850 SetFile "), 3000)
	if err := c.SetFile(ctx, "upload.bin", data); err != nil {
		t.Fatalf("SetFile: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(store, "upload.bin"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the server stored %d octets, %v; want %d", len(got), err, len(data))
	}
	if back, err := c.ReadFile(ctx, "upload.bin"); err != nil || !bytes.Equal(back, data) {
		t.Errorf("GetFile: %d octets, %v", len(back), err)
	}
	if err := c.DeleteFile(ctx, "upload.bin"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(store, "upload.bin")); !os.IsNotExist(err) {
		t.Error("upload.bin is still in the server's store")
	}
	var se *mms.ServiceError
	if err := c.DeleteFile(ctx, "IEDSERVER.BIN"); !errors.As(err, &se) {
		t.Errorf("deleting IEDSERVER.BIN: %v, want the server's refusal", err)
	}

	// Abort, on a second association.
	c2, err := client.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Abort(); err != nil {
		t.Errorf("Abort: %v", err)
	}
	// The server is still serving after it.
	if _, err := c.ServerStatus(ctx, true); err != nil {
		t.Errorf("Status after another association's abort: %v", err)
	}
}

// TestRenameInteropWithLibiecServer renames a file on libiec61850's
// server_example_files built with MMS_RENAME_FILE_SERVICE and with the
// example's refusal of renames removed (interop/run.sh builds it). The
// server's file access handler prints the two names it decoded from the
// request. Set IEC61850_C_RENAME_FILE_SERVER to that binary and
// IEC61850_C_FILE_SERVER_STORE to its vmd-filestore directory.
func TestRenameInteropWithLibiecServer(t *testing.T) {
	bin := os.Getenv("IEC61850_C_RENAME_FILE_SERVER")
	src := os.Getenv("IEC61850_C_FILE_SERVER_STORE")
	if bin == "" || src == "" {
		t.Skip("set IEC61850_C_RENAME_FILE_SERVER and IEC61850_C_FILE_SERVER_STORE")
	}
	work := t.TempDir()
	store := filepath.Join(work, "vmd-filestore")
	if err := os.CopyFS(store, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, strconv.Itoa(port))
	cmd.Dir, cmd.Stdout = work, &stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	var c *client.Client
	for i := 0; i < 50; i++ {
		if c, err = client.Dial(ctx, addr, client.WithTimeout(2*time.Second)); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if !c.MMS().Negotiated().Services.Has(mms.ServiceFileRename) {
		t.Error("the server does not advertise fileRename")
	}

	data := []byte("go-iec61850 rename")
	if err := os.WriteFile(filepath.Join(store, "before.txt"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.RenameFile(ctx, "before.txt", "after.txt"); err != nil {
		t.Fatalf("RenameFile: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(store, "after.txt")); err != nil || !bytes.Equal(got, data) {
		t.Errorf("after.txt = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(store, "before.txt")); !os.IsNotExist(err) {
		t.Error("before.txt is still there")
	}
	var se *mms.ServiceError
	if err := c.RenameFile(ctx, "missing.txt", "other.txt"); !errors.As(err, &se) || se.Class != 11 {
		t.Errorf("renaming a missing file: %v, want a file-class service error", err)
	}
	c.Close()
	// SIGINT ends the example cleanly, flushing what it printed.
	cmd.Process.Signal(os.Interrupt)
	cmd.Wait()
	if !strings.Contains(stdout.String(), "local-file: before.txt other-file: after.txt") {
		t.Errorf("the server did not decode the two names:\n%s", stdout.String())
	}
}
