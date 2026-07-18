package server_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

func TestFileServices(t *testing.T) {
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	// A big file to exercise multi-chunk reads (> fileChunkSize).
	big := bytes.Repeat([]byte("COMTRADE-"), 3000) // 27 000 bytes
	fsys := fstest.MapFS{
		"record.cfg": {Data: []byte("station,rec001,2013\n")},
		"record.dat": {Data: big},
	}
	srv := server.New(m, server.WithFileStore(fsys))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	t.Run("Directory", func(t *testing.T) {
		entries, err := c.FileDirectory(ctx, "")
		if err != nil {
			t.Fatalf("FileDirectory: %v", err)
		}
		if len(entries) != 2 {
			t.Fatalf("expected 2 files, got %d: %+v", len(entries), entries)
		}
		byName := map[string]uint32{}
		for _, e := range entries {
			byName[e.Name] = e.Size
		}
		if byName["record.dat"] != uint32(len(big)) {
			t.Fatalf("record.dat size = %d, want %d", byName["record.dat"], len(big))
		}
	})

	t.Run("ReadFile small", func(t *testing.T) {
		data, err := c.ReadFile(ctx, "record.cfg")
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if string(data) != "station,rec001,2013\n" {
			t.Fatalf("content = %q", data)
		}
	})

	t.Run("ReadFile multi-chunk", func(t *testing.T) {
		data, err := c.ReadFile(ctx, "record.dat")
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.Equal(data, big) {
			t.Fatalf("multi-chunk read mismatch: got %d bytes, want %d", len(data), len(big))
		}
	})

	t.Run("ReadFile missing", func(t *testing.T) {
		if _, err := c.ReadFile(ctx, "nope.dat"); err == nil {
			t.Fatal("expected error reading missing file")
		}
	})
}
