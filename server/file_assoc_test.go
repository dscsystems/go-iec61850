package server_test

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// countingFS counts the files open on it. Its files do not implement
// io.Seeker, so an initialPosition is reached by reading.
type countingFS struct {
	fs.FS
	open atomic.Int32
}

func (c *countingFS) Open(name string) (fs.File, error) {
	f, err := c.FS.Open(name)
	if err != nil {
		return nil, err
	}
	c.open.Add(1)
	return &countedFile{File: f, fs: c}, nil
}

type countedFile struct {
	fs.File
	fs     *countingFS
	closed atomic.Bool
}

func (f *countedFile) Close() error {
	if f.closed.CompareAndSwap(false, true) {
		f.fs.open.Add(-1)
	}
	return f.File.Close()
}

func startFileServer(t *testing.T, fsys fs.FS) string {
	t.Helper()
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m, server.WithFileStore(fsys))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func dialFiles(t *testing.T, addr string, maxPDU int32) *mms.Conn {
	t.Helper()
	opts := mms.Options{ConnectTimeout: 5 * time.Second}
	if maxPDU > 0 {
		init := mms.DefaultInitiate()
		init.LocalDetail = maxPDU
		opts.Initiate = &init
	}
	c, err := mms.Dial(context.Background(), addr, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readAll(t *testing.T, c *mms.Conn, id int32) []byte {
	t.Helper()
	ctx := context.Background()
	var out []byte
	for {
		chunk, more, err := c.FileRead(ctx, id)
		if err != nil {
			t.Fatalf("FileRead: %v", err)
		}
		out = append(out, chunk...)
		if !more {
			return out
		}
	}
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// A file-read state machine belongs to the association that opened it:
// another client can neither read from it nor close it.
func TestFileHandlesBelongToTheirAssociation(t *testing.T) {
	data := payload(20000)
	addr := startFileServer(t, fstest.MapFS{"rec.dat": {Data: data}})
	a, b := dialFiles(t, addr, 0), dialFiles(t, addr, 0)
	ctx := context.Background()

	id, _, err := a.FileOpen(ctx, "rec.dat")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.FileRead(ctx, id); err == nil {
		t.Error("another association read from the transfer")
	}
	if err := b.FileClose(ctx, id); err == nil {
		t.Error("another association closed the transfer")
	}
	if got := readAll(t, a, id); !bytes.Equal(got, data) {
		t.Errorf("transfer corrupted: %d bytes, want %d", len(got), len(data))
	}
	if err := a.FileClose(ctx, id); err != nil {
		t.Errorf("FileClose: %v", err)
	}
}

// Files left open are closed when the association ends, and the number one
// association may hold is bounded.
func TestOpenFilesBoundedAndReleased(t *testing.T) {
	fsys := &countingFS{FS: fstest.MapFS{"rec.dat": {Data: payload(1000)}}}
	addr := startFileServer(t, fsys)
	c := dialFiles(t, addr, 0)
	ctx := context.Background()

	var ids []int32
	for {
		id, _, err := c.FileOpen(ctx, "rec.dat")
		if err != nil {
			var se *mms.ServiceError
			if !errorsAs(err, &se) || se.Class != 11 || se.Code != 2 {
				t.Fatalf("open %d refused with %v, want file-busy", len(ids)+1, err)
			}
			break
		}
		ids = append(ids, id)
		if len(ids) > 64 {
			t.Fatal("no limit on open files")
		}
	}
	if got := fsys.open.Load(); got != int32(len(ids)) {
		t.Fatalf("%d files open, want %d", got, len(ids))
	}
	if err := c.FileClose(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.FileOpen(ctx, "rec.dat"); err != nil {
		t.Errorf("open after a close: %v", err)
	}

	c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for fsys.open.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%d files still open after the association ended", fsys.open.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// initialPosition starts the transfer at the requested offset, by seeking
// or, on a file that cannot seek, by reading past the bytes before it.
func TestFileOpenInitialPosition(t *testing.T) {
	data := payload(20000)
	for name, fsys := range map[string]fs.FS{
		"seekable":   fstest.MapFS{"rec.dat": {Data: data}},
		"sequential": &countingFS{FS: fstest.MapFS{"rec.dat": {Data: data}}},
	} {
		t.Run(name, func(t *testing.T) {
			c := dialFiles(t, startFileServer(t, fsys), 0)
			ctx := context.Background()
			id, size, err := c.FileOpenAt(ctx, "rec.dat", 12345)
			if err != nil {
				t.Fatal(err)
			}
			if size != uint32(len(data)) {
				t.Errorf("size = %d, want the whole file's %d", size, len(data))
			}
			if got := readAll(t, c, id); !bytes.Equal(got, data[12345:]) {
				t.Errorf("read %d bytes from offset 12345, want %d", len(got), len(data)-12345)
			}
			_, _, err = c.FileOpenAt(ctx, "rec.dat", uint32(len(data)+1))
			var se *mms.ServiceError
			if !errorsAs(err, &se) || se.Class != 11 || se.Code != 5 {
				t.Errorf("a position past the end gave %v, want file position-invalid", err)
			}
		})
	}
}

// With a small negotiated PDU, file data and directory listings are cut to
// fit it: every chunk is answered, no data is skipped, and the listing is
// paged.
func TestFileServicesFitSmallPDU(t *testing.T) {
	data := payload(30000)
	files := fstest.MapFS{"rec.dat": {Data: data}}
	for i := 0; i < 60; i++ {
		files[fmt.Sprintf("COMTRADE_%03d.cfg", i)] = &fstest.MapFile{Data: []byte("x")}
	}
	const maxPDU = 400
	c := dialFiles(t, startFileServer(t, files), maxPDU)
	ctx := context.Background()

	id, _, err := c.FileOpen(ctx, "rec.dat")
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for {
		chunk, more, err := c.FileRead(ctx, id)
		if err != nil {
			t.Fatalf("FileRead after %d bytes: %v", len(got), err)
		}
		if len(chunk) > maxPDU {
			t.Fatalf("chunk of %d bytes over a %d-octet PDU", len(chunk), maxPDU)
		}
		got = append(got, chunk...)
		if !more {
			break
		}
	}
	if !bytes.Equal(got, data) {
		t.Errorf("read %d bytes, want %d", len(got), len(data))
	}

	entries, err := c.FileDirectory(ctx, "")
	if err != nil {
		t.Fatalf("FileDirectory: %v", err)
	}
	if len(entries) != len(files) {
		t.Errorf("listed %d entries, want %d", len(entries), len(files))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.Name] {
			t.Errorf("%s listed twice", e.Name)
		}
		seen[e.Name] = true
	}
}

func errorsAs(err error, target **mms.ServiceError) bool {
	se, ok := err.(*mms.ServiceError)
	if ok {
		*target = se
	}
	return ok
}
