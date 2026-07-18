package client

import (
	"context"
	"io"

	"github.com/dscsystems/go-iec61850/mms"
)

// FileEntry describes a file on the server.
type FileEntry = mms.FileEntry

// FileDirectory lists the files under path (empty for the filestore root).
func (c *Client) FileDirectory(ctx context.Context, path string) ([]FileEntry, error) {
	return c.mc.FileDirectory(ctx, path)
}

// OpenFile opens a server file for reading. The returned reader streams
// the file via successive MMS fileRead requests and releases the file-read
// state machine on Close. The context governs the whole transfer.
func (c *Client) OpenFile(ctx context.Context, name string) (io.ReadCloser, error) {
	frsm, _, err := c.mc.FileOpen(ctx, name)
	if err != nil {
		return nil, err
	}
	return &fileReader{ctx: ctx, mc: c.mc, frsm: frsm}, nil
}

// ReadFile reads an entire server file into memory.
func (c *Client) ReadFile(ctx context.Context, name string) ([]byte, error) {
	rc, err := c.OpenFile(ctx, name)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

type fileReader struct {
	ctx  context.Context
	mc   *mms.Conn
	frsm int32
	buf  []byte
	done bool
}

func (r *fileReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		data, more, err := r.mc.FileRead(r.ctx, r.frsm)
		if err != nil {
			return 0, err
		}
		r.buf = data
		if !more {
			r.done = true
		}
		if len(data) == 0 && r.done {
			return 0, io.EOF
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *fileReader) Close() error {
	return r.mc.FileClose(r.ctx, r.frsm)
}
