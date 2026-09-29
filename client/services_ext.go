package client

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Abort ends the association abruptly (ACSE A-ABORT) instead of releasing
// it as Close does; requests still outstanding fail with mms.ErrAborted.
func (c *Client) Abort() error { return c.mc.Abort() }

// ServerStatus asks the server for the status of its device (MMS Status).
// extended asks it to derive the status afresh.
func (c *Client) ServerStatus(ctx context.Context, extended bool) (mms.ServerStatus, error) {
	return c.mc.Status(ctx, extended)
}

// SetFile stores data in the server's file store as name (IEC 61850
// SetFile, which IEC 61850-8-1 maps to MMS obtainFile: the server reads
// the file back from this client). The server refuses a name that exists.
func (c *Client) SetFile(ctx context.Context, name string, data []byte) error {
	return c.mc.ObtainFile(ctx, memFS{name: localName, data: data}, localName, name)
}

// SetFileFrom is SetFile with the content read from the file src of fsys.
func (c *Client) SetFileFrom(ctx context.Context, fsys fs.FS, src, name string) error {
	return c.mc.ObtainFile(ctx, fsys, src, name)
}

// DeleteFile deletes a file of the server's file store (IEC 61850
// DeleteFile).
func (c *Client) DeleteFile(ctx context.Context, name string) error {
	return c.mc.FileDelete(ctx, name)
}

// LogStatus returns how many entries a log ("LD/LN.LG.LogName") holds, and
// whether the server lets clients delete them (MMS ReportJournalStatus).
func (c *Client) LogStatus(ctx context.Context, logRef model.ObjectReference) (mms.JournalStatus, error) {
	domain, item := logRefToMMS(logRef)
	return c.mc.ReportJournalStatus(ctx, domain, item)
}

// ClearLog deletes log entries (MMS InitializeJournal): all of them when
// until is zero, else those up to and including until and, when entryID is
// not empty, no further than that entry. It returns how many went.
func (c *Client) ClearLog(ctx context.Context, logRef model.ObjectReference, until time.Time, entryID []byte) (uint32, error) {
	domain, item := logRefToMMS(logRef)
	return c.mc.InitializeJournal(ctx, domain, item, until, entryID)
}

// localName is the name a SetFile of in-memory data is served under.
const localName = "setfile.bin"

// memFS serves one in-memory file.
type memFS struct {
	name string
	data []byte
}

func (m memFS) Open(name string) (fs.File, error) {
	if name != m.name {
		return nil, fs.ErrNotExist
	}
	return &memFile{Reader: bytes.NewReader(m.data), name: m.name, size: int64(len(m.data))}, nil
}

type memFile struct {
	*bytes.Reader
	name string
	size int64
}

func (f *memFile) Stat() (fs.FileInfo, error) { return memInfo{f.name, f.size}, nil }
func (f *memFile) Close() error               { return nil }

type memInfo struct {
	name string
	size int64
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return 0o444 }
func (i memInfo) ModTime() time.Time { return time.Now() }
func (i memInfo) IsDir() bool        { return false }
func (i memInfo) Sys() any           { return nil }

var _ io.Seeker = (*memFile)(nil)
