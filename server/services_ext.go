package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
)

// MMS confirmed service tags of the services this file adds.
const (
	svcObtainFile          = 46
	svcInitializeJournal   = 67
	svcReportJournalStatus = 68
	svcFileDelete          = 76
)

// --- Authentication ---

// WithAuthenticator makes the server decide on every association before
// accepting it: f is given the client's ACSE password, identities, address
// and TLS state (whose peer certificates are the ones the TLS
// configuration verified). An error refuses the association with an ACSE
// rejection the client is told of — authentication-required for
// mms.ErrAuthenticationRequired, authentication-failure otherwise — and
// the connection is closed.
func WithAuthenticator(f func(mms.AssociationRequest) error) Option {
	return func(s *Server) { s.authenticate = f }
}

// WithPassword accepts only associations presenting password as their ACSE
// authentication value; one without is told authentication is required.
// It is WithAuthenticator with a constant-time password comparison.
func WithPassword(password string) Option {
	want := []byte(password)
	return WithAuthenticator(func(r mms.AssociationRequest) error {
		if r.Password == "" {
			return mms.ErrAuthenticationRequired
		}
		if subtle.ConstantTimeCompare([]byte(r.Password), want) != 1 {
			return errors.New("wrong password")
		}
		return nil
	})
}

// --- Status ---

// SetStatus sets what the Status service reports: the logical and physical
// status of the device (mms.LogicalStateChangesAllowed and
// mms.PhysicalOperational until it is called). Safe while serving.
func (s *Server) SetStatus(logical, physical int) {
	s.status.Store(uint32(logical)<<8 | uint32(physical)&0xff)
}

func (h *handler) serverStatus() *asn1.Element {
	v := h.s.status.Load()
	return mms.EncodeStatusResponse(mms.ServerStatus{Logical: int(v >> 8), Physical: int(v & 0xff)})
}

// --- Files ---

// WritableFS is a file store the server can write as well as read: with
// one, WithFileStore also serves SetFile (MMS obtainFile) and DeleteFile
// (fileDelete). DirFS makes one from a directory.
type WritableFS interface {
	fs.FS
	// Create creates a new file for writing, failing if it exists.
	Create(name string) (io.WriteCloser, error)
	Remove(name string) error
}

// DirFS returns a WritableFS of the files under dir. Names are resolved
// within dir: no name, symbolic link included, reaches outside it.
func DirFS(dir string) (WritableFS, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &rootFS{FS: r.FS(), root: r}, nil
}

type rootFS struct {
	fs.FS
	root *os.Root
}

func (r *rootFS) Create(name string) (io.WriteCloser, error) {
	return r.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
}

func (r *rootFS) Remove(name string) error { return r.root.Remove(name) }

// fsName maps an MMS file name to an fs.FS path: separators become
// slashes, a leading one is dropped, and a name that would leave the store
// is refused.
func fsName(name string) (string, bool) {
	n := strings.TrimLeft(strings.ReplaceAll(name, "\\", "/"), "/")
	if n == "" {
		return "", false
	}
	n = path.Clean(n)
	return n, fs.ValidPath(n) && n != "."
}

// MMS file error codes (class file, 11).
const (
	errClassFile         = 11
	fileAccessDenied     = 6
	fileNonExistent      = 7
	fileDuplicateName    = 8
	fileNameSyntaxError  = 3
	fileInsufficientSpce = 9
)

func fileErr(code uint8) error { return &mms.ServiceError{Class: errClassFile, Code: code} }

// writable returns the store when it can be written.
func (h *handler) writable() (WritableFS, bool) {
	if h.s.files == nil {
		return nil, false
	}
	w, ok := h.s.files.fsys.(WritableFS)
	return w, ok
}

func (h *handler) fileDelete(content []byte) (*asn1.Element, error) {
	w, ok := h.writable()
	if !ok {
		return nil, fileErr(fileAccessDenied)
	}
	raw, err := mms.ParseFileName(content)
	if err != nil {
		return nil, fileErr(fileNameSyntaxError)
	}
	name, ok := fsName(raw)
	if !ok {
		return nil, fileErr(fileNameSyntaxError)
	}
	if err := w.Remove(name); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fileErr(fileNonExistent)
		}
		return nil, fileErr(fileAccessDenied)
	}
	h.s.log.Info("server: file deleted", "file", name)
	return asn1.Prim(asn1.ContextPrimitive(svcFileDelete), nil), nil
}

// maxObtainedFile bounds a file SetFile may write.
const maxObtainedFile = 256 << 20

// obtainTimeout bounds how long the server waits for the client during an
// ObtainFile.
const obtainTimeout = 2 * time.Minute

// obtainFile serves ObtainFile (IEC 61850 SetFile): the server reads
// sourceFile from the client with fileOpen, fileRead and fileClose, and
// stores it as destinationFile. The reads go through the connection while
// it keeps serving, so the answer is deferred.
func (h *handler) obtainFile(req *mms.Request) (*asn1.Element, error) {
	w, ok := h.writable()
	if !ok {
		return nil, fileErr(fileAccessDenied)
	}
	dec := asn1.NewDecoder(req.Content)
	if _, present, _ := dec.Optional(asn1.ContextConstructed(0)); present {
		// A third-party source file server: this server can only read
		// from the client that asked.
		return nil, &mms.ServiceError{Class: 1, Code: 3} // application-reference: invalid
	}
	srcContent, err := dec.Expect(asn1.ContextConstructed(1))
	if err != nil {
		return nil, fileErr(fileNameSyntaxError)
	}
	dstContent, err := dec.Expect(asn1.ContextConstructed(2))
	if err != nil {
		return nil, fileErr(fileNameSyntaxError)
	}
	src, err := mms.ParseFileName(srcContent)
	if err != nil {
		return nil, fileErr(fileNameSyntaxError)
	}
	rawDst, err := mms.ParseFileName(dstContent)
	if err != nil {
		return nil, fileErr(fileNameSyntaxError)
	}
	dst, ok := fsName(rawDst)
	if !ok {
		return nil, fileErr(fileNameSyntaxError)
	}
	if _, err := fs.Stat(w, dst); err == nil {
		return nil, fileErr(fileDuplicateName)
	}
	conn := req.Conn
	log := h.s.log
	return req.Defer(func(ctx context.Context) (*asn1.Element, error) {
		ctx, cancel := context.WithTimeout(ctx, obtainTimeout)
		defer cancel()
		if err := fetchFile(ctx, conn, w, src, dst); err != nil {
			w.Remove(dst)
			log.Warn("server: SetFile failed", "source", src, "file", dst, "err", err)
			var se *mms.ServiceError
			if errors.As(err, &se) {
				return nil, se
			}
			return nil, fileErr(fileAccessDenied)
		}
		log.Info("server: file written", "file", dst)
		return asn1.Prim(asn1.ContextPrimitive(svcObtainFile), nil), nil
	})
}

// fetchFile reads src from the client into a new file dst.
func fetchFile(ctx context.Context, conn *mms.ServerConn, w WritableFS, src, dst string) error {
	resp, err := conn.Call(ctx, asn1.Cons(asn1.ContextConstructed(svcFileOpen),
		asn1.Cons(asn1.ContextConstructed(0), asn1.Prim(asn1.TagGraphicString, []byte(src))),
		asn1.UintElem(asn1.ContextPrimitive(1), 0),
	))
	if err != nil {
		return err
	}
	content, err := asn1.NewDecoder(resp).Expect(asn1.ContextConstructed(svcFileOpen))
	if err != nil {
		return err
	}
	idb, err := asn1.NewDecoder(content).Expect(asn1.ContextPrimitive(0))
	if err != nil {
		return err
	}
	frsm, _ := asn1.DecodeInt(idb)
	defer conn.Call(ctx, asn1.IntElem(asn1.ContextPrimitive(svcFileClose), frsm))

	out, err := w.Create(dst)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fileErr(fileDuplicateName)
		}
		return fileErr(fileAccessDenied)
	}
	written := 0
	for {
		resp, err := conn.Call(ctx, asn1.IntElem(asn1.ContextPrimitive(svcFileRead), frsm))
		if err != nil {
			out.Close()
			return err
		}
		rc, err := asn1.NewDecoder(resp).Expect(asn1.ContextConstructed(svcFileRead))
		if err != nil {
			out.Close()
			return err
		}
		rd := asn1.NewDecoder(rc)
		data, err := rd.Expect(asn1.ContextPrimitive(0))
		if err != nil {
			out.Close()
			return err
		}
		more := true // moreFollows DEFAULT TRUE
		if b, ok, _ := rd.Optional(asn1.ContextPrimitive(1)); ok {
			more = len(b) == 1 && b[0] != 0
		}
		written += len(data)
		if written > maxObtainedFile {
			out.Close()
			return fileErr(fileInsufficientSpce)
		}
		if _, err := out.Write(data); err != nil {
			out.Close()
			return fileErr(fileInsufficientSpce)
		}
		if !more {
			break
		}
	}
	return out.Close()
}

// --- Journals ---

// WithDeletableLogs lets clients delete log entries (MMS
// InitializeJournal), and reports the logs as deletable
// (ReportJournalStatus). Without it a log is only ever trimmed by its
// capacity.
func WithDeletableLogs() Option { return func(s *Server) { s.deletableLogs = true } }

// journalNamed resolves an ObjectName to a journal.
func (h *handler) journalNamed(on []byte) (*journal, error) {
	domain, item, err := parseObjectNameElem(asn1.NewDecoder(on))
	if err != nil {
		return nil, err
	}
	j := h.s.logs.journals[domain+"\x00"+item]
	if j == nil {
		return nil, mms.AccessObjectNonExistent
	}
	return j, nil
}

func (h *handler) reportJournalStatus(content []byte) (*asn1.Element, error) {
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	j, err := h.journalNamed(content)
	if err != nil {
		return nil, err
	}
	return asn1.Cons(asn1.ContextConstructed(svcReportJournalStatus),
		asn1.UintElem(asn1.ContextPrimitive(0), uint64(len(j.entries))),
		asn1.BoolElem(asn1.ContextPrimitive(1), h.s.deletableLogs),
	), nil
}

// initializeJournal deletes log entries: all of them, or those up to the
// limiting time, stopping at the limiting entry when one is named.
func (h *handler) initializeJournal(content []byte) (*asn1.Element, error) {
	dec := asn1.NewDecoder(content)
	name, err := dec.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err
	}
	var limit *time.Time
	var limitEntry []byte
	if ls, ok, _ := dec.Optional(asn1.ContextConstructed(1)); ok {
		ld := asn1.NewDecoder(ls)
		tb, err := ld.Expect(asn1.ContextPrimitive(0))
		if err != nil {
			return nil, err
		}
		tv, err := mms.NewBinaryTimeRaw(tb)
		if err != nil {
			return nil, err
		}
		t := tv.Time()
		limit = &t
		if eb, ok, _ := ld.Optional(asn1.ContextPrimitive(1)); ok {
			limitEntry = eb
		}
	}
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	j, err := h.journalNamed(name)
	if err != nil {
		return nil, err
	}
	if !h.s.deletableLogs {
		return nil, mms.AccessObjectAccessDenied
	}
	n := len(j.entries)
	if limit != nil {
		n = 0
		for _, e := range j.entries {
			if e.time.After(*limit) {
				break
			}
			n++
			if limitEntry != nil && string(e.id) == string(limitEntry) {
				break
			}
		}
	}
	j.entries = append([]*logEntry(nil), j.entries[n:]...)
	h.s.logs.syncLocked(j)
	h.s.log.Info("server: log entries deleted", "log", j.name, "deleted", n)
	return asn1.UintElem(asn1.ContextPrimitive(svcInitializeJournal), uint64(n)), nil
}

// --- Data sets ---

// dataSetInUse reports whether a control block names the data set
// domain/ln$ds: a report or log control block by its current DatSet, a
// GOOSE or sampled value control block by its configured one.
func (h *handler) dataSetInUse(domain, ln, ds string) bool {
	ref := domain + "/" + ln + "$" + ds
	for _, rs := range h.s.reports.reg {
		if rs.attrText("DatSet") == ref {
			return true
		}
	}
	for _, st := range h.s.logs.lcbs {
		if v := st.attr("DatSet"); v != nil && v.Text() == ref {
			return true
		}
	}
	if dev := h.s.model.Device(domain); dev != nil {
		if n := dev.Node(ln); n != nil {
			for _, g := range n.GSEControls {
				if g.DataSet == ds {
					return true
				}
			}
			for _, sv := range n.SVControls {
				if sv.DataSet == ds {
					return true
				}
			}
		}
	}
	return false
}

