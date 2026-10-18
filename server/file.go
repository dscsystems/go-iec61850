package server

import (
	"errors"
	"io"
	"io/fs"
	"math"
	"path"
	"sort"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
)

// fileStore serves the server's MMS file services from an fs.FS. Open files
// belong to the association that opened them (assocFiles), not to the store.
type fileStore struct {
	fsys fs.FS
}

func newFileStore(fsys fs.FS) *fileStore {
	return &fileStore{fsys: fsys}
}

// fileChunkSize bounds a single fileRead response payload; a smaller
// negotiated PDU size bounds it further.
const fileChunkSize = 8000

// maxOpenFiles bounds the file-read state machines one association may hold.
// Files are streamed rather than loaded, so this bounds open descriptors, not
// memory.
const maxOpenFiles = 8

// fileEnvelope bounds what surrounds a fileRead's data or a fileDirectory's
// entries in the encoded response: the confirmed response's tag, length and
// invokeID, the service's tag and length, the list or data tag and length,
// and moreFollows.
const fileEnvelope = 32

// assocFiles is one association's open files. Their ids are its own, so one
// client can neither read from nor close another's transfer, and they are
// released when the association ends.
type assocFiles struct {
	mu   sync.Mutex
	next int32
	open map[int32]*openFile
}

type openFile struct {
	f    fs.File
	size int64
	pos  int64
}

// assocFiles returns the association's open-file table, creating it on first
// use.
func (h *handler) assocFiles() *assocFiles {
	if h.files == nil {
		h.files = &assocFiles{open: make(map[int32]*openFile)}
	}
	return h.files
}

// releaseFiles closes every file the association left open.
func (h *handler) releaseFiles() {
	if h.files == nil {
		return
	}
	h.files.mu.Lock()
	defer h.files.mu.Unlock()
	for id, o := range h.files.open {
		o.f.Close()
		delete(h.files.open, id)
	}
}

func (fstore *fileStore) open_(af *assocFiles, name string, pos uint64) (int32, *openFile, time.Time, error) {
	n, ok := fsName(name)
	if !ok {
		return 0, nil, time.Time{}, fileErr(fileNonExistent)
	}
	af.mu.Lock()
	full := len(af.open) >= maxOpenFiles
	af.mu.Unlock()
	if full {
		return 0, nil, time.Time{}, fileErr(fileBusy)
	}
	f, err := fstore.fsys.Open(n)
	if err != nil {
		return 0, nil, time.Time{}, fileErr(fileNonExistent)
	}
	info, err := f.Stat()
	if err != nil || info.IsDir() {
		f.Close()
		return 0, nil, time.Time{}, fileErr(fileNonExistent)
	}
	if pos > uint64(info.Size()) {
		f.Close()
		return 0, nil, time.Time{}, fileErr(filePositionInvalid)
	}
	if pos > 0 {
		if err := skipTo(f, int64(pos)); err != nil {
			f.Close()
			return 0, nil, time.Time{}, fileErr(filePositionInvalid)
		}
	}
	o := &openFile{f: f, size: info.Size(), pos: int64(pos)}
	af.mu.Lock()
	defer af.mu.Unlock()
	if len(af.open) >= maxOpenFiles {
		f.Close()
		return 0, nil, time.Time{}, fileErr(fileBusy)
	}
	af.next++
	af.open[af.next] = o
	return af.next, o, info.ModTime(), nil
}

// skipTo moves f to pos: by seeking when it can, else by reading past the
// bytes before it.
func skipTo(f fs.File, pos int64) error {
	if sk, ok := f.(io.Seeker); ok {
		_, err := sk.Seek(pos, io.SeekStart)
		return err
	}
	_, err := io.CopyN(io.Discard, f, pos)
	return err
}

// read returns the next chunk of at most size bytes. The position advances
// only by what is returned, and size is chosen by the caller to fit the
// negotiated PDU, so no returned data can be refused for its size and lost.
func (af *assocFiles) read(id int32, size int) ([]byte, bool, error) {
	af.mu.Lock()
	o, ok := af.open[id]
	af.mu.Unlock()
	if !ok {
		return nil, false, fileErr(fileNonExistent)
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(o.f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, mms.AccessObjectAccessDenied
	}
	o.pos += int64(n)
	more := err == nil && o.pos < o.size
	return buf[:n], more, nil
}

func (af *assocFiles) close(id int32) bool {
	af.mu.Lock()
	defer af.mu.Unlock()
	o, ok := af.open[id]
	if ok {
		o.f.Close()
		delete(af.open, id)
	}
	return ok
}

func (fstore *fileStore) list(dir string) ([]fileInfo, error) {
	if dir == "" {
		dir = "."
	}
	ents, err := fs.ReadDir(fstore.fsys, path.Clean(dir))
	if err != nil {
		return nil, err
	}
	var out []fileInfo
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, fileInfo{name: e.Name(), size: uint32(info.Size()), mod: info.ModTime()})
	}
	return out, nil
}

type fileInfo struct {
	name string
	size uint32
	mod  time.Time
}

// --- handler integration ---

func (h *handler) fileService(req *mms.Request) (*asn1.Element, error, bool) {
	if h.s.files == nil {
		return nil, nil, false
	}
	maxPDU := 0
	if req.Conn != nil {
		maxPDU = req.Conn.MaxPDU
	}
	switch req.Service {
	case svcFileOpen:
		return h.fileOpen(req.Content)
	case svcFileRead:
		return h.fileRead(req.Content, maxPDU)
	case svcFileClose:
		return h.fileClose(req.Content)
	case svcFileDirectory:
		return h.fileDirectory(req.Content, maxPDU)
	}
	return nil, nil, false
}

func (h *handler) fileOpen(content []byte) (*asn1.Element, error, bool) {
	dec := asn1.NewDecoder(content)
	nameSeq, err := dec.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err, true
	}
	name, err := mms.ParseFileName(nameSeq)
	if err != nil {
		return nil, err, true
	}
	// initialPosition [1]: where the transfer starts, for a resumed or
	// partial download.
	var pos uint64
	if pb, ok, _ := dec.Optional(asn1.ContextPrimitive(1)); ok {
		if pos, err = asn1.DecodeUint(pb); err != nil {
			return nil, fileErr(filePositionInvalid), true
		}
	}
	id, o, mod, err := h.s.files.open_(h.assocFiles(), name, pos)
	if err != nil {
		return nil, err, true
	}
	resp := asn1.Cons(asn1.ContextConstructed(svcFileOpen),
		asn1.IntElem(asn1.ContextPrimitive(0), int64(id)),
		asn1.Cons(asn1.ContextConstructed(1),
			asn1.UintElem(asn1.ContextPrimitive(0), uint64(o.size)),
			asn1.Prim(asn1.ContextPrimitive(1), []byte(genTime(mod))),
		),
	)
	return resp, nil, true
}

func (h *handler) fileRead(content []byte, maxPDU int) (*asn1.Element, error, bool) {
	id, err := asn1.DecodeInt(content)
	if err != nil {
		return nil, err, true
	}
	size := fileChunkSize
	if maxPDU > 0 && maxPDU-fileEnvelope < size {
		size = max(maxPDU-fileEnvelope, 1)
	}
	if id < math.MinInt32 || id > math.MaxInt32 {
		return nil, fileErr(fileNonExistent), true
	}
	chunk, more, err := h.assocFiles().read(int32(id), size)
	if err != nil {
		return nil, err, true
	}
	resp := asn1.Cons(asn1.ContextConstructed(svcFileRead),
		asn1.Prim(asn1.ContextPrimitive(0), chunk),
		asn1.BoolElem(asn1.ContextPrimitive(1), more),
	)
	return resp, nil, true
}

func (h *handler) fileClose(content []byte) (*asn1.Element, error, bool) {
	id, err := asn1.DecodeInt(content)
	if err != nil {
		return nil, err, true
	}
	if id < math.MinInt32 || id > math.MaxInt32 || !h.assocFiles().close(int32(id)) {
		return nil, fileErr(fileNonExistent), true
	}
	return asn1.Prim(asn1.ContextPrimitive(svcFileClose), nil), nil, true
}

// fileDirectory lists a directory a page at a time: as many entries as fit
// the negotiated PDU, after continueAfter, with moreFollows set when some
// remain.
func (h *handler) fileDirectory(content []byte, maxPDU int) (*asn1.Element, error, bool) {
	dec := asn1.NewDecoder(content)
	dir, after := "", ""
	if spec, ok, _ := dec.Optional(asn1.ContextConstructed(0)); ok {
		if name, err := mms.ParseFileName(spec); err == nil {
			dir = name
		}
	}
	if ca, ok, _ := dec.Optional(asn1.ContextConstructed(1)); ok {
		if name, err := mms.ParseFileName(ca); err == nil {
			after = name
		}
	}
	infos, err := h.s.files.list(dir)
	if err != nil {
		return nil, mms.AccessObjectNonExistent, true
	}
	if after != "" {
		// Entries are in name order, so the page resumes after the name,
		// whether or not that entry still exists.
		i := sort.Search(len(infos), func(i int) bool { return infos[i].name > after })
		infos = infos[i:]
	}
	budget := maxPDU - fileEnvelope
	seqOf := asn1.Cons(asn1.TagSequence)
	more, used := false, 0
	for i, fi := range infos {
		el := asn1.Cons(asn1.TagSequence,
			asn1.Cons(asn1.ContextConstructed(0), asn1.Prim(asn1.TagGraphicString, []byte(fi.name))),
			asn1.Cons(asn1.ContextConstructed(1),
				asn1.UintElem(asn1.ContextPrimitive(0), uint64(fi.size)),
				asn1.Prim(asn1.ContextPrimitive(1), []byte(genTime(fi.mod))),
			),
		)
		// Always at least one entry, or a client could never progress.
		if maxPDU > 0 && i > 0 && used+el.Size() > budget {
			more = true
			break
		}
		used += el.Size()
		seqOf.Add(el)
	}
	resp := asn1.Cons(asn1.ContextConstructed(svcFileDirectory),
		asn1.Cons(asn1.ContextConstructed(0), seqOf),
		asn1.BoolElem(asn1.ContextPrimitive(1), more),
	)
	return resp, nil, true
}

func genTime(t time.Time) string {
	if t.IsZero() {
		t = time.Unix(0, 0)
	}
	return t.UTC().Format("20060102150405.000Z")
}
