package server

import (
	"io/fs"
	"path"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
)

// fileStore serves the server's MMS file services from an fs.FS. Open
// files are tracked by file-read state machine id.
type fileStore struct {
	fsys fs.FS
	mu   sync.Mutex
	next int32
	open map[int32]*openFile
}

type openFile struct {
	data []byte
	pos  int
}

func newFileStore(fsys fs.FS) *fileStore {
	return &fileStore{fsys: fsys, next: 1, open: make(map[int32]*openFile)}
}

// fileChunkSize bounds a single fileRead response payload.
const fileChunkSize = 8000

func (fstore *fileStore) open_(name string) (int32, uint32, time.Time, error) {
	data, err := fs.ReadFile(fstore.fsys, path.Clean(name))
	if err != nil {
		return 0, 0, time.Time{}, err
	}
	var mod time.Time
	if info, err := fs.Stat(fstore.fsys, path.Clean(name)); err == nil {
		mod = info.ModTime()
	}
	fstore.mu.Lock()
	id := fstore.next
	fstore.next++
	fstore.open[id] = &openFile{data: data}
	fstore.mu.Unlock()
	return id, uint32(len(data)), mod, nil
}

func (fstore *fileStore) read(id int32) ([]byte, bool, bool) {
	fstore.mu.Lock()
	defer fstore.mu.Unlock()
	f, ok := fstore.open[id]
	if !ok {
		return nil, false, false
	}
	end := f.pos + fileChunkSize
	if end > len(f.data) {
		end = len(f.data)
	}
	chunk := f.data[f.pos:end]
	f.pos = end
	more := f.pos < len(f.data)
	return chunk, more, true
}

func (fstore *fileStore) close(id int32) {
	fstore.mu.Lock()
	delete(fstore.open, id)
	fstore.mu.Unlock()
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
	switch req.Service {
	case svcFileOpen:
		return h.fileOpen(req.Content)
	case svcFileRead:
		return h.fileRead(req.Content)
	case svcFileClose:
		return h.fileClose(req.Content)
	case svcFileDirectory:
		return h.fileDirectory(req.Content)
	}
	return nil, nil, false
}

func (h *handler) fileOpen(content []byte) (*asn1.Element, error, bool) {
	dec := asn1.NewDecoder(content)
	nameSeq, err := dec.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err, true
	}
	name, err := asn1.NewDecoder(nameSeq).Expect(asn1.TagGraphicString)
	if err != nil {
		return nil, err, true
	}
	id, size, mod, err := h.s.files.open_(string(name))
	if err != nil {
		return nil, mms.AccessObjectNonExistent, true
	}
	resp := asn1.Cons(asn1.ContextConstructed(svcFileOpen),
		asn1.IntElem(asn1.ContextPrimitive(0), int64(id)),
		asn1.Cons(asn1.ContextConstructed(1),
			asn1.UintElem(asn1.ContextPrimitive(0), uint64(size)),
			asn1.Prim(asn1.ContextPrimitive(1), []byte(genTime(mod))),
		),
	)
	return resp, nil, true
}

func (h *handler) fileRead(content []byte) (*asn1.Element, error, bool) {
	id, err := asn1.DecodeInt(content)
	if err != nil {
		return nil, err, true
	}
	chunk, more, ok := h.s.files.read(int32(id))
	if !ok {
		return nil, mms.AccessObjectNonExistent, true
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
	h.s.files.close(int32(id))
	return asn1.Prim(asn1.ContextPrimitive(svcFileClose), nil), nil, true
}

func (h *handler) fileDirectory(content []byte) (*asn1.Element, error, bool) {
	dec := asn1.NewDecoder(content)
	dir := ""
	if spec, ok, _ := dec.Optional(asn1.ContextConstructed(0)); ok {
		if name, err := asn1.NewDecoder(spec).Expect(asn1.TagGraphicString); err == nil {
			dir = string(name)
		}
	}
	infos, err := h.s.files.list(dir)
	if err != nil {
		return nil, mms.AccessObjectNonExistent, true
	}
	seqOf := asn1.Cons(asn1.TagSequence)
	for _, fi := range infos {
		seqOf.Add(asn1.Cons(asn1.TagSequence,
			asn1.Cons(asn1.ContextConstructed(0), asn1.Prim(asn1.TagGraphicString, []byte(fi.name))),
			asn1.Cons(asn1.ContextConstructed(1),
				asn1.UintElem(asn1.ContextPrimitive(0), uint64(fi.size)),
				asn1.Prim(asn1.ContextPrimitive(1), []byte(genTime(fi.mod))),
			),
		))
	}
	resp := asn1.Cons(asn1.ContextConstructed(svcFileDirectory),
		asn1.Cons(asn1.ContextConstructed(0), seqOf),
		asn1.BoolElem(asn1.ContextPrimitive(1), false),
	)
	return resp, nil, true
}

func genTime(t time.Time) string {
	if t.IsZero() {
		t = time.Unix(0, 0)
	}
	return t.UTC().Format("20060102150405.000Z")
}
