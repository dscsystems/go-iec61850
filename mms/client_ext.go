package mms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/internal/osi/acse"
)

// RejectedError is an association the server refused: its AARE carried
// result rejected, with this ACSE service-user diagnostic.
type RejectedError struct {
	Diagnostic int
}

func (e *RejectedError) Error() string {
	switch e.Diagnostic {
	case acse.DiagAuthenticationFailure:
		return "mms: association rejected: authentication failure"
	case acse.DiagAuthenticationRequired:
		return "mms: association rejected: authentication required"
	}
	return fmt.Sprintf("mms: association rejected (diagnostic %d)", e.Diagnostic)
}

// ErrAuthenticationFailed matches a RejectedError for a failed or missing
// authentication with errors.Is.
var ErrAuthenticationFailed = errors.New("mms: authentication failed")

func (e *RejectedError) Is(target error) bool {
	return target == ErrAuthenticationFailed &&
		(e.Diagnostic == acse.DiagAuthenticationFailure || e.Diagnostic == acse.DiagAuthenticationRequired)
}

// Abort ends the association abruptly (ACSE A-ABORT): nothing more is sent
// or answered, and requests still outstanding fail with ErrAborted. Close
// releases the association in order and is what a client normally uses.
func (c *Conn) Abort() error {
	c.mu.Lock()
	if c.state != StateConnected {
		c.mu.Unlock()
		return nil
	}
	c.state = StateClosing
	c.closeErr = ErrAborted
	c.mu.Unlock()

	c.writeMu.Lock()
	c.fr.sendAbort()
	c.writeMu.Unlock()
	err := c.raw.Close()
	<-c.readerDone
	c.mu.Lock()
	c.state = StateClosed
	c.mu.Unlock()
	return err
}

// Outstanding is a confirmed request that has been sent and whose response
// has not been collected.
type Outstanding struct {
	c  *Conn
	id uint32
	ch chan result
}

// InvokeID is the request's MMS invoke identifier.
func (o *Outstanding) InvokeID() uint32 { return o.id }

// Start sends a confirmed request and returns without waiting for its
// response. Wait collects it; Cancel asks the server to abandon it.
func (c *Conn) Start(service *asn1.Element) (*Outstanding, error) {
	c.mu.Lock()
	if c.state != StateConnected {
		err := c.closeErr
		c.mu.Unlock()
		return nil, err
	}
	id := c.nextID
	c.nextID++
	ch := make(chan result, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	req := asn1.Cons(tagConfirmedRequest,
		asn1.UintElem(asn1.TagInteger, uint64(id)),
		service,
	).Encode()
	c.log.Debug("mms: tx PDU", "hex", fmt.Sprintf("%x", req))
	c.writeMu.Lock()
	err := c.fr.sendMMS(req)
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, err
	}
	return &Outstanding{c: c, id: id, ch: ch}, nil
}

// Wait returns the response of the request, or ctx's error when it ends
// first; a response arriving after that is discarded.
func (o *Outstanding) Wait(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		o.c.mu.Lock()
		delete(o.c.pending, o.id)
		o.c.mu.Unlock()
		return nil, ctx.Err()
	case r := <-o.ch:
		return r.pdu, r.err
	}
}

// Cancel asks the server to abandon the request (MMS Cancel). It returns
// nil when the server agreed, in which case Wait reports the request's
// error; a server that has already answered, or cannot cancel, refuses
// with a *ServiceError of class cancel (10).
func (o *Outstanding) Cancel(ctx context.Context) error { return o.c.Cancel(ctx, o.id) }

// Cancel asks the server to abandon the outstanding request with the given
// invoke identifier (ISO 9506 Cancel).
func (c *Conn) Cancel(ctx context.Context, invokeID uint32) error {
	c.mu.Lock()
	if c.state != StateConnected {
		err := c.closeErr
		c.mu.Unlock()
		return err
	}
	if c.cancels == nil {
		c.cancels = map[uint32]chan error{}
	}
	if _, busy := c.cancels[invokeID]; busy {
		c.mu.Unlock()
		return fmt.Errorf("mms: a cancel of request %d is already outstanding", invokeID)
	}
	ch := make(chan error, 1)
	c.cancels[invokeID] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.cancels, invokeID)
		c.mu.Unlock()
	}()
	c.writeMu.Lock()
	err := c.fr.sendMMS(asn1.UintElem(tagCancelRequest, uint64(invokeID)).Encode())
	c.writeMu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-ch:
		return err
	}
}

// deliverCancel hands a Cancel-ResponsePDU or Cancel-ErrorPDU to the
// Cancel waiting for it.
func (c *Conn) deliverCancel(tag asn1.Tag, content []byte) {
	var id uint32
	var err error
	if tag == tagCancelResponse {
		n, derr := asn1.DecodeUint(content)
		if derr != nil {
			return
		}
		id = uint32(n)
	} else {
		// Cancel-ErrorPDU ::= SEQUENCE { originalInvokeID [0], serviceError [1] }
		dec := asn1.NewDecoder(content)
		b, derr := dec.Expect(asn1.ContextPrimitive(0))
		if derr != nil {
			return
		}
		n, _ := asn1.DecodeUint(b)
		id = uint32(n)
		se := &ServiceError{}
		if class, code, ok := drillErrorClass(dec.Rest(), 0); ok {
			se.Class, se.Code = class, code
		}
		err = se
	}
	c.mu.Lock()
	ch := c.cancels[id]
	c.mu.Unlock()
	if ch != nil {
		ch <- err
	}
}

// --- Status ---

// VMD status values of the Status service (ISO 9506-2).
const (
	LogicalStateChangesAllowed   = 0
	LogicalNoStateChangesAllowed = 1
	LogicalLimitedServices       = 2
	LogicalSupportServices       = 3

	PhysicalOperational          = 0
	PhysicalPartiallyOperational = 1
	PhysicalInoperable           = 2
	PhysicalNeedsCommissioning   = 3
)

// ServerStatus is the answer of the Status service.
type ServerStatus struct {
	Logical, Physical int
	// LocalDetail is the server's implementation-specific status bits,
	// nil when it sent none.
	LocalDetail *asn1.BitString
}

// Status asks the server for the status of its virtual device. extended
// asks it to derive the status afresh rather than report its last one.
func (c *Conn) Status(ctx context.Context, extended bool) (ServerStatus, error) {
	resp, err := c.call(ctx, asn1.BoolElem(asn1.ContextPrimitive(svcStatus), extended))
	if err != nil {
		return ServerStatus{}, err
	}
	content, err := asn1.NewDecoder(resp).Expect(asn1.ContextConstructed(svcStatus))
	if err != nil {
		return ServerStatus{}, err
	}
	return parseStatus(content)
}

func parseStatus(content []byte) (ServerStatus, error) {
	var st ServerStatus
	dec := asn1.NewDecoder(content)
	b, err := dec.Expect(asn1.ContextPrimitive(0))
	if err != nil {
		return st, err
	}
	n, _ := asn1.DecodeInt(b)
	st.Logical = int(n)
	if b, err = dec.Expect(asn1.ContextPrimitive(1)); err != nil {
		return st, err
	}
	n, _ = asn1.DecodeInt(b)
	st.Physical = int(n)
	if b, ok, _ := dec.Optional(asn1.ContextPrimitive(2)); ok {
		if bs, err := asn1.DecodeBitString(b); err == nil {
			st.LocalDetail = &bs
		}
	}
	return st, nil
}

// EncodeStatusResponse builds the Status response service element.
func EncodeStatusResponse(st ServerStatus) *asn1.Element {
	e := asn1.Cons(asn1.ContextConstructed(svcStatus),
		asn1.IntElem(asn1.ContextPrimitive(0), int64(st.Logical)),
		asn1.IntElem(asn1.ContextPrimitive(1), int64(st.Physical)),
	)
	if st.LocalDetail != nil {
		e.Add(asn1.BitStringElem(asn1.ContextPrimitive(2), *st.LocalDetail))
	}
	return e
}

// --- Files ---

// fileName encodes a FileName, SEQUENCE OF GraphicString, under tag.
func fileName(tag asn1.Tag, name string) *asn1.Element {
	return asn1.Cons(tag, asn1.Prim(asn1.TagGraphicString, []byte(name)))
}

// ParseFileName decodes the content of a FileName, joining its parts.
func ParseFileName(content []byte) (string, error) {
	dec := asn1.NewDecoder(content)
	var name string
	for dec.More() {
		t, v, err := dec.ReadTLV()
		if err != nil {
			return "", err
		}
		if t != asn1.TagGraphicString && t != asn1.TagVisibleString {
			return "", fmt.Errorf("mms: file name part of tag %v", t)
		}
		name += string(v)
	}
	return name, nil
}

// FileDelete deletes a file of the server's file store (MMS fileDelete,
// IEC 61850 DeleteFile).
func (c *Conn) FileDelete(ctx context.Context, name string) error {
	_, err := c.call(ctx, fileName(asn1.ContextConstructed(svcFileDelete), name))
	return err
}

// ObtainFile has the server fetch sourceFile from this end and store it as
// destinationFile (MMS obtainFile, which IEC 61850-8-1 maps SetFile to).
// While the request is outstanding the server reads the file from src with
// fileOpen, fileRead and fileClose requests, which this connection answers;
// it serves sourceFile and nothing else. One ObtainFile runs at a time.
func (c *Conn) ObtainFile(ctx context.Context, src fs.FS, sourceFile, destinationFile string) error {
	c.obtainMu.Lock()
	defer c.obtainMu.Unlock()
	fsrv := &fileServer{fsys: src, name: sourceFile, open: map[int32]*openFile{}}
	c.mu.Lock()
	c.files = fsrv
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.files = nil
		c.mu.Unlock()
		fsrv.closeAll()
	}()
	req := asn1.Cons(asn1.ContextConstructed(svcObtainFile),
		fileName(asn1.ContextConstructed(1), sourceFile),
		fileName(asn1.ContextConstructed(2), destinationFile),
	)
	_, err := c.call(ctx, req)
	return err
}

// fileServer answers the file reads of an ObtainFile.
type fileServer struct {
	fsys fs.FS
	name string
	mu   sync.Mutex
	next int32
	open map[int32]*openFile
}

type openFile struct {
	f    fs.File
	size int64
}

// fileChunk is the most a fileRead response carries.
const fileChunk = 8192

func (s *fileServer) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, o := range s.open {
		o.f.Close()
		delete(s.open, id)
	}
}

// serveRequest answers a confirmed request from the server. Only the file
// reads of an ObtainFile in progress are served; anything else is
// rejected as unrecognised.
func (c *Conn) serveRequest(content []byte) {
	dec := asn1.NewDecoder(content)
	idBytes, err := dec.Expect(asn1.TagInteger)
	if err != nil {
		return
	}
	id64, _ := asn1.DecodeUint(idBytes)
	id := uint32(id64)
	tag, body, err := dec.ReadTLV()
	if err != nil {
		return
	}
	c.mu.Lock()
	fsrv := c.files
	c.mu.Unlock()
	var resp *asn1.Element
	var serr error = &ServiceError{Rejected: true, Class: 1, Code: 1}
	if fsrv != nil {
		resp, serr = fsrv.handle(int(tag.Number), body)
	}
	var out []byte
	if serr != nil {
		out = encodeError(id, serr)
	} else {
		out = asn1.Cons(tagConfirmedResponse, asn1.UintElem(asn1.TagInteger, uint64(id)), resp).Encode()
	}
	c.writeMu.Lock()
	c.fr.sendMMS(out)
	c.writeMu.Unlock()
}

// File service error codes of class file (11).
const (
	errClassFile           = 11
	fileErrAccessDenied    = 6
	fileErrNonExistent     = 7
	fileErrDuplicateName   = 8
	fileErrSyntax          = 3
	fileErrPositionInvalid = 5
)

func fileError(code uint8) error { return &ServiceError{Class: errClassFile, Code: code} }

func (s *fileServer) handle(service int, body []byte) (*asn1.Element, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch service {
	case svcFileOpen:
		dec := asn1.NewDecoder(body)
		nb, err := dec.Expect(asn1.ContextConstructed(0))
		if err != nil {
			return nil, fileError(fileErrSyntax)
		}
		name, err := ParseFileName(nb)
		if err != nil || name != s.name {
			return nil, fileError(fileErrAccessDenied)
		}
		var pos uint64
		if pb, ok, _ := dec.Optional(asn1.ContextPrimitive(1)); ok {
			pos, _ = asn1.DecodeUint(pb)
		}
		f, err := s.fsys.Open(name)
		if err != nil {
			return nil, fileError(fileErrNonExistent)
		}
		info, err := f.Stat()
		if err != nil || info.IsDir() {
			f.Close()
			return nil, fileError(fileErrNonExistent)
		}
		if pos > 0 {
			sk, ok := f.(io.Seeker)
			if !ok || int64(pos) > info.Size() {
				f.Close()
				return nil, fileError(fileErrPositionInvalid)
			}
			if _, err := sk.Seek(int64(pos), io.SeekStart); err != nil {
				f.Close()
				return nil, fileError(fileErrPositionInvalid)
			}
		}
		s.next++
		s.open[s.next] = &openFile{f: f, size: info.Size()}
		return asn1.Cons(asn1.ContextConstructed(svcFileOpen),
			asn1.IntElem(asn1.ContextPrimitive(0), int64(s.next)),
			asn1.Cons(asn1.ContextConstructed(1),
				asn1.UintElem(asn1.ContextPrimitive(0), uint64(info.Size())),
				asn1.Prim(asn1.ContextPrimitive(1), generalizedTime(info.ModTime())),
			),
		), nil
	case svcFileRead:
		n, err := asn1.DecodeInt(body)
		if err != nil {
			return nil, fileError(fileErrSyntax)
		}
		o := s.open[int32(n)]
		if o == nil {
			return nil, fileError(fileErrNonExistent)
		}
		buf := make([]byte, fileChunk)
		k, err := io.ReadFull(o.f, buf)
		more := err == nil
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, fileError(fileErrAccessDenied)
		}
		return asn1.Cons(asn1.ContextConstructed(svcFileRead),
			asn1.Prim(asn1.ContextPrimitive(0), buf[:k]),
			asn1.BoolElem(asn1.ContextPrimitive(1), more),
		), nil
	case svcFileClose:
		n, err := asn1.DecodeInt(body)
		if err != nil {
			return nil, fileError(fileErrSyntax)
		}
		if o := s.open[int32(n)]; o != nil {
			o.f.Close()
			delete(s.open, int32(n))
		}
		return asn1.Prim(asn1.ContextPrimitive(svcFileClose), nil), nil
	}
	return nil, &ServiceError{Rejected: true, Class: 1, Code: 1}
}

// generalizedTime is the GeneralizedTime encoding of t in UTC.
func generalizedTime(t time.Time) []byte {
	return []byte(t.UTC().Format("20060102150405.000Z"))
}

// --- Journals ---

// JournalStatus is the answer of ReportJournalStatus.
type JournalStatus struct {
	CurrentEntries uint32
	// Deletable says whether InitializeJournal may delete entries.
	Deletable bool
}

// ReportJournalStatus asks for the number of entries of a journal (an
// IEC 61850 log) and whether it may be initialised.
func (c *Conn) ReportJournalStatus(ctx context.Context, domain, item string) (JournalStatus, error) {
	resp, err := c.call(ctx, asn1.Cons(asn1.ContextConstructed(svcReportJournalStatus), objectName(domain, item)))
	if err != nil {
		return JournalStatus{}, err
	}
	content, err := asn1.NewDecoder(resp).Expect(asn1.ContextConstructed(svcReportJournalStatus))
	if err != nil {
		return JournalStatus{}, err
	}
	var js JournalStatus
	dec := asn1.NewDecoder(content)
	b, err := dec.Expect(asn1.ContextPrimitive(0))
	if err != nil {
		return js, err
	}
	n, _ := asn1.DecodeUint(b)
	js.CurrentEntries = uint32(n)
	if b, err = dec.Expect(asn1.ContextPrimitive(1)); err != nil {
		return js, err
	}
	js.Deletable = len(b) == 1 && b[0] != 0
	return js, nil
}

// InitializeJournal deletes entries of a journal and returns how many it
// deleted: all of them when until is zero, else those up to and including
// the time until and, when entryID is not empty, no further than the entry
// it names.
func (c *Conn) InitializeJournal(ctx context.Context, domain, item string, until time.Time, entryID []byte) (uint32, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcInitializeJournal),
		asn1.Cons(asn1.ContextConstructed(0), objectName(domain, item)))
	if !until.IsZero() {
		limit := asn1.Cons(asn1.ContextConstructed(1),
			asn1.Prim(asn1.ContextPrimitive(0), binaryTimeBytes(until)))
		if len(entryID) > 0 {
			limit.Add(asn1.Prim(asn1.ContextPrimitive(1), entryID))
		}
		req.Add(limit)
	}
	resp, err := c.call(ctx, req)
	if err != nil {
		return 0, err
	}
	b, err := asn1.NewDecoder(resp).Expect(asn1.ContextPrimitive(svcInitializeJournal))
	if err != nil {
		return 0, err
	}
	n, err := asn1.DecodeUint(b)
	return uint32(n), err
}
