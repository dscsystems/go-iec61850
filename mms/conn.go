package mms

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/internal/osi/acse"
	"github.com/dscsystems/go-iec61850/internal/osi/cotp"
	"github.com/dscsystems/go-iec61850/internal/osi/presentation"
	"github.com/dscsystems/go-iec61850/internal/osi/session"
)

// Options configures an MMS client connection.
type Options struct {
	// TLS, when non-nil, wraps the TCP connection per IEC 62351-3. The
	// default MMS-over-TLS port is 3782.
	TLS *tls.Config
	// Password, when non-empty, is sent as an ACSE authentication value.
	Password string
	// Initiate overrides the negotiated MMS parameters.
	Initiate *InitiateRequest
	// ConnectTimeout bounds the TCP + association handshake. Zero means
	// no explicit deadline beyond the context.
	ConnectTimeout time.Duration
	// Logger receives protocol diagnostics; nil discards them.
	Logger *slog.Logger
	// Called and Calling, when non-empty, are the ACSE identities to address
	// and to claim in the AARQ. Devices that check the called AP-title refuse
	// an association that omits it.
	Called  ACSEIdentity
	Calling ACSEIdentity
}

// Conn is an established MMS association. It is safe for concurrent use:
// multiple goroutines may issue confirmed requests, which are matched to
// responses by invoke ID. Unconfirmed PDUs (information reports) are
// delivered to every handler registered with OnInformationReport.
type Conn struct {
	fr        *framing
	raw       net.Conn
	log       *slog.Logger
	negotiate InitiateRequest
	// responding is the identity the peer answered with, which a proxy
	// replays to its own clients.
	responding ACSEIdentity

	writeMu sync.Mutex

	mu       sync.Mutex
	nextID   uint32
	pending  map[uint32]chan result
	state    State
	closeErr error

	// Unconfirmed-PDU handlers are additive: several independent
	// subscriptions may share one association, so registering a handler
	// must not displace the ones already there. Each entry carries the id
	// its remove func closes over.
	nextHandlerID     uint64
	reportHandlers    []reportHandler
	rawUnconfHandlers []rawUnconfHandler
	readerDone        chan struct{}
}

type reportHandler struct {
	id uint64
	fn func(*InformationReport)
}

type rawUnconfHandler struct {
	id uint64
	fn func(pdu []byte)
}

type result struct {
	pdu []byte
	err error
}

// State is the lifecycle state of an association.
type State uint8

const (
	// StateClosed is a connection that is not established: never dialled,
	// concluded, or dropped by the peer or the transport.
	StateClosed State = iota
	// StateConnecting is a handshake in progress. Dial is synchronous and
	// returns nothing until the association is up, so a *Conn is never
	// observed in this state; it exists for parity and for callers that
	// track their own connect attempt.
	StateConnecting
	// StateConnected is an established association that can carry requests.
	StateConnected
	// StateClosing is a Close that has begun: the conclude has been sent
	// and the transport is being torn down.
	StateClosing
)

func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateClosing:
		return "closing"
	}
	return fmt.Sprintf("State(%d)", uint8(s))
}

// Dial establishes an MMS association to a "host:port" address.
func Dial(ctx context.Context, addr string, opts Options) (*Conn, error) {
	d := net.Dialer{Timeout: opts.ConnectTimeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if opts.TLS != nil {
		tlsConn := tls.Client(raw, opts.TLS)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, fmt.Errorf("mms: TLS handshake: %w", err)
		}
		raw = tlsConn
	}
	c, err := newClientConn(raw, opts)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

func newClientConn(raw net.Conn, opts Options) (*Conn, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if opts.ConnectTimeout > 0 {
		raw.SetDeadline(time.Now().Add(opts.ConnectTimeout))
	}

	// COTP handshake.
	ct, err := cotp.Connect(raw, cotp.Options{})
	if err != nil {
		return nil, fmt.Errorf("mms: COTP connect: %w", err)
	}

	init := DefaultInitiate()
	if opts.Initiate != nil {
		init = *opts.Initiate
	}

	// Build ACSE AARQ wrapping the MMS InitiateRequest, wrap in
	// presentation CP, exchange via the session CONNECT.
	aarq := acse.AARQWithIdentity(EncodeInitiateRequest(init), opts.Password,
		opts.Called.toACSE(), opts.Calling.toACSE())
	cp := presentation.BuildCP(presentation.DefaultCallingPSel, presentation.DefaultCalledPSel, aarq)
	cpaUserData, err := session.ConnectClient(ct, nil, nil, cp)
	if err != nil {
		return nil, fmt.Errorf("mms: session connect: %w", err)
	}
	aare, err := presentation.ParseCPUserData(cpaUserData)
	if err != nil {
		return nil, fmt.Errorf("mms: presentation CPA: %w", err)
	}
	res, err := acse.ParseAARE(aare)
	if err != nil {
		return nil, fmt.Errorf("mms: ACSE AARE: %w", err)
	}
	if !res.Accepted {
		return nil, fmt.Errorf("mms: association rejected (diagnostic %d)", res.Diagnostic)
	}
	negotiated, err := ParseInitiateResponse(res.UserData)
	if err != nil {
		return nil, fmt.Errorf("mms: initiate response: %w", err)
	}

	if opts.ConnectTimeout > 0 {
		raw.SetDeadline(time.Time{})
	}

	c := &Conn{
		fr:         &framing{cotp: ct},
		raw:        raw,
		log:        logger,
		negotiate:  negotiated,
		responding: identityFromACSE(res.Responding),
		state:      StateConnected,
		nextID:     1,
		pending:    make(map[uint32]chan result),
		readerDone: make(chan struct{}),
	}
	go c.readLoop()
	return c, nil
}

// RespondingIdentity returns the ACSE identity the peer answered with in its
// AARE. It is zero when the peer omitted it, which is legal — and which a
// proxy has to reproduce faithfully rather than inventing one.
func (c *Conn) RespondingIdentity() ACSEIdentity { return c.responding }

// MaxServOutstanding returns the negotiated maximum outstanding services.
func (c *Conn) MaxServOutstanding() int { return c.negotiate.MaxServOutstanding }

// State reports the lifecycle state of the association.
// It becomes StateClosed as soon as
// the reader goroutine sees the transport end, so a peer that drops the
// association is visible without issuing a request first.
func (c *Conn) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// closedChan is already closed, and stands in for the reader's channel on a
// connection that was never dialled: such a connection is closed, and a
// caller waiting on it must not block forever.
var closedChan = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// Done returns a channel closed when the association ends, whether from
// Close, a peer disconnect or a transport error — the push counterpart to
// polling State.
// By the time it fires, State reports StateClosed and Err reports
// the cause. The channel is never reopened; a Conn is not redialled.
func (c *Conn) Done() <-chan struct{} {
	// readerDone is fixed at construction, so no lock is needed.
	if c.readerDone == nil {
		return closedChan
	}
	return c.readerDone
}

// Err returns the error that ended the association, or nil while it is
// still up. A conclude issued by Close reports net.ErrClosed; a peer
// disconnect reports the transport error (io.EOF for a clean close).
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == StateConnected || c.state == StateConnecting {
		return nil
	}
	return c.closeErr
}

// OnInformationReport registers a handler for unconfirmed information
// reports (used by ACSI reporting) and returns a function that removes it
// again. Handlers are additive and are called in registration order: an
// association carrying several report subscriptions delivers every report
// to all of them, so a later registration never silences an earlier one.
//
// Handlers must be registered before enabling any report; they run on the
// connection's reader goroutine and must not block. The returned remove
// func is idempotent and safe to call from any goroutine, including from
// within a handler.
func (c *Conn) OnInformationReport(h func(*InformationReport)) (remove func()) {
	if h == nil {
		return func() {}
	}
	c.mu.Lock()
	c.nextHandlerID++
	id := c.nextHandlerID
	c.reportHandlers = append(c.reportHandlers, reportHandler{id: id, fn: h})
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for i, e := range c.reportHandlers {
			if e.id == id {
				// Copy rather than shift in place: the reader goroutine may
				// be iterating a snapshot backed by this array.
				c.reportHandlers = append(c.reportHandlers[:i:i], c.reportHandlers[i+1:]...)
				return
			}
		}
	}
}

// OnRawUnconfirmed registers a handler receiving the undecoded content of
// every unconfirmed PDU, before the decoded report handlers run, and returns a
// function that removes it again. It exists for proxies and diagnostics that
// must reproduce or record exactly what arrived. Like OnInformationReport,
// handlers are additive, run on the reader goroutine and must not block.
func (c *Conn) OnRawUnconfirmed(h func(pdu []byte)) (remove func()) {
	if h == nil {
		return func() {}
	}
	c.mu.Lock()
	c.nextHandlerID++
	id := c.nextHandlerID
	c.rawUnconfHandlers = append(c.rawUnconfHandlers, rawUnconfHandler{id: id, fn: h})
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for i, e := range c.rawUnconfHandlers {
			if e.id == id {
				c.rawUnconfHandlers = append(c.rawUnconfHandlers[:i:i], c.rawUnconfHandlers[i+1:]...)
				return
			}
		}
	}
}

// Negotiated returns the association parameters agreed during the initiate
// exchange. A proxy replays these so its own clients see the capabilities the
// real device advertised, in particular the servicesSupported bit-string that
// clients gate feature use on.
func (c *Conn) Negotiated() InitiateRequest { return c.negotiate }

func (c *Conn) readLoop() {
	defer close(c.readerDone)
	for {
		pdu, err := c.fr.recvMMS()
		if err != nil {
			c.failAll(err)
			return
		}
		c.dispatch(pdu)
	}
}

func (c *Conn) dispatch(pdu []byte) {
	dec := asn1.NewDecoder(pdu)
	tag, content, err := dec.ReadTLV()
	if err != nil {
		c.log.Warn("mms: bad PDU", "err", err)
		return
	}
	c.log.Debug("mms: rx PDU", "tag", tag.String(), "len", len(pdu), "hex", fmt.Sprintf("%x", pdu))
	switch tag {
	case tagConfirmedResponse, tagConfirmedError:
		id, body, err := splitInvoke(content)
		if err != nil {
			c.log.Warn("mms: bad confirmed PDU", "err", err)
			return
		}
		var r result
		if tag == tagConfirmedResponse {
			r.pdu = body
		} else {
			r.err = decodeServiceError(tag, body)
		}
		c.deliver(id, r)
	case tagRejectPDU:
		id, err := c.deliverReject(content)
		if err != nil {
			c.log.Warn("mms: bad reject PDU", "err", err)
			return
		}
		_ = id
	case tagUnconfirmed:
		c.handleUnconfirmed(content)
	case tagConcludeResponse:
		// Peer accepted our conclude; the reader will see EOF next.
	default:
		c.log.Debug("mms: unhandled PDU tag", "tag", tag.String())
	}
}

// splitInvoke reads the leading invokeID of a confirmed PDU and returns
// the invoke id plus the remaining service-specific content. The invokeID
// is a universal INTEGER in ConfirmedResponsePDU but is context-tagged
// [0] in ConfirmedErrorPDU in the MMS module 61850 uses, so accept either.
func splitInvoke(content []byte) (uint32, []byte, error) {
	dec := asn1.NewDecoder(content)
	tag, idBytes, err := dec.ReadTLV()
	if err != nil {
		return 0, nil, err
	}
	if tag != asn1.TagInteger && tag != asn1.ContextPrimitive(0) {
		return 0, nil, fmt.Errorf("mms: unexpected invokeID tag %v: %w", tag, asn1.ErrUnexpected)
	}
	id, err := asn1.DecodeUint(idBytes)
	if err != nil {
		return 0, nil, err
	}
	return uint32(id), dec.Rest(), nil
}

// deliverReject parses a RejectPDU (originalInvokeID [0] IMPLICIT
// Unsigned32 OPTIONAL, rejectReason CHOICE) and delivers a ServiceError.
func (c *Conn) deliverReject(content []byte) (uint32, error) {
	dec := asn1.NewDecoder(content)
	var id uint32
	if idBytes, ok, err := dec.Optional(asn1.ContextPrimitive(0)); err != nil {
		return 0, err
	} else if ok {
		n, _ := asn1.DecodeUint(idBytes)
		id = uint32(n)
	}
	se := &ServiceError{Rejected: true}
	if dec.More() {
		tag, rr, err := dec.ReadTLV()
		if err == nil {
			se.Class = uint8(tag.Number)
			if n, err := asn1.DecodeInt(rr); err == nil {
				se.Code = uint8(n)
			}
			se.Detail = rejectReasonName(tag.Number, se.Code)
		}
	}
	c.deliver(id, result{err: se})
	return id, nil
}

func rejectReasonName(category uint32, code uint8) string {
	if category == 1 { // confirmed-requestPDU
		names := map[uint8]string{
			0: "other", 1: "unrecognized-service", 2: "unrecognized-modifier",
			3: "invalid-invokeID", 4: "invalid-argument", 5: "invalid-modifier",
			6: "max-serv-outstanding-exceeded", 8: "max-recursion-exceeded",
			9: "value-out-of-range",
		}
		if s, ok := names[code]; ok {
			return s
		}
	}
	return fmt.Sprintf("reject category %d code %d", category, code)
}

func (c *Conn) deliver(id uint32, r result) {
	c.mu.Lock()
	ch, ok := c.pending[id]
	if ok {
		delete(c.pending, id)
	}
	c.mu.Unlock()
	if ok {
		ch <- r
	} else {
		c.log.Warn("mms: response for unknown invoke id", "id", id)
	}
}

func (c *Conn) failAll(err error) {
	c.mu.Lock()
	if c.state == StateConnected {
		c.closeErr = err // first cause wins; Close records its own
	} else {
		err = c.closeErr
	}
	c.state = StateClosed
	pending := c.pending
	c.pending = make(map[uint32]chan result)
	c.mu.Unlock()
	for _, ch := range pending {
		ch <- result{err: err}
	}
}

// call sends a confirmed request wrapping the fully-encoded service
// element and waits for the matching response.
func (c *Conn) call(ctx context.Context, service *asn1.Element) ([]byte, error) {
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

	// ConfirmedRequestPDU ::= [0] SEQUENCE { invokeID INTEGER, service }
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

	select {
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	case r := <-ch:
		return r.pdu, r.err
	}
}

// Close releases the association (best-effort MMS conclude) and closes
// the transport.
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.state != StateConnected {
		c.mu.Unlock()
		return nil
	}
	// Concurrent callers see StateClosing until the reader has drained.
	c.state = StateClosing
	c.closeErr = net.ErrClosed
	c.mu.Unlock()

	// Best-effort conclude, then ACSE/session release. Ignore errors.
	c.writeMu.Lock()
	conclude := asn1.Cons(tagConcludeRequest).Encode()
	c.fr.sendMMS(conclude)
	c.writeMu.Unlock()

	err := c.raw.Close()
	<-c.readerDone // the reader's failAll moves the state to StateClosed
	c.mu.Lock()
	c.state = StateClosed
	c.mu.Unlock()
	return err
}

var errShort = errors.New("mms: short PDU")

func decodeServiceError(tag asn1.Tag, body []byte) error {
	if tag == tagRejectPDU {
		return &ServiceError{Rejected: true, Detail: "rejectPDU"}
	}
	// ConfirmedErrorPDU carries serviceError { errorClass [n] CHOICE }.
	// The nesting varies by module (serviceError [2] { errorClass [0] {
	// class [n] value } }), so drill to the innermost primitive
	// context-specific element: its tag number is the error class and its
	// content is the code.
	se := &ServiceError{}
	class, code, ok := drillErrorClass(body, 0)
	if ok {
		se.Class = class
		se.Code = code
	}
	return se
}

// drillErrorClass descends constructed context-specific elements to the
// first primitive context-specific element, returning its tag number and
// integer value.
func drillErrorClass(body []byte, depth int) (class, code uint8, ok bool) {
	if depth > 8 {
		return 0, 0, false
	}
	dec := asn1.NewDecoder(body)
	for dec.More() {
		tag, content, err := dec.ReadTLV()
		if err != nil {
			return 0, 0, false
		}
		if tag.Class != asn1.ClassContextSpecific {
			continue
		}
		if tag.Constructed {
			if c, v, found := drillErrorClass(content, depth+1); found {
				return c, v, true
			}
			continue
		}
		n, _ := asn1.DecodeInt(content)
		return uint8(tag.Number), uint8(n), true
	}
	return 0, 0, false
}
