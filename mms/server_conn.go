package mms

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/internal/osi/acse"
	"github.com/dscsystems/go-iec61850/internal/osi/cotp"
	"github.com/dscsystems/go-iec61850/internal/osi/presentation"
	"github.com/dscsystems/go-iec61850/internal/osi/session"
)

// ErrReportQueueFull is returned by SendUnconfirmed when the outbound queue is
// saturated and the report was dropped.
var ErrReportQueueFull = errors.New("mms: unconfirmed queue full")

// ServerConn is one accepted MMS association on the server side. It reads
// confirmed requests and dispatches them to a Handler, sending the
// responses the handler returns. It is used by the server package; most
// applications use that higher-level API instead.
type ServerConn struct {
	fr       *framing
	raw      net.Conn
	writeMu  sync.Mutex
	Password string // ACSE authentication value presented by the client
	Peer     net.Addr

	unconf    chan []byte // async queue for unconfirmed PDUs (reports)
	closeOnce sync.Once
}

// Handler processes a decoded confirmed request and returns the encoded
// confirmed-response service element (the CHOICE element, e.g. an A4 read
// response), or an error to send a confirmed-error/reject.
type Handler interface {
	Handle(req *Request) (*asn1.Element, error)
}

// Request is a decoded confirmed-request service.
type Request struct {
	InvokeID uint32
	Service  int    // confirmed service CHOICE tag number
	Content  []byte // service-specific content octets
	Conn     *ServerConn
}

// AcceptOptions configures the server-side association handshake.
type AcceptOptions struct {
	// Initiate, when non-nil, supplies the parameters to answer with instead
	// of echoing the client's proposal. A proxy sets this to the parameters
	// the real device advertised, so its clients see the device's
	// capabilities rather than their own request reflected back.
	//
	// The values are still bounded by the client's proposal where the
	// protocol requires it: neither side may be asked to accept a larger PDU
	// or more outstanding services than it offered.
	Initiate *InitiateRequest
}

// AcceptConn performs the server-side association handshake over an
// already-accepted transport (TCP or TLS) and returns the association.
func AcceptConn(raw net.Conn) (*ServerConn, error) {
	return AcceptConnOpts(raw, AcceptOptions{})
}

// AcceptConnOpts is AcceptConn with explicit control over the response
// parameters.
func AcceptConnOpts(raw net.Conn, opts AcceptOptions) (*ServerConn, error) {
	ct, err := cotp.Accept(raw)
	if err != nil {
		return nil, fmt.Errorf("mms: COTP accept: %w", err)
	}
	// Session CONNECT carrying the presentation CP with the ACSE AARQ.
	res, err := session.AcceptServer(ct)
	if err != nil {
		return nil, fmt.Errorf("mms: session accept: %w", err)
	}
	aarq, err := presentation.ParseCPUserData(res.UserData)
	if err != nil {
		return nil, fmt.Errorf("mms: presentation CP: %w", err)
	}
	mmsInit, password, err := acse.ParseAARQ(aarq)
	if err != nil {
		return nil, fmt.Errorf("mms: ACSE AARQ: %w", err)
	}
	negotiated, err := ParseInitiateRequest(mmsInit)
	if err != nil {
		return nil, fmt.Errorf("mms: initiate request: %w", err)
	}

	// Build the InitiateResponse -> AARE -> CPA -> session ACCEPT.
	answer := negotiated
	if opts.Initiate != nil {
		answer = clampInitiate(*opts.Initiate, negotiated)
	}
	initResp := EncodeInitiateResponse(answer)
	aare := acse.AARE(initResp)
	cpa := presentation.BuildCPA(presentation.DefaultCallingPSel, presentation.DefaultCalledPSel, aare)
	if err := session.Reply(ct, cpa); err != nil {
		return nil, fmt.Errorf("mms: session reply: %w", err)
	}
	sc := &ServerConn{
		fr: &framing{cotp: ct}, raw: raw, Password: password, Peer: raw.RemoteAddr(),
		unconf: make(chan []byte, 512),
	}
	// A dedicated writer drains unconfirmed PDUs (reports) so callers never
	// block on the socket while holding the model lock.
	go sc.pumpUnconfirmed()
	return sc, nil
}

// clampInitiate limits the parameters we answer with to what the client
// proposed, where the protocol requires the responder not to exceed the
// initiator's offer. The service and parameter bitmaps are ours to state and
// pass through untouched — they describe what this end supports, not a
// negotiated minimum.
func clampInitiate(want, proposed InitiateRequest) InitiateRequest {
	out := want
	if proposed.LocalDetail > 0 && (out.LocalDetail == 0 || out.LocalDetail > proposed.LocalDetail) {
		out.LocalDetail = proposed.LocalDetail
	}
	clamp := func(ours, theirs int) int {
		if theirs > 0 && (ours == 0 || ours > theirs) {
			return theirs
		}
		return ours
	}
	out.MaxServOutstanding = clamp(out.MaxServOutstanding, proposed.MaxServOutstanding)
	out.MaxServOutstandingCalling = clamp(out.MaxServOutstandingCalling, proposed.MaxServOutstandingCalling)
	out.MaxServOutstandingCalled = clamp(out.MaxServOutstandingCalled, proposed.MaxServOutstandingCalled)
	if proposed.NestingLevel > 0 && (out.NestingLevel == 0 || out.NestingLevel > proposed.NestingLevel) {
		out.NestingLevel = proposed.NestingLevel
	}
	return out
}

func (sc *ServerConn) pumpUnconfirmed() {
	for pdu := range sc.unconf {
		sc.writeMu.Lock()
		err := sc.fr.sendMMS(pdu)
		sc.writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

// Serve reads confirmed requests until the association ends, dispatching
// each to h. It returns when the peer concludes, the connection closes, or
// a fatal transport error occurs.
func (sc *ServerConn) Serve(h Handler) error {
	for {
		pdu, err := sc.fr.recvMMS()
		if err != nil {
			return err
		}
		if err := sc.handlePDU(pdu, h); err != nil {
			return err
		}
	}
}

func (sc *ServerConn) handlePDU(pdu []byte, h Handler) error {
	dec := asn1.NewDecoder(pdu)
	tag, content, err := dec.ReadTLV()
	if err != nil {
		return nil // ignore malformed PDUs
	}
	switch tag {
	case tagConfirmedRequest:
		return sc.handleConfirmed(content, h)
	case tagConcludeRequest:
		// Accept the conclude and end the association.
		sc.send(asn1.Cons(tagConcludeResponse).Encode())
		return net.ErrClosed
	default:
		return nil
	}
}

func (sc *ServerConn) handleConfirmed(content []byte, h Handler) error {
	dec := asn1.NewDecoder(content)
	idBytes, err := dec.Expect(asn1.TagInteger)
	if err != nil {
		return nil
	}
	id64, _ := asn1.DecodeUint(idBytes)
	invokeID := uint32(id64)

	// The service is the next element; its tag number is the service id.
	serviceTag, serviceContent, err := dec.ReadTLV()
	if err != nil {
		return nil
	}
	req := &Request{
		InvokeID: invokeID,
		Service:  int(serviceTag.Number),
		Content:  serviceContent,
		Conn:     sc,
	}
	resp, herr := h.Handle(req)
	if herr != nil {
		return sc.sendError(invokeID, herr)
	}
	// ConfirmedResponsePDU ::= [1] SEQUENCE { invokeID, service }
	out := asn1.Cons(tagConfirmedResponse,
		asn1.UintElem(asn1.TagInteger, uint64(invokeID)),
		resp,
	).Encode()
	return sc.send(out)
}

func (sc *ServerConn) sendError(invokeID uint32, herr error) error {
	// A rejected request is answered with a RejectPDU, not a service error.
	if se, ok := herr.(*ServiceError); ok && se.Rejected {
		rej := asn1.Cons(tagRejectPDU,
			asn1.UintElem(asn1.ContextPrimitive(0), uint64(invokeID)),             // originalInvokeID [0]
			asn1.IntElem(asn1.ContextPrimitive(uint32(se.Class)), int64(se.Code)), // rejectReason [category]
		).Encode()
		return sc.send(rej)
	}

	// ConfirmedErrorPDU ::= [2] SEQUENCE {
	//   invokeID     [0] IMPLICIT Unsigned32,
	//   serviceError [2] SEQUENCE { errorClass [0] CHOICE { [class] value } } }
	classTag, value := errorClassChoice(herr)
	errPDU := asn1.Cons(tagConfirmedError,
		asn1.Prim(asn1.ContextPrimitive(0), asn1.AppendUint(nil, uint64(invokeID))),
		asn1.Cons(asn1.ContextConstructed(2),
			asn1.Cons(asn1.ContextConstructed(0),
				asn1.IntElem(asn1.ContextPrimitive(classTag), int64(value))),
		),
	).Encode()
	return sc.send(errPDU)
}

// errorClassChoice maps a handler error to the errorClass CHOICE tag
// number and value used in a ServiceError (IEC 61850 MMS profile). The
// access-class enum (0..3) differs from the DataAccessError enum used
// inline in read results.
func errorClassChoice(err error) (tagNum uint32, value int64) {
	if dae, ok := err.(DataAccessError); ok {
		switch dae {
		case AccessObjectAccessUnsupported:
			return 7, 1 // access: object-access-unsupported
		case AccessObjectNonExistent:
			return 7, 2 // access: object-non-existent
		case AccessObjectAccessDenied:
			return 7, 3 // access: object-access-denied
		default:
			return 7, 2
		}
	}
	if se, ok := err.(*ServiceError); ok && se.Class != 0 {
		return uint32(se.Class), int64(se.Code)
	}
	return 4, 0 // service: other
}

// SendUnconfirmed queues an unconfirmed PDU (an information report) for
// asynchronous transmission. It never blocks the caller: if the outbound
// queue is full (a slow or stalled client), the report is dropped rather
// than stalling the server, which is the buffer-overflow condition the
// protocol already models for reporting.
func (sc *ServerConn) SendUnconfirmed(service *asn1.Element) error {
	pdu := asn1.Cons(tagUnconfirmed, service).Encode()
	select {
	case sc.unconf <- pdu:
	default:
		// The report is dropped rather than stalling the server, which is the
		// buffer-overflow condition the protocol already models. Reporting it
		// lets a buffered RCB set BufOvfl so the client learns it missed
		// entries; callers that ignore the error keep the previous behaviour.
		return ErrReportQueueFull
	}
	return nil
}

func (sc *ServerConn) send(pdu []byte) error {
	sc.writeMu.Lock()
	defer sc.writeMu.Unlock()
	return sc.fr.sendMMS(pdu)
}

// Close closes the transport and stops the unconfirmed writer.
func (sc *ServerConn) Close() error {
	sc.closeOnce.Do(func() { close(sc.unconf) })
	return sc.raw.Close()
}
