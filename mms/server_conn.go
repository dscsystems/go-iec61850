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

	// MaxPDU is the negotiated maximum MMS PDU size in octets (the
	// localDetail of the Initiate exchange). Nothing this end sends may
	// exceed it: longer responses become a resource error, and longer
	// reports are segmented by the caller.
	MaxPDU int

	// While a confirmed request is being handled, unconfirmed PDUs are
	// held so they reach the wire in the order the protocol requires
	// relative to its response: before holds what must precede it (a
	// LastApplError), after what must follow it (CommandTermination, the
	// reports a write provokes). See SendUnconfirmed.
	reqMu  sync.Mutex
	inReq  bool
	before [][]byte
	after  [][]byte

	// Called and Calling are the ACSE identities from the client's AARQ: who
	// it addressed and who it claims to be. A client that fills in Called is
	// checking which application entity it reached and will compare the
	// responding identity in the AARE against it.
	Called  ACSEIdentity
	Calling ACSEIdentity
}

// ACSEIdentity is an application-entity identity: the AP-title and
// AE-qualifier exchanged in the association APDUs.
type ACSEIdentity struct {
	APTitle     []uint32 // ap-title-form2 object identifier
	AEQualifier int32
	HasAEQual   bool

	APInvocationID  int32
	HasAPInvocation bool
	AEInvocationID  int32
	HasAEInvocation bool
}

// Empty reports whether the identity carries nothing to encode.
func (id ACSEIdentity) Empty() bool {
	return len(id.APTitle) == 0 && !id.HasAEQual && !id.HasAPInvocation && !id.HasAEInvocation
}

func (id ACSEIdentity) toACSE() acse.Identity {
	return acse.Identity{
		APTitle:         asn1.OID(id.APTitle),
		AEQualifier:     id.AEQualifier,
		HasAEQual:       id.HasAEQual,
		APInvocationID:  id.APInvocationID,
		HasAPInvocation: id.HasAPInvocation,
		AEInvocationID:  id.AEInvocationID,
		HasAEInvocation: id.HasAEInvocation,
	}
}

func identityFromACSE(id acse.Identity) ACSEIdentity {
	return ACSEIdentity{
		APTitle:         []uint32(id.APTitle),
		AEQualifier:     id.AEQualifier,
		HasAEQual:       id.HasAEQual,
		APInvocationID:  id.APInvocationID,
		HasAPInvocation: id.HasAPInvocation,
		AEInvocationID:  id.AEInvocationID,
		HasAEInvocation: id.HasAEInvocation,
	}
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
	// Initiate, when non-nil, supplies the parameters to answer with; nil
	// answers with DefaultServerInitiate. The servicesSupported bitmap
	// states what this end implements and is never the client's own
	// reflected back. A proxy sets it to the parameters the real device
	// advertised, raw bitmaps included, so its clients see the device.
	//
	// The values are still bounded by the client's proposal where the
	// protocol requires it: neither side may be asked to accept a larger PDU
	// or more outstanding services than it offered.
	Initiate *InitiateRequest

	// Responding, when non-nil, is the identity to answer with in the AARE.
	// A proxy sets it to the device's identity: a client configured with the
	// device's AP-title checks it and refuses an association that omits it or
	// answers with the wrong one. Nil keeps the bare acceptance, which is
	// legal and is what a server with no identity of its own sends.
	Responding *ACSEIdentity

	// Trace, when non-nil, is called with each handshake APDU as it is read
	// or written, before any interpretation. A peer that aborts the
	// association gives no reason, so these bytes are the only way to see
	// what it objected to.
	Trace func(event string, data []byte)
}

func (o AcceptOptions) trace(event string, data []byte) {
	if o.Trace != nil {
		o.Trace(event, data)
	}
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
	opts.trace("rx CP", res.UserData)
	cp, err := presentation.ParseCP(res.UserData)
	if err != nil {
		return nil, fmt.Errorf("mms: presentation CP: %w", err)
	}
	aarq := cp.UserData
	opts.trace("rx AARQ", aarq)
	areq, err := acse.ParseAARQFull(aarq)
	if err != nil {
		return nil, fmt.Errorf("mms: ACSE AARQ: %w", err)
	}
	mmsInit, password := areq.UserData, areq.Password
	opts.trace("rx InitiateRequest", mmsInit)
	negotiated, err := ParseInitiateRequest(mmsInit)
	if err != nil {
		return nil, fmt.Errorf("mms: initiate request: %w", err)
	}

	// Build the InitiateResponse -> AARE -> CPA -> session ACCEPT.
	want := DefaultServerInitiate()
	if opts.Initiate != nil {
		want = *opts.Initiate
	}
	answer := clampInitiate(want, negotiated)
	initResp := EncodeInitiateResponse(answer)
	opts.trace("tx InitiateResponse", initResp)
	var responding acse.Identity
	if opts.Responding != nil {
		responding = opts.Responding.toACSE()
	}
	aare := acse.AAREWithIdentity(initResp, responding)
	opts.trace("tx AARE", aare)
	// The responder's selector is the one the peer addressed, so it sees the
	// entity it dialled answer rather than a stack default.
	respondingPSel := cp.CalledPSel
	if len(respondingPSel) == 0 {
		respondingPSel = presentation.DefaultCalledPSel
	}
	cpa := presentation.BuildCPA(respondingPSel, cp.Contexts, aare)
	opts.trace("tx CPA", cpa)
	if err := session.Reply(ct, res.CalledSSEL, cpa); err != nil {
		return nil, fmt.Errorf("mms: session reply: %w", err)
	}
	sc := &ServerConn{
		fr: &framing{cotp: ct}, raw: raw, Password: password, Peer: raw.RemoteAddr(),
		MaxPDU:  int(answer.LocalDetail),
		unconf:  make(chan []byte, 512),
		Called:  identityFromACSE(areq.Called),
		Calling: identityFromACSE(areq.Calling),
	}
	// A dedicated writer drains unconfirmed PDUs (reports) so callers never
	// block on the socket while holding the model lock.
	go sc.pumpUnconfirmed()
	return sc, nil
}

// DefaultServerInitiate is the answer of a server that names no
// parameters: the services every IEC 61850 MMS server provides, and the
// mandatory parameter CBB. A server offering more (datasets defined by
// clients, files, journals) passes its own InitiateRequest.
func DefaultServerInitiate() InitiateRequest {
	return InitiateRequest{
		LocalDetail:        65000,
		MaxServOutstanding: 10,
		NestingLevel:       10,
		Services: NewServiceSupport(
			ServiceGetNameList, ServiceIdentify, ServiceRead, ServiceWrite,
			ServiceGetVariableAccessAttributes, ServiceGetNamedVariableListAttributes,
			ServiceInformationReport, ServiceConclude,
		),
	}
}

// clampInitiate limits the parameters we answer with to what the client
// proposed, where the protocol requires the responder not to exceed the
// initiator's offer. The servicesSupported bitmap is ours to state and
// passes through untouched: it describes what this end implements. The
// parameter CBB is negotiated (ISO 9506-2): the answer is what both ends
// support, unless want carries raw octets to reproduce verbatim.
func clampInitiate(want, proposed InitiateRequest) InitiateRequest {
	out := want
	if want.ParameterCBBRaw == nil && proposed.ParameterCBBRaw != nil {
		out.ParameterCBBRaw = intersectParameterCBB(parameterCBB(), proposed.ParameterCBBRaw)
	}
	if proposed.LocalDetail > 0 && (out.LocalDetail == 0 || out.LocalDetail > proposed.LocalDetail) {
		out.LocalDetail = proposed.LocalDetail
	}
	// Calling and called default to the single value, so a caller naming
	// only MaxServOutstanding is not overruled by a larger proposal.
	if out.MaxServOutstandingCalling == 0 {
		out.MaxServOutstandingCalling = out.MaxServOutstanding
	}
	if out.MaxServOutstandingCalled == 0 {
		out.MaxServOutstandingCalled = out.MaxServOutstanding
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
	sc.beginRequest()
	resp, herr := h.Handle(req)
	before, after := sc.endRequest()
	for _, pdu := range before {
		if err := sc.send(pdu); err != nil {
			return err
		}
	}
	err = nil
	if herr != nil {
		err = sc.sendError(invokeID, herr)
	} else {
		// ConfirmedResponsePDU ::= [1] SEQUENCE { invokeID, service }
		out := asn1.Cons(tagConfirmedResponse,
			asn1.UintElem(asn1.TagInteger, uint64(invokeID)),
			resp,
		).Encode()
		if sc.MaxPDU > 0 && len(out) > sc.MaxPDU {
			// The peer cannot accept a PDU this long; ISO 9506 answers
			// with a resource error rather than sending it anyway.
			err = sc.sendError(invokeID, &ServiceError{Class: errClassResource, Code: 0})
		} else {
			err = sc.send(out)
		}
	}
	if err != nil {
		return err
	}
	// Queued behind the response, in order with any earlier reports.
	for _, pdu := range after {
		sc.enqueue(pdu)
	}
	return nil
}

// errClassResource is the resource errorClass of an MMS ServiceError
// (ISO 9506-2); code 0 within it is "other".
const errClassResource = 3

func (sc *ServerConn) beginRequest() {
	sc.reqMu.Lock()
	sc.inReq = true
	sc.reqMu.Unlock()
}

func (sc *ServerConn) endRequest() (before, after [][]byte) {
	sc.reqMu.Lock()
	defer sc.reqMu.Unlock()
	sc.inReq = false
	before, after = sc.before, sc.after
	sc.before, sc.after = nil, nil
	return before, after
}

// hold keeps pdu for the request in progress, reporting false when there
// is none. first selects the list sent ahead of the response.
func (sc *ServerConn) hold(pdu []byte, first bool) bool {
	sc.reqMu.Lock()
	defer sc.reqMu.Unlock()
	if !sc.inReq {
		return false
	}
	if first {
		sc.before = append(sc.before, pdu)
	} else {
		sc.after = append(sc.after, pdu)
	}
	return true
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
//
// While a confirmed request is being handled the PDU is held and sent
// after that request's response: a CommandTermination follows the operate
// it terminates (IEC 61850-8-1), and reports provoked by a write follow the
// write's response. Reports from other activity are delayed only by the
// time the request takes.
func (sc *ServerConn) SendUnconfirmed(service *asn1.Element) error {
	pdu := asn1.Cons(tagUnconfirmed, service).Encode()
	if sc.hold(pdu, false) {
		return nil
	}
	return sc.enqueue(pdu)
}

// SendUnconfirmedFirst is SendUnconfirmed for a PDU that must precede the
// response of the request being handled, as a LastApplError precedes the
// negative response to the control it explains (IEC 61850-8-1). Outside a
// request it behaves as SendUnconfirmed.
func (sc *ServerConn) SendUnconfirmedFirst(service *asn1.Element) error {
	pdu := asn1.Cons(tagUnconfirmed, service).Encode()
	if sc.hold(pdu, true) {
		return nil
	}
	return sc.enqueue(pdu)
}

func (sc *ServerConn) enqueue(pdu []byte) error {
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
