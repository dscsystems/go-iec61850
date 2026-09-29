package mms

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/dscsystems/go-iec61850/asn1"
)

// AssociationRequest is what a server knows of a client asking to
// associate, for an authenticator to decide on.
type AssociationRequest struct {
	Peer net.Addr
	// Password is the ACSE authentication value (the password mechanism),
	// empty when the client sent none.
	Password        string
	Called, Calling ACSEIdentity
	// TLS is the state of the TLS connection the association runs over,
	// nil without TLS; its PeerCertificates are the client's verified
	// certificate chain.
	TLS *tls.ConnectionState
}

// ErrAuthenticationRequired, returned by an authenticator, rejects the
// association as needing authentication (ACSE diagnostic
// authentication-required) rather than as having failed it.
var ErrAuthenticationRequired = errors.New("mms: authentication required")

// ErrRejected is the error AcceptConnOpts returns for an association the
// authenticator refused; the client was told so before the connection was
// closed.
var ErrRejected = errors.New("mms: association rejected")

// Abort ends the association abruptly (ACSE A-ABORT) and closes the
// transport.
func (sc *ServerConn) Abort() error {
	sc.writeMu.Lock()
	sc.fr.sendAbort()
	sc.writeMu.Unlock()
	return sc.Close()
}

// errDeferred is what a handler returns after Defer: the response follows
// later.
var errDeferred = errors.New("mms: response deferred")

// Defer answers the request later: fn runs on its own goroutine, and its
// result is sent as the response when it returns, while the connection
// goes on serving other requests — and the responses to requests this
// server sends the client (Call), which fn may be waiting on. The handler
// returns what Defer returns. fn's context ends when the client cancels
// the request (MMS Cancel) or the connection closes; the client is then
// told the request was cancelled.
func (r *Request) Defer(fn func(ctx context.Context) (*asn1.Element, error)) (*asn1.Element, error) {
	r.deferred = fn
	return nil, errDeferred
}

// runDeferred runs a deferred request and sends its outcome.
func (sc *ServerConn) runDeferred(invokeID uint32, fn func(context.Context) (*asn1.Element, error)) {
	ctx, cancel := context.WithCancel(sc.ctx())
	sc.callMu.Lock()
	if sc.running == nil {
		sc.running = map[uint32]context.CancelFunc{}
	}
	sc.running[invokeID] = cancel
	sc.callMu.Unlock()
	go func() {
		defer func() {
			sc.callMu.Lock()
			delete(sc.running, invokeID)
			sc.callMu.Unlock()
			cancel()
		}()
		resp, err := fn(ctx)
		if ctx.Err() != nil && sc.ctx().Err() == nil {
			// Cancelled by the client: service-preempt, cancel.
			sc.sendError(invokeID, &ServiceError{Class: 5, Code: 3})
			return
		}
		if err != nil {
			sc.sendError(invokeID, err)
			return
		}
		sc.sendResponse(invokeID, resp)
	}()
}

// sendResponse sends a confirmed response, or a resource error when it
// would exceed the negotiated PDU size.
func (sc *ServerConn) sendResponse(invokeID uint32, resp *asn1.Element) error {
	out := asn1.Cons(tagConfirmedResponse,
		asn1.UintElem(asn1.TagInteger, uint64(invokeID)),
		resp,
	).Encode()
	if sc.MaxPDU > 0 && len(out) > sc.MaxPDU {
		return sc.sendError(invokeID, &ServiceError{Class: errClassResource, Code: 0})
	}
	return sc.send(out)
}

// handleCancel answers a Cancel-RequestPDU: a deferred request still
// running is cancelled; anything else has been answered already, or never
// existed, and cannot be.
func (sc *ServerConn) handleCancel(content []byte) error {
	n, err := asn1.DecodeUint(content)
	if err != nil {
		return nil
	}
	id := uint32(n)
	sc.callMu.Lock()
	cancel := sc.running[id]
	sc.callMu.Unlock()
	if cancel != nil {
		cancel()
		return sc.send(asn1.UintElem(tagCancelResponse, uint64(id)).Encode())
	}
	// Cancel-ErrorPDU: cancel, invoke-id-unknown.
	return sc.send(asn1.Cons(tagCancelError,
		asn1.UintElem(asn1.ContextPrimitive(0), uint64(id)),
		asn1.Cons(asn1.ContextConstructed(1), serviceErrorBody(&ServiceError{Class: 10, Code: 1})),
	).Encode())
}

// Call sends a confirmed request to the client and waits for its
// response, as a server answering ObtainFile reads the file from the
// client. It may only be used from a deferred request (Request.Defer):
// the response arrives through Serve, which must be free to read it.
func (sc *ServerConn) Call(ctx context.Context, service *asn1.Element) ([]byte, error) {
	sc.callMu.Lock()
	if sc.calls == nil {
		sc.calls = map[uint32]chan result{}
	}
	sc.nextCall++
	id := sc.nextCall
	ch := make(chan result, 1)
	sc.calls[id] = ch
	sc.callMu.Unlock()
	defer func() {
		sc.callMu.Lock()
		delete(sc.calls, id)
		sc.callMu.Unlock()
	}()
	req := asn1.Cons(tagConfirmedRequest, asn1.UintElem(asn1.TagInteger, uint64(id)), service).Encode()
	if err := sc.send(req); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.pdu, r.err
	}
}

// deliverCall hands the client's answer to a Call.
func (sc *ServerConn) deliverCall(tag asn1.Tag, content []byte) {
	var id uint32
	var r result
	if tag == tagRejectPDU {
		dec := asn1.NewDecoder(content)
		b, ok, _ := dec.Optional(asn1.ContextPrimitive(0))
		if !ok {
			return
		}
		n, _ := asn1.DecodeUint(b)
		id, r.err = uint32(n), &ServiceError{Rejected: true, Detail: "rejected by the client"}
	} else {
		n, body, err := splitInvoke(content)
		if err != nil {
			return
		}
		id = n
		if tag == tagConfirmedResponse {
			r.pdu = body
		} else {
			r.err = decodeServiceError(tag, body)
		}
	}
	sc.callMu.Lock()
	ch := sc.calls[id]
	sc.callMu.Unlock()
	if ch != nil {
		ch <- r
	}
}

// ctx is a context that ends when the connection closes.
func (sc *ServerConn) ctx() context.Context {
	sc.ctxOnce.Do(func() { sc.connCtx, sc.connCancel = context.WithCancel(context.Background()) })
	return sc.connCtx
}

// serverConnExt holds the ServerConn state of deferred requests and
// server-initiated calls.
type serverConnExt struct {
	callMu     sync.Mutex
	nextCall   uint32
	calls      map[uint32]chan result
	running    map[uint32]context.CancelFunc
	ctxOnce    sync.Once
	connCtx    context.Context
	connCancel context.CancelFunc
}

func (e *serverConnExt) stop() {
	e.ctxOnce.Do(func() { e.connCtx, e.connCancel = context.WithCancel(context.Background()) })
	e.connCancel()
}
