package server

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"github.com/dscsystems/go-iec61850/secevent"
)

// WithSecurityPolicy reports the server's security events as p says (see
// package secevent). Events go to p.Sink: a *secevent.Dispatcher is
// shared and left open by Close; any other sink gets a dispatcher of the
// server's own, closed by Close once the connections have ended.
//
// Events are observations: with the policy fields this version has, they
// change nothing on the wire.
func WithSecurityPolicy(p secevent.Policy) Option {
	return func(s *Server) { s.secPolicy = p }
}

// WithCyberEventSink reports the server's security events to sink with the
// default policy: WithSecurityPolicy(secevent.DefaultPolicy()) with Sink
// set.
func WithCyberEventSink(sink secevent.Sink) Option {
	return func(s *Server) {
		p := secevent.DefaultPolicy()
		p.Sink = sink
		s.secPolicy = p
	}
}

// SecurityStats counts the security events reported so far; zero without a
// policy. With a shared dispatcher it counts those of every endpoint
// sharing it.
func (s *Server) SecurityStats() secevent.Stats { return s.secDisp.Stats() }

// startEvents creates the server's dispatcher from its policy.
func (s *Server) startEvents() {
	s.secDisp, s.secOwned = s.secPolicy.Dispatcher()
	s.events = secevent.NewEmitter(s.secDisp, "mms", "server")
}

// emitConn reports an event about a connection not (yet) an association.
func (s *Server) emitConn(raw net.Conn, session uint64, start time.Time, e secevent.Event) {
	if !s.events.Enabled() {
		return
	}
	e.SessionID = session
	e.Peer = secevent.PeerInfo{Network: "tcp", RemoteAddr: secevent.AddrPort(raw.RemoteAddr()),
		LocalAddr: secevent.AddrPort(raw.LocalAddr()), ConnectedAt: start}
	s.events.Emit(e)
}

// tlsFailure classifies a failed TLS handshake.
func tlsFailure(err error) secevent.Event {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return secevent.Event{Kind: secevent.KindTLSHandshakeTimeout, Protocol: "tls", Action: secevent.Disconnected,
			Detail: "TLS handshake not completed within the handshake timeout", Err: err}
	}
	return secevent.Event{Kind: secevent.KindTLSHandshakeFailed, Protocol: "tls", Action: secevent.Disconnected, Err: err}
}

// closedLocally is the end of a connection the server closed before it
// became an association.
func closedLocally(start time.Time, detail string) secevent.Event {
	return secevent.Event{Kind: secevent.KindConnClosed, Action: secevent.Disconnected, Detail: detail,
		Session: &secevent.SessionSummary{Reason: "closed locally", Duration: time.Since(start)}}
}

// beginSetup registers a connection starting its setup, so Close can
// interrupt it; false once Close has run.
func (s *Server) beginSetup(raw net.Conn) bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closed {
		return false
	}
	s.setup[raw] = struct{}{}
	return true
}

func (s *Server) endSetup(raw net.Conn) {
	s.connMu.Lock()
	delete(s.setup, raw)
	s.connMu.Unlock()
}

// tlsVerifiesPeer says the server's TLS configuration refuses clients
// whose certificate fails a verification of its own (an IEC 62351-3
// profile from iec62351.ServerConfig checks in VerifyConnection), so a
// client that presented a certificate was verified.
func (s *Server) tlsVerifiesPeer() bool {
	c := s.tls
	return c != nil && (c.VerifyConnection != nil || c.VerifyPeerCertificate != nil)
}

// closeEvents lets the connections, which Close has just closed, report
// their end, then closes the server's own dispatcher. The wait is bounded:
// a handler that does not return holds its connection's last event, not
// Close. A shared dispatcher is left open, and may be closed once Close
// returns.
func (s *Server) closeEvents() {
	if !s.events.Enabled() {
		return
	}
	done := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
	if s.secOwned {
		s.secDisp.Close()
	}
}
