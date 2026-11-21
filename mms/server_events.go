package mms

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dscsystems/go-iec61850/secevent"
)

// Association setup stages, the Stage of a SetupError and of the
// assoc.setup_failed event. They are stable identifiers.
const (
	StageCOTP         = "cotp"         // COTP connection request
	StageSession      = "session"      // session CONNECT
	StagePresentation = "presentation" // presentation CP
	StageACSE         = "acse"         // ACSE AARQ
	StageE2E          = "e2e"          // IEC 62351-4 E2E handshake
	StageAProfile     = "aprofile"     // IEC 62351-4 A-profile authentication
	StageAuth         = "auth"         // AcceptOptions.Authenticate
	StageInitiate     = "initiate"     // MMS Initiate request
	StageContext      = "context"      // presentation context negotiation
	StageReply        = "reply"        // sending the acceptance
)

// SetupError is a failed association setup: the stage it reached, and why.
// errors.Is and errors.As see through it to the cause.
type SetupError struct {
	Stage string
	Err   error
}

func (e *SetupError) Error() string { return e.Err.Error() }
func (e *SetupError) Unwrap() error { return e.Err }

// serverConnEvents is the security event state of a ServerConn.
type serverConnEvents struct {
	events      *secevent.Emitter
	sessionID   uint64
	started     time.Time
	guard       *frameGuard
	tlsVerifies bool
	requests    atomic.Uint64
	serving     atomic.Bool
	localClose  atomic.Bool
	closedOnce  sync.Once
}

// SessionID is the identifier correlating this association's security
// events; zero when none are reported.
func (sc *ServerConn) SessionID() uint64 { return sc.ev.sessionID }

// PeerInfo describes the client: its addresses, TLS state and ACSE
// identity.
func (sc *ServerConn) PeerInfo() secevent.PeerInfo {
	p := peerInfo(sc.raw, sc.ev.tlsVerifies)
	p.ConnectedAt = sc.ev.started
	a := &secevent.ACSEPeer{
		CallingAPTitle:    oidString(sc.Calling.APTitle),
		CalledAPTitle:     oidString(sc.Called.APTitle),
		PasswordPresented: sc.Password != "",
	}
	// Copies: the event must not point into the connection.
	if sc.Calling.HasAEQual {
		q := sc.Calling.AEQualifier
		a.CallingAEQualifier = &q
	}
	if sc.Called.HasAEQual {
		q := sc.Called.AEQualifier
		a.CalledAEQualifier = &q
	}
	if c := sc.AProfilePeer; c != nil {
		a.AProfileSubject = c.Subject.String()
		a.AProfileSHA256 = secevent.Fingerprint(c.Raw)
	}
	if sc.E2E() {
		ps := sc.PeerSecurity()
		a.E2E = true
		a.E2EPeerAE = ps.AE.APTitle.String()
		a.E2EAssoID = ps.AssoID
	}
	p.ACSE = a
	return p
}

// ReportCyberEvent submits e as an event of this association, filling the
// peer and session it leaves unset. Without AcceptOptions.Events it does
// nothing.
func (sc *ServerConn) ReportCyberEvent(e secevent.Event) {
	if !sc.ev.events.Enabled() {
		return
	}
	if e.SessionID == 0 {
		e.SessionID = sc.ev.sessionID
	}
	if !e.Peer.RemoteAddr.IsValid() {
		e.Peer = sc.PeerInfo()
	}
	sc.ev.events.Emit(e)
}

func (sc *ServerConn) emitEstablished() {
	if !sc.ev.events.Enabled() {
		return
	}
	detail := "plain"
	switch {
	case sc.E2E():
		detail = "e2e"
	case sc.AProfilePeer != nil:
		detail = "aprofile"
	case sc.Password != "":
		detail = "password"
	}
	sc.ReportCyberEvent(secevent.Event{Kind: secevent.KindAssocEstablished,
		Detail: "authentication " + detail + ", max PDU " + itoa(sc.MaxPDU)})
}

// emitClosed reports the end of the association, once.
func (sc *ServerConn) emitClosed(err error) {
	if !sc.ev.events.Enabled() {
		return
	}
	sc.ev.closedOnce.Do(func() {
		reason, action := closeReason(err, sc.ev.localClose.Load())
		sum := &secevent.SessionSummary{Reason: reason, Duration: time.Since(sc.ev.started),
			Requests: sc.ev.requests.Load()}
		if g := sc.ev.guard; g != nil {
			sum.OctetsIn, sum.OctetsOut = g.in.Load(), g.out.Load()
		}
		switch {
		case errors.Is(err, ErrFrameTimeout):
			sc.ReportCyberEvent(secevent.Event{Kind: secevent.KindDoSSlowFrame, Action: secevent.Disconnected,
				Detail: "a frame was not completed in time", Err: err})
		case errors.Is(err, ErrIdleTimeout):
			sc.ReportCyberEvent(secevent.Event{Kind: secevent.KindConnIdleTimeout, Action: secevent.Disconnected,
				Err: err})
		case errors.Is(err, ErrAborted) && !sc.ev.localClose.Load():
			sc.ReportCyberEvent(secevent.Event{Kind: secevent.KindAssocAbortedByPeer, Err: err})
		}
		ev := secevent.Event{Kind: secevent.KindConnClosed, Action: action, Session: sum, Detail: reason}
		if action == secevent.Disconnected {
			ev.Err = err
		}
		sc.ReportCyberEvent(ev)
	})
}

// closeReason names why Serve ended.
func closeReason(err error, local bool) (string, secevent.Action) {
	switch {
	case err == nil || errors.Is(err, net.ErrClosed) && !local:
		return "concluded", secevent.Observed
	case local:
		return "closed locally", secevent.Disconnected
	case errors.Is(err, ErrFrameTimeout):
		return "frame timeout", secevent.Disconnected
	case errors.Is(err, ErrIdleTimeout):
		return "idle timeout", secevent.Disconnected
	case errors.Is(err, ErrAborted):
		return "aborted by peer", secevent.Observed
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "write stalled", secevent.Disconnected
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "peer closed", secevent.Observed
	}
	return "transport error", secevent.Observed
}

// emitSetupFailure classifies a failed setup: a connection that never sent
// a frame, one that ran out of time, and one that failed at a stage.
func emitSetupFailure(raw net.Conn, g *frameGuard, opts AcceptOptions, start time.Time, err *SetupError) {
	if !opts.Events.Enabled() {
		return
	}
	ev := secevent.Event{SessionID: opts.SessionID, Peer: peerInfo(raw, opts.TLSVerifiesPeer), Stage: err.Stage,
		Action: secevent.Disconnected, Err: err.Err}
	ev.Peer.ConnectedAt = start
	switch {
	case errors.Is(err, net.ErrClosed):
		// This end closed the transport, shutting down: not the client's
		// doing.
		ev.Kind, ev.Err = secevent.KindConnClosed, nil
		ev.Detail = "closed locally during setup"
		ev.Session = &secevent.SessionSummary{Reason: "closed locally", Duration: time.Since(start),
			OctetsIn: g.in.Load(), OctetsOut: g.out.Load()}
	case err.Stage == StageCOTP && g.in.Load() == 0 && !errors.Is(err, os.ErrDeadlineExceeded):
		ev.Kind, ev.Action, ev.Err = secevent.KindConnNoData, secevent.Observed, nil
		ev.Detail = "closed before sending anything"
	case errors.Is(err, os.ErrDeadlineExceeded):
		ev.Kind = secevent.KindConnNeverAssociated
		ev.Detail = "no association within the handshake timeout"
	default:
		ev.Kind = secevent.KindAssocSetupFailed
		if errors.Is(err, ErrRejected) {
			ev.Action = secevent.Rejected
		}
	}
	opts.Events.Emit(ev)
}

// peerInfo describes the remote end of a transport.
func peerInfo(raw net.Conn, tlsVerifies bool) secevent.PeerInfo {
	p := secevent.PeerInfo{Network: "tcp",
		RemoteAddr: secevent.AddrPort(raw.RemoteAddr()), LocalAddr: secevent.AddrPort(raw.LocalAddr())}
	if tc, ok := raw.(tlsConn); ok {
		p.TLS = TLSPeer(tc.ConnectionState(), tlsVerifies)
	}
	return p
}

// TLSPeer describes a TLS connection state for security events; nil before
// the handshake. The peer is verified when the state holds a verified
// chain, or when verifiesPeer says the TLS layer refuses unverified
// certificates and the peer presented one (see
// AcceptOptions.TLSVerifiesPeer).
func TLSPeer(st tls.ConnectionState, verifiesPeer bool) *secevent.TLSPeer {
	if !st.HandshakeComplete {
		return nil
	}
	t := &secevent.TLSPeer{Version: st.Version, CipherSuite: st.CipherSuite, ServerName: st.ServerName,
		Verified: len(st.VerifiedChains) > 0 || verifiesPeer && len(st.PeerCertificates) > 0}
	if len(st.PeerCertificates) > 0 {
		t.CertFields(st.PeerCertificates[0])
	}
	return t
}

func oidString(o []uint32) string {
	if len(o) == 0 {
		return ""
	}
	b := make([]byte, 0, 4*len(o))
	for i, v := range o {
		if i > 0 {
			b = append(b, '.')
		}
		b = append(b, itoa(int(v))...)
	}
	return string(b)
}

func itoa(v int) string {
	if v < 0 {
		return "-" + itoa(-v)
	}
	var buf [20]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			return string(buf[i:])
		}
	}
}
