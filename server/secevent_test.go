package server_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/secevent"
	"github.com/dscsystems/go-iec61850/server"
)

// eventLog collects the events a server reports.
type eventLog struct {
	mu   sync.Mutex
	ev   []secevent.Event
	more chan struct{}
}

func newEventLog() *eventLog { return &eventLog{more: make(chan struct{}, 1)} }

func (l *eventLog) Deliver(e secevent.Event) {
	l.mu.Lock()
	l.ev = append(l.ev, e)
	l.mu.Unlock()
	select {
	case l.more <- struct{}{}:
	default:
	}
}

func (l *eventLog) find(k secevent.Kind) (secevent.Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.ev {
		if e.Kind == k {
			return e, true
		}
	}
	return secevent.Event{}, false
}

// wait returns the first event of kind k, waiting for it.
func (l *eventLog) wait(t *testing.T, k secevent.Kind) secevent.Event {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if e, ok := l.find(k); ok {
			return e
		}
		select {
		case <-l.more:
		case <-deadline:
			l.mu.Lock()
			defer l.mu.Unlock()
			var got []secevent.Kind
			for _, e := range l.ev {
				got = append(got, e.Kind)
			}
			t.Fatalf("no %s event; got %v", k, got)
		}
	}
}

func eventServer(t *testing.T, opts ...server.Option) (string, *server.Server, *eventLog) {
	t.Helper()
	log := newEventLog()
	opts = append([]server.Option{server.WithSecurityPolicy(secevent.Policy{Sink: log, AggregateWindow: -1})}, opts...)
	addr, srv := startConfigured(t, opts...)
	return addr, srv, log
}

func TestEventsAssociationLifecycle(t *testing.T) {
	addr, srv, log := eventServer(t)
	c, _ := dialCapture(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Read(ctx, "simpleIOGenericIO/GGIO1.Mod.stVal", model.ST); err != nil {
		t.Fatal(err)
	}
	c.Close()

	acc := log.wait(t, secevent.KindConnAccepted)
	est := log.wait(t, secevent.KindAssocEstablished)
	closed := log.wait(t, secevent.KindConnClosed)
	if acc.SessionID == 0 || est.SessionID != acc.SessionID || closed.SessionID != acc.SessionID {
		t.Fatalf("sessions %d %d %d", acc.SessionID, est.SessionID, closed.SessionID)
	}
	if !acc.Peer.RemoteAddr.IsValid() || est.Peer.ACSE == nil || est.Protocol != "mms" || est.Role != "server" {
		t.Fatalf("established %+v", est)
	}
	s := closed.Session
	if s == nil || s.Reason == "" || s.Requests < 1 || s.OctetsIn == 0 || s.OctetsOut == 0 || s.Duration <= 0 {
		t.Fatalf("summary %+v", s)
	}
	if st := srv.SecurityStats(); st.ByKind[secevent.KindConnAccepted] != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func dialRaw(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestEventsNoData(t *testing.T) {
	addr, _, log := eventServer(t)
	dialRaw(t, addr).Close()
	e := log.wait(t, secevent.KindConnNoData)
	if e.Stage != mms.StageCOTP || e.SessionID == 0 {
		t.Fatalf("%+v", e)
	}
	if _, ok := log.find(secevent.KindAssocSetupFailed); ok {
		t.Fatal("setup failure reported as well")
	}
}

func TestEventsSetupFailedStage(t *testing.T) {
	addr, _, log := eventServer(t)
	c := dialRaw(t, addr)
	// A TPKT carrying a COTP data TPDU where the connection request
	// belongs.
	c.Write([]byte{3, 0, 0, 7, 2, 0xf0, 0x80})
	e := log.wait(t, secevent.KindAssocSetupFailed)
	if e.Stage != mms.StageCOTP || e.Err == nil || e.Action != secevent.Disconnected {
		t.Fatalf("%+v", e)
	}
}

func TestEventsNeverAssociated(t *testing.T) {
	addr, _, log := eventServer(t, server.WithHandshakeTimeout(150*time.Millisecond))
	dialRaw(t, addr)
	e := log.wait(t, secevent.KindConnNeverAssociated)
	if e.Action != secevent.Disconnected {
		t.Fatalf("%+v", e)
	}
}

func TestEventsAuthRejected(t *testing.T) {
	addr, _, log := eventServer(t, server.WithAuthenticator(func(mms.AssociationRequest) error {
		return errors.New("not you")
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second)); err == nil {
		c.Close()
		t.Fatal("association accepted")
	}
	e := log.wait(t, secevent.KindAssocSetupFailed)
	if e.Stage != mms.StageAuth || e.Action != secevent.Rejected {
		t.Fatalf("%+v", e)
	}
	if !errors.Is(e.Err, mms.ErrRejected) {
		t.Fatalf("err %v", e.Err)
	}
}

func TestEventsRejectedLimit(t *testing.T) {
	addr, _, log := eventServer(t, server.WithMaxConnections(1))
	dialCapture(t, addr)
	dialRaw(t, addr)
	e := log.wait(t, secevent.KindConnRejectedLimit)
	if e.Action != secevent.Rejected || !e.Peer.RemoteAddr.IsValid() {
		t.Fatalf("%+v", e)
	}
}

func TestEventsSlowFrame(t *testing.T) {
	addr, _, log := eventServer(t, server.WithFrameTimeout(150*time.Millisecond))
	_, raw := dialCapture(t, addr)
	raw.Write([]byte{3, 0})
	log.wait(t, secevent.KindDoSSlowFrame)
	if e := log.wait(t, secevent.KindConnClosed); e.Session.Reason != "frame timeout" || e.Action != secevent.Disconnected {
		t.Fatalf("%+v", e.Session)
	}
}

// Close lets the associations report their end before it closes the
// server's own dispatcher.
func TestEventsCloseDeliversClosed(t *testing.T) {
	addr, srv, log := eventServer(t)
	dialCapture(t, addr)
	log.wait(t, secevent.KindAssocEstablished)
	srv.Close()
	e, ok := log.find(secevent.KindConnClosed)
	if !ok || e.Session.Reason != "closed locally" {
		t.Fatalf("closed %+v %v", e, ok)
	}
}

func TestEventsTLS(t *testing.T) {
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	log := newEventLog()
	srv := server.New(m, server.WithHandshakeTimeout(150*time.Millisecond),
		server.WithSecurityPolicy(secevent.Policy{Sink: log, AggregateWindow: -1}))
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(tls.NewListener(inner, selfSignedTLS(t)))
	t.Cleanup(func() { srv.Close() })

	dialRaw(t, inner.Addr().String())
	if e := log.wait(t, secevent.KindTLSHandshakeTimeout); e.Protocol != "tls" {
		t.Fatalf("%+v", e)
	}
	c := dialRaw(t, inner.Addr().String())
	c.Write([]byte{3, 0, 0, 22, 0x11, 0xe0, 0, 0, 0, 1, 0, 0xc0, 1, 0x0d, 0xc2, 2, 0, 1, 0xc1, 2, 0, 1})
	log.wait(t, secevent.KindTLSHandshakeFailed)
}

func TestEventsAcceptError(t *testing.T) {
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	log := newEventLog()
	srv := server.New(m, server.WithCyberEventSink(log))
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(&flakyListener{Listener: inner, failures: 3})
	t.Cleanup(func() { srv.Close() })
	if e := log.wait(t, secevent.KindConnAcceptError); e.Err == nil || e.Severity != secevent.Critical {
		t.Fatalf("%+v", e)
	}
}

// A shared dispatcher outlives the server.
func TestEventsSharedDispatcher(t *testing.T) {
	log := newEventLog()
	d := secevent.NewDispatcher(log, secevent.Options{AggregateWindow: -1})
	defer d.Close()
	addr, srv := startConfigured(t, server.WithCyberEventSink(d))
	dialRaw(t, addr).Close()
	log.wait(t, secevent.KindConnNoData)
	srv.Close()
	d.Submit(secevent.Event{Kind: secevent.KindRemoteRejected})
	log.wait(t, secevent.KindRemoteRejected)
}

// Close interrupts a connection still setting up, and its end is reported
// before the server's own dispatcher closes.
func TestEventsCloseDuringSetup(t *testing.T) {
	addr, srv, log := eventServer(t)
	dialRaw(t, addr)
	log.wait(t, secevent.KindConnAccepted)
	deadline := time.Now().Add(5 * time.Second)
	for srv.OpenConnections() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	srv.Close()
	e, ok := log.find(secevent.KindConnClosed)
	if !ok || e.Session.Reason != "closed locally" {
		t.Fatalf("closed %+v %v", e, ok)
	}
	if _, ok := log.find(secevent.KindConnNoData); ok {
		t.Fatal("local close reported as the client's")
	}
}

// With a shared dispatcher, the documented order (server, then dispatcher)
// loses no conn.closed.
func TestEventsSharedDispatcherClose(t *testing.T) {
	log := newEventLog()
	d := secevent.NewDispatcher(log, secevent.Options{AggregateWindow: -1})
	addr, srv := startConfigured(t, server.WithCyberEventSink(d))
	dialCapture(t, addr)
	log.wait(t, secevent.KindAssocEstablished)
	srv.Close()
	d.Close()
	if e, ok := log.find(secevent.KindConnClosed); !ok || e.Session.Reason != "closed locally" {
		t.Fatalf("closed %+v %v", e, ok)
	}
}
