package mms

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/e2e"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

var (
	e2eClientAE = e2e.AETitle{APTitle: asn1.OID{1, 3, 9999, 11}, AEQualifier: 1}
	e2eServerAE = e2e.AETitle{APTitle: asn1.OID{1, 3, 9999, 22}, AEQualifier: 3}
)

type e2eFixture struct {
	cli *e2e.ClientConfig
	srv *e2e.ServerConfig
}

func newE2EFixture(t *testing.T) *e2eFixture {
	t.Helper()
	root := pkitest.NewRoot("root", pkitest.ECDSAP256)
	cl := root.NewE2ELeaf(e2eClientAE.APTitle, e2eClientAE.AEQualifier, pkitest.LeafOptions{})
	sl := root.NewE2ELeaf(e2eServerAE.APTitle, e2eServerAE.AEQualifier, pkitest.LeafOptions{KeyType: pkitest.RSA2048})
	trust := pki.NewTrustStore(root.Cert)
	return &e2eFixture{
		cli: &e2e.ClientConfig{Local: e2e.Identity{AE: e2eClientAE, Certificate: cl.DER, Signer: cl.Key},
			Policy: e2e.Policy{Trust: trust}, Peer: e2eServerAE},
		srv: &e2e.ServerConfig{Local: e2e.Identity{AE: e2eServerAE, Certificate: sl.DER, Signer: sl.Key},
			Policy: e2e.Policy{Trust: trust}},
	}
}

type statusHandler struct{}

func (statusHandler) Handle(req *Request) (*asn1.Element, error) {
	if req.Service == svcStatus {
		// Provoke an unconfirmed PDU after the response.
		req.Conn.SendUnconfirmed(asn1.Cons(asn1.ContextConstructed(0), asn1.Cons(asn1.ContextConstructed(1))))
		return EncodeStatusResponse(ServerStatus{Logical: 0, Physical: 1}), nil
	}
	return nil, &ServiceError{Class: 4, Code: 0}
}

// serveOne accepts one association and serves it.
func serveOne(t *testing.T, ln net.Listener, opts AcceptOptions) <-chan error {
	done := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		sc, err := AcceptConnOpts(raw, opts)
		if err != nil {
			done <- err
			return
		}
		done <- sc.Serve(statusHandler{})
		sc.Close()
	}()
	return done
}

func TestE2EAssociation(t *testing.T) {
	f := newE2EFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var authed e2e.PeerSecurity
	done := serveOne(t, ln, AcceptOptions{E2E: f.srv, E2ERequired: true, HandshakeTimeout: 5 * time.Second,
		Authenticate: func(ar AssociationRequest) error { authed = ar.Security; return nil }})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, ln.Addr().String(), Options{E2E: f.cli, ConnectTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if ps := c.PeerSecurity(); ps.AE.String() != e2eServerAE.String() || ps.AssoID == "" {
		t.Fatalf("peer %+v", ps)
	}
	var mu sync.Mutex
	unconf := 0
	c.OnRawUnconfirmed(func([]byte) { mu.Lock(); unconf++; mu.Unlock() })
	for i := 0; i < 20; i++ {
		st, err := c.Status(ctx, false)
		if err != nil || st.Physical != 1 {
			t.Fatalf("status %d: %+v %v", i, st, err)
		}
	}
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("server ended with %v, want a release", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if unconf != 20 {
		t.Fatalf("unconfirmed PDUs = %d", unconf)
	}
	if authed.AE.String() != e2eClientAE.String() || authed.Certificate == nil {
		t.Fatalf("authenticator saw %+v", authed)
	}
}

func TestE2ERefusals(t *testing.T) {
	f := newE2EFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx := context.Background()

	// A plain client is refused by a server requiring E2E.
	done := serveOne(t, ln, AcceptOptions{E2E: f.srv, E2ERequired: true})
	_, err = Dial(ctx, ln.Addr().String(), Options{ConnectTimeout: 5 * time.Second})
	var rej *RejectedError
	if !errors.As(err, &rej) || rej.Diagnostic != 2 {
		t.Fatalf("plain client: %v", err)
	}
	if err := <-done; !errors.Is(err, ErrRejected) {
		t.Fatalf("server: %v", err)
	}

	// An E2E client calling the wrong AE title: the server's certificate
	// does not name it, and the server refuses the called title.
	done = serveOne(t, ln, AcceptOptions{E2E: f.srv})
	wrong := e2e.ClientConfig{Local: f.cli.Local, Policy: f.cli.Policy, Peer: e2e.AETitle{APTitle: asn1.OID{1, 3, 9999, 99}, AEQualifier: 1}}
	_, err = Dial(ctx, ln.Addr().String(), Options{E2E: &wrong, ConnectTimeout: 5 * time.Second})
	if !errors.As(err, &rej) || rej.Diagnostic != 7 {
		t.Fatalf("wrong called AE: %v", err)
	}
	<-done

	// An untrusted client certificate: signed HandshakeSecReject with a
	// diagnostic the client can authenticate.
	other := pkitest.NewRoot("other", pkitest.ECDSAP256)
	leaf := other.NewE2ELeaf(e2eClientAE.APTitle, e2eClientAE.AEQualifier, pkitest.LeafOptions{})
	untrusted := e2e.ClientConfig{Local: e2e.Identity{AE: e2eClientAE, Certificate: leaf.DER, Signer: leaf.Key},
		Policy: f.cli.Policy, Peer: e2eServerAE}
	done = serveOne(t, ln, AcceptOptions{E2E: f.srv})
	_, err = Dial(ctx, ln.Addr().String(), Options{E2E: &untrusted, ConnectTimeout: 5 * time.Second})
	var erej *E2ERejectedError
	if !errors.As(err, &erej) || erej.Diag != e2e.HDInvalidCertificationPath || !erej.Authenticated {
		t.Fatalf("untrusted client: %v", err)
	}
	if err := <-done; !errors.Is(err, ErrRejected) {
		t.Fatalf("server: %v", err)
	}

	// A server without E2E refuses the native-mode context.
	done = serveOne(t, ln, AcceptOptions{})
	_, err = Dial(ctx, ln.Addr().String(), Options{E2E: f.cli, ConnectTimeout: 5 * time.Second})
	if !errors.As(err, &rej) || rej.Diagnostic != 2 {
		t.Fatalf("server without E2E: %v", err)
	}
	<-done
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// A rekey over a live association: the client's rekey rides on a request,
// the server's changedKey on a response, while unconfirmed PDUs flow.
func TestE2ERekeyOverTheWire(t *testing.T) {
	f := newE2EFixture(t)
	clk := &testClock{t: time.Now()}
	f.cli.Clock, f.srv.Clock = clk.now, clk.now
	f.cli.Policy.RekeyInterval = 15 * time.Minute
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := serveOne(t, ln, AcceptOptions{E2E: f.srv})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, ln.Addr().String(), Options{E2E: f.cli})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	unconf := 0
	c.OnRawUnconfirmed(func([]byte) { mu.Lock(); unconf++; mu.Unlock() })
	settle := func(want int) {
		// Reports sealed before a clock jump would arrive stale.
		for i := 0; i < 200; i++ {
			mu.Lock()
			n := unconf
			mu.Unlock()
			if n >= want {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	for round := 1; round <= 3; round++ {
		clk.add(16 * time.Minute)
		for i := 0; i < 4; i++ {
			if _, err := c.Status(ctx, false); err != nil {
				t.Fatalf("round %d status %d: %v", round, i, err)
			}
		}
		settle(4 * round)
		if e := c.PeerSecurity().KeyEpoch; e != uint32(round) {
			t.Fatalf("round %d: client key epoch %d", round, e)
		}
	}
	c.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("server: %v", err)
	}
}
