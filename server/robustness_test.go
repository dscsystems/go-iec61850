package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// flakyListener fails its first n Accepts with EMFILE, as a process out of
// file descriptors does, then behaves.
type flakyListener struct {
	net.Listener
	mu       sync.Mutex
	failures int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.failures > 0 {
		l.failures--
		l.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Net: "tcp", Addr: l.Addr(),
			Err: os.NewSyscallError("accept", syscall.EMFILE)}
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

// A transient Accept failure must not stop the server.
func TestServeSurvivesTransientAcceptErrors(t *testing.T) {
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &flakyListener{Listener: inner, failures: 3}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, inner.Addr().String(), client.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("dial after transient accept errors: %v", err)
	}
	c.Close()

	srv.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

// dialCapture associates with addr and returns the client together with
// its transport, for writing raw octets on the association.
func dialCapture(t *testing.T, addr string) (*client.Client, net.Conn) {
	t.Helper()
	var raw net.Conn
	capture := func(_ context.Context, c net.Conn) (net.Conn, error) { raw = c; return c, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second), client.WithTLSHandshake(capture))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, raw
}

func waitClosed(t *testing.T, c *client.Client, within time.Duration) {
	t.Helper()
	select {
	case <-c.Done():
	case <-time.After(within):
		t.Fatalf("association still open after %v", within)
	}
}

// A client that starts a frame and stalls is disconnected once the frame
// timeout passes.
func TestFrameTimeoutDisconnectsStalledClient(t *testing.T) {
	addr, _ := startConfigured(t, server.WithFrameTimeout(200*time.Millisecond))
	c, raw := dialCapture(t, addr)
	// Half of a TPKT header, and nothing more.
	if _, err := raw.Write([]byte{3, 0}); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, c, 5*time.Second)
}

// Without the idle timeout, a quiet association stays: the frame timeout
// does not apply between frames.
func TestQuietAssociationStaysByDefault(t *testing.T) {
	addr, _ := startConfigured(t, server.WithFrameTimeout(100*time.Millisecond))
	c, _ := dialCapture(t, addr)
	select {
	case <-c.Done():
		t.Fatalf("quiet association closed: %v", c.Err())
	case <-time.After(500 * time.Millisecond):
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Read(ctx, "simpleIOGenericIO/GGIO1.Mod.stVal", model.ST); err != nil {
		t.Fatalf("read after a quiet period: %v", err)
	}
}

func TestIdleTimeout(t *testing.T) {
	addr, _ := startConfigured(t, server.WithIdleTimeout(300*time.Millisecond))
	c, _ := dialCapture(t, addr)
	// Requests keep it alive.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 8 {
		if _, err := c.Read(ctx, "simpleIOGenericIO/GGIO1.Mod.stVal", model.ST); err != nil {
			t.Fatalf("read while active: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Silence ends it.
	waitClosed(t, c, 5*time.Second)
}

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ied"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}}}
}

// A connection to the TLS port that never starts its handshake holds a
// slot only until the handshake timeout, and the server keeps serving.
func TestSilentTLSConnectionReleasesSlot(t *testing.T) {
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m, server.WithHandshakeTimeout(200*time.Millisecond))
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(tls.NewListener(inner, selfSignedTLS(t)))
	t.Cleanup(func() { srv.Close() })

	c, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for srv.OpenConnections() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for srv.OpenConnections() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("slot still held: %d open", srv.OpenConnections())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The peer sees its connection closed.
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection still open")
	}
}
