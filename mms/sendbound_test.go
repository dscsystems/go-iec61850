package mms

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

// countingHandler counts the requests that reach the server.
type countingHandler struct{ n *atomic.Int32 }

func (h countingHandler) Handle(req *Request) (*asn1.Element, error) {
	h.n.Add(1)
	return asn1.Cons(asn1.ContextConstructed(svcIdentify),
		asn1.Prim(asn1.ContextPrimitive(0), []byte("v")),
		asn1.Prim(asn1.ContextPrimitive(1), []byte("m")),
		asn1.Prim(asn1.ContextPrimitive(2), []byte("r")),
	), nil
}

// A request whose context has already ended is not transmitted.
func TestCancelledRequestNotSent(t *testing.T) {
	var n atomic.Int32
	addr := serve(t, countingHandler{&n})
	c, err := Dial(context.Background(), addr, Options{ConnectTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.call(ctx, asn1.Prim(asn1.ContextPrimitive(svcIdentify), nil)); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, err := c.call(context.Background(), asn1.Prim(asn1.ContextPrimitive(svcIdentify), nil)); err != nil {
		t.Fatalf("the association did not survive: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("server saw %d requests, want 1 (the cancelled one must not be sent)", got)
	}
}

// stallingProxy forwards a connection to target until stall is called; from
// then on it reads nothing more from the client, so the client's writes fill
// the socket buffers and block, as against a stalled peer.
type stallingProxy struct {
	addr    string
	stalled chan struct{}
	once    sync.Once
}

func newStallingProxy(t *testing.T, target string) *stallingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &stallingProxy{addr: ln.Addr().String(), stalled: make(chan struct{})}
	go func() {
		client, err := ln.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { client.Close() })
		server, err := net.Dial("tcp", target)
		if err != nil {
			client.Close()
			return
		}
		t.Cleanup(func() { server.Close() })
		go io.Copy(client, server)
		buf := make([]byte, 4096)
		for {
			select {
			case <-p.stalled:
				return
			default:
			}
			client.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			n, err := client.Read(buf)
			if n > 0 {
				server.Write(buf[:n])
			}
			if err != nil && !errors.Is(err, net.ErrClosed) {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					continue
				}
				return
			}
		}
	}()
	return p
}

// stall stops the forwarding, waiting out a read already in progress.
func (p *stallingProxy) stall() {
	p.once.Do(func() { close(p.stalled) })
	time.Sleep(100 * time.Millisecond)
}

// bigRequest is a confirmed request large enough to block on a peer that
// reads nothing.
func bigRequest() *asn1.Element {
	return asn1.Prim(asn1.ContextPrimitive(svcIdentify), make([]byte, 64<<20))
}

// A send blocked on a stalled peer gives up when its context ends, and the
// association, whose stream may now hold a partial PDU, is closed.
func TestStalledSendBoundedByContext(t *testing.T) {
	var n atomic.Int32
	p := newStallingProxy(t, serve(t, countingHandler{&n}))
	c, err := Dial(context.Background(), p.addr, Options{ConnectTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.stall()

	// Long enough to build the request even under -race, so that the
	// deadline finds the write blocked rather than not yet started.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := c.call(ctx, bigRequest())
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "write interrupted") {
			t.Fatalf("err = %v, want an interrupted write", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a send blocked on the socket ignored its context")
	}
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the association stayed open after an interrupted write")
	}
}

// Close returns promptly even while another request's write is stalled on
// the socket, and that write fails.
func TestCloseUnblocksStalledWriter(t *testing.T) {
	var n atomic.Int32
	p := newStallingProxy(t, serve(t, countingHandler{&n}))
	c, err := Dial(context.Background(), p.addr, Options{ConnectTimeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	p.stall()

	writer := make(chan error, 1)
	go func() {
		_, err := c.Start(bigRequest()) // unbounded send
		writer <- err
	}()
	time.Sleep(200 * time.Millisecond) // let the write block

	closed := make(chan struct{})
	go func() {
		c.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(closeWriteGrace + 3*time.Second):
		t.Fatal("Close hung behind a stalled writer")
	}
	select {
	case err := <-writer:
		if err == nil {
			t.Error("the stalled write reported success")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the stalled write was not unblocked by Close")
	}
}

// silentListener accepts TCP connections and never says anything.
func silentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	return ln.Addr().String()
}

// ConnectTimeout bounds the whole establishment: a TLS handshake that never
// completes, under a context without a deadline, and the association
// handshake after TCP.
func TestConnectTimeoutCoversHandshakes(t *testing.T) {
	addr := silentListener(t)
	for name, opts := range map[string]Options{
		"tls":  {ConnectTimeout: 300 * time.Millisecond, TLS: &tls.Config{InsecureSkipVerify: true}},
		"cotp": {ConnectTimeout: 300 * time.Millisecond},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := Dial(context.Background(), addr, opts)
			if err == nil {
				t.Fatal("Dial succeeded against a silent peer")
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Fatalf("Dial took %v, ConnectTimeout is 300ms", d)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("err = %v, want it to wrap context.DeadlineExceeded", err)
			}
		})
	}
}

// Cancelling the context interrupts the association handshake.
func TestDialHonoursCancellation(t *testing.T) {
	addr := silentListener(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err := Dial(ctx, addr, Options{})
	if err == nil {
		t.Fatal("Dial succeeded against a silent peer")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Dial took %v after its context was cancelled", d)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want it to wrap context.Canceled", err)
	}
}
