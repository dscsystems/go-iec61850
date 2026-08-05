package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// connRecorder collects connection events without blocking the server's
// connection goroutines.
type connRecorder struct {
	mu     sync.Mutex
	events []server.ConnectionEvent
	fired  chan struct{}
}

func newConnRecorder() *connRecorder {
	return &connRecorder{fired: make(chan struct{}, 64)}
}

func (r *connRecorder) handle(ev server.ConnectionEvent) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
	select {
	case r.fired <- struct{}{}:
	default:
	}
}

func (r *connRecorder) snapshot() []server.ConnectionEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]server.ConnectionEvent(nil), r.events...)
}

// waitFor polls the recorded events until cond holds.
func (r *connRecorder) waitFor(t *testing.T, what string, cond func([]server.ConnectionEvent) bool) []server.ConnectionEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if evs := r.snapshot(); cond(evs) {
			return evs
		}
		select {
		case <-r.fired:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("timed out waiting for %s; events so far: %+v", what, r.snapshot())
		}
	}
}

// startConfigured starts the demo model with server options under test.
func startConfigured(t *testing.T, opts ...server.Option) (string, *server.Server) {
	t.Helper()
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m, opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), srv
}

func TestConnectionIndicationAndCount(t *testing.T) {
	rec := newConnRecorder()
	addr, srv := startConfigured(t)
	srv.OnConnection(rec.handle)

	if got := srv.OpenConnections(); got != 0 {
		t.Fatalf("open connections before any client = %d, want 0", got)
	}
	if got := srv.MaxConnections(); got != 0 {
		t.Errorf("MaxConnections = %d, want 0 (unlimited)", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	evs := rec.waitFor(t, "the open indication", func(evs []server.ConnectionEvent) bool {
		return len(evs) >= 1
	})
	if evs[0].State != server.ConnectionOpened {
		t.Errorf("first event = %s, want opened", evs[0].State)
	}
	if evs[0].Peer == "" {
		t.Error("the open indication carries no peer address")
	}
	if evs[0].Conn == nil {
		t.Error("the open indication carries no association")
	}
	if evs[0].Open != 1 {
		t.Errorf("open count in the event = %d, want 1", evs[0].Open)
	}
	if got := srv.OpenConnections(); got != 1 {
		t.Errorf("OpenConnections = %d, want 1", got)
	}

	// A second client is counted too.
	b, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, "the second open indication", func(evs []server.ConnectionEvent) bool {
		return len(evs) >= 2
	})
	if got := srv.OpenConnections(); got != 2 {
		t.Errorf("OpenConnections with two clients = %d, want 2", got)
	}

	// Closing one is indicated and drops the count.
	a.Close()
	evs = rec.waitFor(t, "the close indication", func(evs []server.ConnectionEvent) bool {
		for _, e := range evs {
			if e.State == server.ConnectionClosed {
				return true
			}
		}
		return false
	})
	var closed server.ConnectionEvent
	for _, e := range evs {
		if e.State == server.ConnectionClosed {
			closed = e
		}
	}
	if closed.Open != 1 {
		t.Errorf("open count after the close = %d, want 1", closed.Open)
	}
	if closed.Conn == nil {
		t.Error("the close indication carries no association")
	}
	waitOpen(t, srv, 1)

	b.Close()
	waitOpen(t, srv, 0)
}

func waitOpen(t *testing.T, srv *server.Server, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if srv.OpenConnections() == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("OpenConnections = %d, want %d", srv.OpenConnections(), want)
}

func TestMaxConnectionsRefusesTheExcess(t *testing.T) {
	rec := newConnRecorder()
	addr, srv := startConfigured(t, server.WithMaxConnections(2))
	srv.OnConnection(rec.handle)

	if got := srv.MaxConnections(); got != 2 {
		t.Fatalf("MaxConnections = %d, want 2", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	a, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatalf("first client: %v", err)
	}
	defer a.Close()
	b, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatalf("second client: %v", err)
	}
	waitOpen(t, srv, 2)

	// The third is dropped at the transport, so the association never
	// completes.
	third, err := client.Dial(ctx, addr, client.WithTimeout(2*time.Second))
	if err == nil {
		third.Close()
		t.Fatal("a third client was served past the maximum")
	}
	rec.waitFor(t, "the refused indication", func(evs []server.ConnectionEvent) bool {
		for _, e := range evs {
			if e.State == server.ConnectionRefused {
				if e.Conn != nil {
					t.Error("a refused connection reported an association")
				}
				if e.Peer == "" {
					t.Error("the refused indication carries no peer address")
				}
				if e.Open != 2 {
					t.Errorf("open count in the refusal = %d, want 2", e.Open)
				}
				return true
			}
		}
		return false
	})
	if got := srv.OpenConnections(); got != 2 {
		t.Errorf("OpenConnections after a refusal = %d, want 2", got)
	}

	// The clients that were admitted still work.
	if _, err := a.LogicalDevices(ctx); err != nil {
		t.Errorf("first client after the refusal: %v", err)
	}

	// Freeing a slot lets the next client in.
	b.Close()
	waitOpen(t, srv, 1)
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatalf("client after a slot was freed: %v", err)
	}
	defer c.Close()
	if _, err := c.LogicalDevices(ctx); err != nil {
		t.Errorf("replacement client: %v", err)
	}
	waitOpen(t, srv, 2)
}

// A server that closes disconnects its clients, and each of those is
// indicated.
func TestConnectionIndicationOnServerClose(t *testing.T) {
	rec := newConnRecorder()
	addr, srv := startConfigured(t)
	srv.OnConnection(rec.handle)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitOpen(t, srv, 1)

	srv.Close()
	rec.waitFor(t, "the close indication", func(evs []server.ConnectionEvent) bool {
		for _, e := range evs {
			if e.State == server.ConnectionClosed {
				return true
			}
		}
		return false
	})
	waitOpen(t, srv, 0)
}

func TestConnectionStateString(t *testing.T) {
	for _, tc := range []struct {
		s    server.ConnectionState
		want string
	}{
		{server.ConnectionOpened, "opened"},
		{server.ConnectionClosed, "closed"},
		{server.ConnectionRefused, "refused"},
		{server.ConnectionState(9), "ConnectionState(9)"},
	} {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}
