package server_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// A control handler must be able to say where a command came from. The
// originator fields are the client's own claim about itself; the peer
// address is what the server observed, and it is per association, so it
// stays right when more than one client is connected.
func TestControlCtxCarriesThePeer(t *testing.T) {
	srv := server.New(sboCheckModel(model.CtlDirectNormal))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	var mu sync.Mutex
	seen := map[string]*server.ControlCtx{} // by orIdent
	srv.OnControl(selRef, func(cc *server.ControlCtx) model.AddCause {
		mu.Lock()
		copyOf := *cc
		seen[cc.OrIdent] = &copyOf
		mu.Unlock()
		return model.AddCauseNone
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	operate := func(ident string) *client.Client {
		t.Helper()
		c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
		if err != nil {
			t.Fatalf("dial %s: %v", ident, err)
		}
		co, err := c.ControlFor(ctx, selRef)
		if err != nil {
			t.Fatalf("ControlFor %s: %v", ident, err)
		}
		if err := co.Operate(ctx, mms.NewBool(true),
			client.WithOriginator(model.OrCatStationControl, ident)); err != nil {
			t.Fatalf("Operate %s: %v", ident, err)
		}
		return c
	}

	// Two clients, each with its own association and its own local port.
	a := operate("scada-a")
	defer a.Close()
	b := operate("scada-b")
	defer b.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("handler saw %d commands, want 2", len(seen))
	}
	for ident, cc := range seen {
		if cc.Conn == nil {
			t.Errorf("%s: no association on the control context", ident)
			continue
		}
		if cc.Peer == "" {
			t.Errorf("%s: no peer address", ident)
		}
		if cc.Conn.Peer == nil || cc.Conn.Peer.String() != cc.Peer {
			t.Errorf("%s: Peer %q does not match Conn.Peer %v", ident, cc.Peer, cc.Conn.Peer)
		}
		// The address has to be usable as an address, not just a label:
		// an audit trail wants the IP on its own.
		host, port, err := net.SplitHostPort(cc.Peer)
		if err != nil {
			t.Errorf("%s: peer %q is not host:port: %v", ident, cc.Peer, err)
			continue
		}
		if net.ParseIP(host) == nil {
			t.Errorf("%s: peer host %q is not an IP", ident, host)
		}
		if port == "" || port == "0" {
			t.Errorf("%s: peer port %q", ident, port)
		}
		if tcp, ok := cc.Conn.Peer.(*net.TCPAddr); !ok || tcp.IP == nil {
			t.Errorf("%s: Conn.Peer = %T, want a *net.TCPAddr carrying an IP", ident, cc.Conn.Peer)
		}
	}

	// The whole point: the two commands are distinguishable by what the
	// server observed, not only by what the clients claimed. Two
	// associations from the same host differ by port, so an audit trail
	// can attribute each command to its own connection.
	if seen["scada-a"].Peer == seen["scada-b"].Peer {
		t.Errorf("both associations reported the same peer %q", seen["scada-a"].Peer)
	}
	if seen["scada-a"].Conn == seen["scada-b"].Conn {
		t.Error("both commands reported the same association")
	}
}

// The select phase is delivered to the handler too, and carries the same
// association as the operate that follows it.
func TestControlCtxPeerOnSelectAndOperate(t *testing.T) {
	srv := server.New(sboCheckModel(model.CtlSBOEnhanced))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	var mu sync.Mutex
	var phases []*server.ControlCtx
	srv.OnControl(selRef, func(cc *server.ControlCtx) model.AddCause {
		mu.Lock()
		copyOf := *cc
		phases = append(phases, &copyOf)
		mu.Unlock()
		return model.AddCauseNone
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	co, err := c.ControlFor(ctx, selRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("Operate: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(phases) != 2 {
		t.Fatalf("handler saw %d phases, want select and operate", len(phases))
	}
	if !phases[0].Select || phases[1].Select {
		t.Fatalf("phases out of order: select=%v then select=%v", phases[0].Select, phases[1].Select)
	}
	for i, p := range phases {
		if p.Peer == "" || p.Conn == nil {
			t.Errorf("phase %d has no peer", i)
		}
	}
	if phases[0].Peer != phases[1].Peer {
		t.Errorf("select came from %q and operate from %q", phases[0].Peer, phases[1].Peer)
	}
	if phases[0].Conn != phases[1].Conn {
		t.Error("select and operate reported different associations")
	}
}
