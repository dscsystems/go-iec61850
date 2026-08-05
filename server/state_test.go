package server_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// waitState polls until the connection reaches want, mirroring how a
// supervisor would use State to notice a dropped association.
func waitState(t *testing.T, c *client.Client, want mms.State) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.State(); got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("state = %s after 3s, want %s", c.State(), want)
}

func TestConnectionStateLifecycle(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.State(); got != mms.StateConnected {
		t.Fatalf("state after Dial = %s, want connected", got)
	}
	if err := c.Err(); err != nil {
		t.Fatalf("Err on a live connection = %v, want nil", err)
	}

	// A request keeps it connected.
	if _, err := c.LogicalDevices(ctx); err != nil {
		t.Fatalf("LogicalDevices: %v", err)
	}
	if got := c.State(); got != mms.StateConnected {
		t.Fatalf("state after a request = %s, want connected", got)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := c.State(); got != mms.StateClosed {
		t.Fatalf("state after Close = %s, want closed", got)
	}
	if err := c.Err(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Err after Close = %v, want net.ErrClosed", err)
	}
	// Close is idempotent and does not move the state back.
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if got := c.State(); got != mms.StateClosed {
		t.Errorf("state after a second Close = %s, want closed", got)
	}
	// Requests on a closed connection fail rather than hang.
	if _, err := c.LogicalDevices(context.Background()); err == nil {
		t.Error("request on a closed connection succeeded")
	}
}

// The point of the state: a peer that drops the association is visible
// without a request having to fail first.
func TestConnectionStateFollowsPeerDisconnect(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got := c.State(); got != mms.StateConnected {
		t.Fatalf("state = %s, want connected", got)
	}

	srv.Close() // drops the association from the server side

	waitState(t, c, mms.StateClosed)
	if err := c.Err(); err == nil || errors.Is(err, net.ErrClosed) {
		t.Errorf("Err after a peer disconnect = %v, want the transport error", err)
	}
	if _, err := c.Read(context.Background(), model.ObjectReference("x/y.z"), model.ST); err == nil {
		t.Error("read on a dropped connection succeeded")
	}
}

func TestZeroClientStateIsClosed(t *testing.T) {
	var c *client.Client
	if got := c.State(); got != mms.StateClosed {
		t.Errorf("nil client state = %s, want closed", got)
	}
	if err := c.Err(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("nil client Err = %v, want net.ErrClosed", err)
	}
	select {
	case <-c.Done():
	default:
		t.Error("nil client Done() blocks; it must be already closed")
	}
}

// Done is the wait counterpart of State: a supervisor blocks on it instead
// of polling, and the state and cause are settled by the time it fires.
func TestDoneFiresOnPeerDisconnect(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	select {
	case <-c.Done():
		t.Fatal("Done fired on a live connection")
	default:
	}

	// Wait from another goroutine, as a supervisor would.
	lost := make(chan struct{})
	go func() {
		<-c.Done()
		close(lost)
	}()

	srv.Close()

	select {
	case <-lost:
	case <-time.After(3 * time.Second):
		t.Fatal("Done did not fire after the peer disconnected")
	}
	if got := c.State(); got != mms.StateClosed {
		t.Errorf("state when Done fired = %s, want closed", got)
	}
	if err := c.Err(); err == nil {
		t.Error("Err was not set when Done fired")
	}

	// Waiting again on an ended connection returns immediately.
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Error("Done blocked on an already-closed connection")
	}
}

func TestDoneFiresOnLocalClose(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	done := c.Done()
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close waits for the reader, so Done is already closed on return.
	select {
	case <-done:
	default:
		t.Fatal("Done had not fired when Close returned")
	}
	if err := c.Err(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Err after Close = %v, want net.ErrClosed", err)
	}
}
