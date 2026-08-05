package client

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The slot count comes from the association; a Client with no connection
// still has to hand out one, or ReadAsync would deadlock.
func TestOutstandingDefaultsToOne(t *testing.T) {
	c := &Client{}
	if got := cap(c.outstanding()); got != 1 {
		t.Errorf("slots = %d, want 1", got)
	}
	// The channel is built once and reused.
	if c.outstanding() != c.outstanding() {
		t.Error("outstanding returned two different channels")
	}
}

func TestAcquireBlocksAtTheLimit(t *testing.T) {
	c := &Client{}
	c.semOnce.Do(func() { c.sem = make(chan struct{}, 2) })

	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := c.acquire(ctx); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}

	// The third has to wait for a slot.
	third := make(chan error, 1)
	go func() { third <- c.acquire(ctx) }()
	select {
	case err := <-third:
		t.Fatalf("acquire beyond the limit returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	c.release()
	select {
	case err := <-third:
		if err != nil {
			t.Fatalf("acquire after release: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("release did not hand the slot on")
	}
}

// Waiting for a slot is bounded by the caller's context, not by the peer.
func TestAcquireHonoursContext(t *testing.T) {
	c := &Client{}
	c.semOnce.Do(func() { c.sem = make(chan struct{}, 1) })
	if err := c.acquire(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.acquire(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("acquire = %v, want DeadlineExceeded", err)
	}
	if time.Since(start) > time.Second {
		t.Error("acquire ignored the deadline")
	}
	// The failed acquire must not have taken the slot.
	c.release()
	if err := c.acquire(context.Background()); err != nil {
		t.Errorf("slot was leaked: %v", err)
	}
}
