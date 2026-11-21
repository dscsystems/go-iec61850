package mms

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// readAll drains the guard until it fails, returning the error.
func readUntilErr(g *frameGuard) error {
	buf := make([]byte, 64)
	for {
		if _, err := g.Read(buf); err != nil {
			return err
		}
	}
}

func TestFrameGuardStalledFrame(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	g := newFrameGuard(a, 100*time.Millisecond, 0)
	g.enable()
	// A whole frame, then half of a header.
	go b.Write([]byte{3, 0, 0, 6, 0xaa, 0xbb, 3, 0})
	start := time.Now()
	err := readUntilErr(g)
	if !errors.Is(err, ErrFrameTimeout) {
		t.Fatalf("err = %v, want ErrFrameTimeout", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestFrameGuardNoTimeoutBetweenFrames(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	g := newFrameGuard(a, 50*time.Millisecond, 0)
	g.enable()
	go func() {
		b.Write([]byte{3, 0, 0, 5, 1})
		// Silence between frames is not governed by the frame timeout.
		time.Sleep(200 * time.Millisecond)
		b.Write([]byte{3, 0, 0, 5, 2})
		b.Close()
	}()
	err := readUntilErr(g)
	if err != io.EOF {
		t.Fatalf("err = %v, want EOF after both frames", err)
	}
}

func TestFrameGuardIdle(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	g := newFrameGuard(a, 0, 100*time.Millisecond)
	g.enable()
	if err := readUntilErr(g); !errors.Is(err, ErrIdleTimeout) {
		t.Fatalf("err = %v, want ErrIdleTimeout", err)
	}
}

// Outbound traffic keeps an association alive: a client that only
// receives reports is not idle.
func TestFrameGuardWritesCountAsActivity(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go io.Copy(io.Discard, b)
	g := newFrameGuard(a, 0, 150*time.Millisecond)
	g.enable()
	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(40 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				g.Write([]byte{0})
			}
		}
	}()
	errc := make(chan error, 1)
	go func() { errc <- readUntilErr(g) }()
	select {
	case err := <-errc:
		t.Fatalf("closed while writing: %v", err)
	case <-time.After(600 * time.Millisecond):
	}
	close(stop)
	select {
	case err := <-errc:
		if !errors.Is(err, ErrIdleTimeout) {
			t.Fatalf("err = %v, want ErrIdleTimeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no idle timeout after the writes stopped")
	}
}

// Before enable the guard is transparent, so the handshake deadline set
// by the caller governs alone.
func TestFrameGuardDisabledPassesThrough(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	g := newFrameGuard(a, 10*time.Millisecond, 10*time.Millisecond)
	go func() {
		b.Write([]byte{3, 0})
		time.Sleep(100 * time.Millisecond)
		b.Write([]byte{0, 4})
		b.Close()
	}()
	if err := readUntilErr(g); err != io.EOF {
		t.Fatalf("err = %v, want EOF", err)
	}
}

func TestFrameGuardTrack(t *testing.T) {
	g := newFrameGuard(nil, time.Second, 0)
	// Split arbitrarily across reads: frame of 7 (3 payload), then 4 (none).
	for _, p := range [][]byte{{3}, {0, 0}, {7, 1, 2}, {3, 3, 0, 0}, {4}} {
		g.track(p)
	}
	if g.midFrame() {
		t.Fatalf("mid-frame after complete frames: hdrN=%d remaining=%d", g.hdrN, g.remaining)
	}
	g.track([]byte{3, 0, 0, 9, 1})
	if !g.midFrame() || g.remaining != 4 {
		t.Fatalf("hdrN=%d remaining=%d, want remaining 4", g.hdrN, g.remaining)
	}
}
