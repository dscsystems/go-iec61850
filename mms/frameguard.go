package mms

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// ErrFrameTimeout ends an association whose peer started a TPKT and did
// not complete it within AcceptOptions.FrameTimeout: a peer that trickles,
// or stops in the middle of, a frame holds its connection, and the server's
// slot, for as long as it likes otherwise (a slow-read attack).
var ErrFrameTimeout = errors.New("mms: frame not completed in time")

// ErrIdleTimeout ends an association that neither sent nor received
// anything for AcceptOptions.IdleTimeout.
var ErrIdleTimeout = errors.New("mms: association idle")

// frameGuard sits between the transport and COTP on the server side once
// the association is set up. It follows the TPKT framing of the octets the
// server reads, and keeps a read deadline on the transport: while a frame
// is incomplete, its start plus frameTimeout; between frames, the last
// activity in either direction plus idleTimeout (none when zero).
//
// It is read by one goroutine (the association's reader) and written by
// several (responses, reports), which only touch lastAct.
type frameGuard struct {
	net.Conn
	frameTimeout, idleTimeout time.Duration

	on atomic.Bool
	// in and out count the octets read and written.
	in, out atomic.Uint64
	// lastAct is the time of the last octet read or written, in Unix
	// nanoseconds.
	lastAct atomic.Int64

	// Reader state.
	hdr        [4]byte
	hdrN       int // header octets of the current frame seen so far
	remaining  int // payload octets of the current frame still to come
	frameStart time.Time
	armed      time.Time // the read deadline currently set on Conn
}

func newFrameGuard(c net.Conn, frameTimeout, idleTimeout time.Duration) *frameGuard {
	return &frameGuard{Conn: c, frameTimeout: frameTimeout, idleTimeout: idleTimeout}
}

// enable starts the supervision. Until it is called the guard passes reads
// through, so the handshake's own deadline governs.
func (g *frameGuard) enable() {
	if g.frameTimeout <= 0 && g.idleTimeout <= 0 {
		return
	}
	g.touch()
	g.on.Store(true)
}

func (g *frameGuard) touch() { g.lastAct.Store(time.Now().UnixNano()) }

func (g *frameGuard) midFrame() bool { return g.hdrN > 0 || g.remaining > 0 }

func (g *frameGuard) Read(b []byte) (int, error) {
	if !g.on.Load() {
		n, err := g.Conn.Read(b)
		g.in.Add(uint64(n))
		return n, err
	}
	for {
		mid := g.midFrame()
		var dl time.Time
		switch {
		case mid && g.frameTimeout > 0:
			dl = g.frameStart.Add(g.frameTimeout)
		case !mid && g.idleTimeout > 0:
			dl = time.Unix(0, g.lastAct.Load()).Add(g.idleTimeout)
		}
		if !dl.Equal(g.armed) {
			if err := g.Conn.SetReadDeadline(dl); err != nil {
				return 0, err
			}
			g.armed = dl
		}
		n, err := g.Conn.Read(b)
		if n > 0 {
			g.in.Add(uint64(n))
			g.track(b[:n])
			g.touch()
			return n, err
		}
		var ne net.Error
		if err == nil || !errors.As(err, &ne) || !ne.Timeout() {
			return n, err
		}
		if mid {
			return 0, fmt.Errorf("%w (%v)", ErrFrameTimeout, g.frameTimeout)
		}
		if g.idleTimeout <= 0 {
			return n, err
		}
		// Something was written since the deadline was set: the
		// association is not idle, so wait again from that point.
		if time.Since(time.Unix(0, g.lastAct.Load())) < g.idleTimeout {
			continue
		}
		return 0, fmt.Errorf("%w for %v", ErrIdleTimeout, g.idleTimeout)
	}
}

// track follows the TPKT framing (RFC 1006: version, reserved, 16-bit
// length including the 4-octet header) across the octets read.
func (g *frameGuard) track(p []byte) {
	for len(p) > 0 {
		if g.remaining > 0 {
			k := min(len(p), g.remaining)
			g.remaining -= k
			p = p[k:]
			continue
		}
		if g.hdrN == 0 {
			g.frameStart = time.Now()
		}
		g.hdr[g.hdrN] = p[0]
		g.hdrN++
		p = p[1:]
		if g.hdrN == len(g.hdr) {
			g.hdrN = 0
			// A length below the header is refused by the TPKT reader;
			// it ends the association, so nothing more is tracked.
			g.remaining = max(int(binary.BigEndian.Uint16(g.hdr[2:]))-len(g.hdr), 0)
		}
	}
}

func (g *frameGuard) Write(b []byte) (int, error) {
	n, err := g.Conn.Write(b)
	g.out.Add(uint64(n))
	if n > 0 && g.on.Load() {
		g.touch()
	}
	return n, err
}
