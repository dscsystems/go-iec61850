// Package netretry decides whether a failed Accept or ReadFrom is worth
// retrying, and paces the retries, so that a transient condition such as
// file-descriptor exhaustion does not end a server for good.
package netretry

import (
	"errors"
	"net"
	"time"
)

// Temporary reports whether err is a condition that may clear by itself:
// a timeout, or an error that says it is temporary (EMFILE, ENFILE,
// ECONNABORTED, ENOBUFS and the like, as the net package reports them).
// A closed listener or socket never is.
func Temporary(err error) bool {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return false
	}
	var t interface{ Temporary() bool }
	if errors.As(err, &t) && t.Temporary() {
		return true
	}
	var to interface{ Timeout() bool }
	return errors.As(err, &to) && to.Timeout()
}

// Backoff paces retries: 5 ms, doubling up to 1 s, as net/http.Server does
// for its accept loop. The zero value is ready to use.
type Backoff struct {
	d time.Duration
}

const (
	minDelay = 5 * time.Millisecond
	maxDelay = time.Second
)

// Next returns the delay before the next retry and lengthens the following
// one.
func (b *Backoff) Next() time.Duration {
	if b.d == 0 {
		b.d = minDelay
	} else {
		b.d = min(2*b.d, maxDelay)
	}
	return b.d
}

// Reset starts the pacing over, after a success.
func (b *Backoff) Reset() { b.d = 0 }
