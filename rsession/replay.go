package rsession

import "time"

// replayWindow tracks the SPDU numbers accepted from one sender under one
// key, in the manner of the IPsec anti-replay window (RFC 4303): the
// highest number seen, and a bitmap of the ones below it. Numbers are
// compared in serial number arithmetic (RFC 1982), so the counter may
// wrap.
type replayWindow struct {
	top    uint32
	seen   uint64 // bit i: top-i has been accepted
	last   time.Time
	primed bool
}

// accept reports whether SPDU number n is fresh, and records it if so.
// size is the window width (at most 64). A number too old for the window,
// or one already seen, is a replay, except after reset has passed with
// nothing accepted: a sender that restarts numbers from zero, as a
// restarted publisher does, is taken back rather than shut out until its
// counter overtakes the old one.
func (w *replayWindow) accept(n uint32, now time.Time, size int, reset time.Duration) bool {
	if !w.primed || (reset > 0 && now.Sub(w.last) > reset) {
		w.top, w.seen, w.last, w.primed = n, 1, now, true
		return true
	}
	diff := int32(n - w.top)
	switch {
	case diff > 0:
		if diff >= 64 {
			w.seen = 1
		} else {
			w.seen = w.seen<<uint(diff) | 1
		}
		w.top = n
	default:
		off := -int64(diff)
		if off >= int64(size) || w.seen&(1<<uint(off)) != 0 {
			return false
		}
		w.seen |= 1 << uint(off)
	}
	w.last = now
	return true
}
