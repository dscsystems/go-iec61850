package goose

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
)

// Filter selects GOOSE messages for a subscription. Zero fields match
// every live message: AppID 0 accepts any APPID, an empty GoCbRef accepts
// any control block.
type Filter struct {
	AppID   uint16
	GoCbRef string
	// Simulated selects messages by the simulation bit of the APDU header.
	// False, the default, accepts only live messages and drops simulated
	// ones before they reach sequence tracking or supervision, so a
	// simulated publisher reusing a live goCbRef can neither disturb the
	// live stream's sequence nor keep its time-allowed-to-live from
	// expiring. True accepts only simulated messages; a consumer that wants
	// both subscribes twice, and each subscription supervises its own.
	Simulated bool
}

func (f Filter) match(m *Message) bool {
	if m.Simulation != f.Simulated {
		return false
	}
	if f.AppID != 0 && m.AppID != f.AppID {
		return false
	}
	if f.GoCbRef != "" && m.GoCbRef != f.GoCbRef {
		return false
	}
	return true
}

// MaxStreams is how many control blocks a subscription tracks the sequence
// of at once. Filter on GoCbRef to be sure of the ones that matter.
const MaxStreams = 4096

// Anomalies flags protocol irregularities detected by a subscriber from
// the per-goCbRef sequence state. They are diagnostics, not part of the
// wire format.
type Anomalies struct {
	StNumRegressed bool // stNum went backwards
	SqNumGap       bool // sqNum skipped, or did not restart at zero on a new stNum
	Stale          bool // inter-arrival time exceeded the previous timeAllowedToLive
	// EntriesMismatch is set when numDatSetEntries disagrees with the
	// number of values in allData; the message's data cannot be trusted.
	EntriesMismatch bool
}

// Subscriber receives GOOSE messages from a shared interface. One
// goroutine reads the interface, started by the first subscription, and
// hands each message to every subscription it matches, so subscriptions on
// one Subscriber do not compete for frames. Each subscription tracks
// sequence and supervises liveness on its own. Create one Subscriber per
// interface: two Subscribers on the same interface would compete.
type Subscriber struct {
	iface ethernet.Interface

	mu      sync.Mutex
	subs    []*subscription
	started bool
}

// NewSubscriber returns a subscriber over iface.
func NewSubscriber(iface ethernet.Interface) *Subscriber {
	return &Subscriber{iface: iface}
}

// Subscribe delivers matching messages to cb from the subscriber's
// reader goroutine, with Anomalies set from this subscription's
// per-goCbRef sequence tracking. Each subscription receives its own
// *Message, but the Values are shared with the other subscriptions the
// message matches, so cb must not modify them. The callback must not
// block: it delays every other subscription. The returned stop function
// ends delivery; the reader itself exits when the interface closes.
func (s *Subscriber) Subscribe(f Filter, cb func(*Message)) (stop func(), err error) {
	return s.SubscribeSupervised(f, cb, nil)
}

// SubscribeSupervised is Subscribe with time-allowed-to-live supervision
// (IEC 61850-8-1): a subscriber has to treat a control block's data as
// invalid once timeAllowedToLive passes without a message, which is how a
// failed publisher or a broken path is noticed. expired is called with the
// goCbRef when that happens, from a timer goroutine, once per silence: the
// next message from that control block ends it. A nil expired supervises
// nothing, as Subscribe.
func (s *Subscriber) SubscribeSupervised(f Filter, cb func(*Message), expired func(goCbRef string)) (stop func(), err error) {
	if s.iface == nil {
		return nil, errors.New("goose: subscriber has no interface")
	}
	if cb == nil {
		return nil, errors.New("goose: nil callback")
	}
	sub := &subscription{f: f, cb: cb, expired: expired, states: make(map[string]*seqState)}
	s.mu.Lock()
	s.subs = append(s.subs, sub)
	if !s.started {
		s.started = true
		go s.run()
	}
	s.mu.Unlock()
	return func() { s.remove(sub) }, nil
}

func (s *Subscriber) remove(sub *subscription) {
	sub.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.subs {
		if x == sub {
			// Copy rather than splice in place: the reader may be
			// iterating a snapshot of the old slice.
			subs := make([]*subscription, 0, len(s.subs)-1)
			subs = append(subs, s.subs[:i]...)
			s.subs = append(subs, s.subs[i+1:]...)
			return
		}
	}
}

func (s *Subscriber) run() {
	for {
		fr, err := s.iface.ReadFrame()
		if err != nil {
			s.mu.Lock()
			s.started = false
			s.mu.Unlock()
			return
		}
		if fr.EtherType != ethernet.EtherTypeGOOSE {
			continue
		}
		s.mu.Lock()
		subs := s.subs
		s.mu.Unlock()
		if len(subs) == 0 {
			continue
		}
		m, err := Parse(fr.Payload)
		if err != nil {
			continue
		}
		m.Anomalies.EntriesMismatch = int(m.NumDatSetEntries) != len(m.Values)
		now := time.Now()
		for _, sub := range subs {
			if sub.stopped.Load() || !sub.f.match(m) {
				continue
			}
			mc := *m // Anomalies are per subscription
			sub.deliver(&mc, now)
		}
	}
}

// seqState is the last observed sequence state for one goCbRef.
type seqState struct {
	stNum, sqNum uint32
	tatl         time.Duration
	arrival      time.Time
	timer        *time.Timer // fires when tatl passes with no message
	// gen identifies the current timer: a timer superseded by a later
	// message may already be firing, and must not report expiry.
	gen uint64
}

type subscription struct {
	f       Filter
	cb      func(*Message)
	expired func(string)
	stopped atomic.Bool

	mu     sync.Mutex // guards states against the supervision timers
	states map[string]*seqState
}

func (sub *subscription) stop() {
	sub.stopped.Store(true)
	sub.mu.Lock()
	for _, st := range sub.states {
		if st.timer != nil {
			st.timer.Stop()
		}
	}
	sub.mu.Unlock()
}

// supervise restarts the time-allowed-to-live timer of ref. It is called
// with sub.mu held.
func (sub *subscription) supervise(ref string, st *seqState) {
	if sub.expired == nil || st.tatl <= 0 {
		return
	}
	if st.timer != nil {
		st.timer.Stop()
	}
	st.gen++
	gen := st.gen
	st.timer = time.AfterFunc(st.tatl, func() {
		sub.mu.Lock()
		current := st.gen == gen
		sub.mu.Unlock()
		if current && !sub.stopped.Load() {
			sub.expired(ref)
		}
	})
}

// deliver updates the sequence state of m's goCbRef, flags anomalies and
// hands m to the callback. It runs on the reader goroutine.
func (sub *subscription) deliver(m *Message, now time.Time) {
	sub.mu.Lock()
	if st, ok := sub.states[m.GoCbRef]; ok {
		// Both counters roll over to 1, not 0, so the wrap is
		// neither a regression nor a gap.
		wrapped := st.stNum == math.MaxUint32 && m.StNum == 1
		if m.StNum < st.stNum && !wrapped {
			m.Anomalies.StNumRegressed = true
		}
		if m.StNum == st.stNum {
			next := st.sqNum + 1
			if next == 0 {
				next = 1
			}
			m.Anomalies.SqNumGap = m.SqNum != next
		} else {
			m.Anomalies.SqNumGap = m.SqNum != 0
		}
		m.Anomalies.Stale = st.tatl > 0 && now.Sub(st.arrival) > st.tatl
		st.stNum, st.sqNum = m.StNum, m.SqNum
		st.arrival = now
		st.tatl = time.Duration(m.TimeAllowedToLive) * time.Millisecond
		sub.supervise(m.GoCbRef, st)
	} else if len(sub.states) < MaxStreams {
		// A stream beyond the limit is delivered but not tracked: its
		// sequence is not checked and its liveness not supervised, so an
		// unfiltered subscription on a hostile network cannot grow
		// without bound.
		st := &seqState{
			stNum:   m.StNum,
			sqNum:   m.SqNum,
			arrival: now,
			tatl:    time.Duration(m.TimeAllowedToLive) * time.Millisecond,
		}
		sub.states[m.GoCbRef] = st
		sub.supervise(m.GoCbRef, st)
	}
	sub.mu.Unlock()
	sub.cb(m)
}
