package goose

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
)

// Filter selects GOOSE messages for a subscription. Zero fields match
// everything: AppID 0 accepts any APPID, an empty GoCbRef accepts any
// control block.
type Filter struct {
	AppID   uint16
	GoCbRef string
}

func (f Filter) match(m *Message) bool {
	if f.AppID != 0 && m.AppID != f.AppID {
		return false
	}
	if f.GoCbRef != "" && m.GoCbRef != f.GoCbRef {
		return false
	}
	return true
}

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

// Subscriber receives GOOSE messages from a shared interface. Each
// Subscribe runs its own read goroutine; multiple concurrent
// subscriptions on one interface would compete for frames, so use one
// subscription per interface (or fan out in the callback).
type Subscriber struct {
	iface ethernet.Interface
}

// NewSubscriber returns a subscriber over iface.
func NewSubscriber(iface ethernet.Interface) *Subscriber {
	return &Subscriber{iface: iface}
}

// Subscribe delivers matching messages to cb from a background
// goroutine, with Anomalies set from per-goCbRef sequence tracking. The
// callback must not block. The returned stop function ends delivery;
// the goroutine itself exits on the next frame or when the interface is
// closed.
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
	sub := &subscription{f: f, cb: cb, expired: expired, states: make(map[string]*seqState)}
	go sub.run(s.iface)
	return sub.stop, nil
}

// seqState is the last observed sequence state for one goCbRef.
type seqState struct {
	stNum, sqNum uint32
	tatl         time.Duration
	arrival      time.Time
	timer        *time.Timer // fires when tatl passes with no message
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

// supervise restarts the time-allowed-to-live timer of ref.
func (sub *subscription) supervise(ref string, st *seqState) {
	if sub.expired == nil || st.tatl <= 0 {
		return
	}
	if st.timer != nil {
		st.timer.Stop()
	}
	st.timer = time.AfterFunc(st.tatl, func() {
		if !sub.stopped.Load() {
			sub.expired(ref)
		}
	})
}

func (sub *subscription) run(iface ethernet.Interface) {
	f, cb, stopped := sub.f, sub.cb, &sub.stopped
	for {
		fr, err := iface.ReadFrame()
		if err != nil {
			return
		}
		if stopped.Load() {
			return
		}
		if fr.EtherType != ethernet.EtherTypeGOOSE {
			continue
		}
		m, err := Parse(fr.Payload)
		if err != nil {
			continue
		}
		if !f.match(m) {
			continue
		}
		now := time.Now()
		m.Anomalies.EntriesMismatch = int(m.NumDatSetEntries) != len(m.Values)
		sub.mu.Lock()
		if st, ok := sub.states[m.GoCbRef]; ok {
			if m.StNum < st.stNum {
				m.Anomalies.StNumRegressed = true
			}
			if m.StNum == st.stNum {
				m.Anomalies.SqNumGap = m.SqNum != st.sqNum+1
			} else {
				m.Anomalies.SqNumGap = m.SqNum != 0
			}
			m.Anomalies.Stale = st.tatl > 0 && now.Sub(st.arrival) > st.tatl
			st.stNum, st.sqNum = m.StNum, m.SqNum
			st.arrival = now
			st.tatl = time.Duration(m.TimeAllowedToLive) * time.Millisecond
			sub.supervise(m.GoCbRef, st)
		} else {
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
		cb(m)
	}
}
