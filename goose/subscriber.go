package goose

import (
	"errors"
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
	if s.iface == nil {
		return nil, errors.New("goose: subscriber has no interface")
	}
	var stopped atomic.Bool
	go s.run(f, cb, &stopped)
	return func() { stopped.Store(true) }, nil
}

// seqState is the last observed sequence state for one goCbRef.
type seqState struct {
	stNum, sqNum uint32
	tatl         time.Duration
	arrival      time.Time
}

func (s *Subscriber) run(f Filter, cb func(*Message), stopped *atomic.Bool) {
	states := make(map[string]*seqState)
	for {
		fr, err := s.iface.ReadFrame()
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
		if st, ok := states[m.GoCbRef]; ok {
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
		} else {
			states[m.GoCbRef] = &seqState{
				stNum:   m.StNum,
				sqNum:   m.SqNum,
				arrival: now,
				tatl:    time.Duration(m.TimeAllowedToLive) * time.Millisecond,
			}
		}
		cb(m)
	}
}
