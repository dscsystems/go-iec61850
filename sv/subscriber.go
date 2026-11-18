package sv

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/dscsystems/go-iec61850/ethernet"
)

// Filter selects sampled-value streams. Zero fields match every live
// stream.
type Filter struct {
	AppID uint16
	SvID  string
	// Simulated selects frames by the simulation bit of the APDU header.
	// False, the default, accepts only live frames and drops simulated
	// ones, so a commissioning stream reusing a live stream's APPID and
	// svID never reaches a live consumer. True accepts only simulated
	// frames; a consumer that wants both subscribes twice.
	Simulated bool
}

func (f Filter) match(pdu *PDU, a *ASDU) bool {
	if pdu.Simulation != f.Simulated {
		return false
	}
	if f.AppID != 0 && pdu.AppID != f.AppID {
		return false
	}
	if f.SvID != "" && a.SvID != f.SvID {
		return false
	}
	return true
}

// Subscriber receives sampled-value APDUs from a shared interface. One
// goroutine reads the interface, started by the first subscription, and
// hands each frame to every subscription it matches, so subscriptions on
// one Subscriber do not compete for frames. Create one Subscriber per
// interface: two Subscribers on the same interface would.
type Subscriber struct {
	iface ethernet.Interface

	mu      sync.Mutex
	subs    []*subscription
	started bool
}

type subscription struct {
	f       Filter
	asdu    func(*ASDU)
	le      func(*LESample)
	sample  LESample // reused for le; touched only by the reader goroutine
	stopped atomic.Bool
}

// NewSubscriber returns a subscriber over iface.
func NewSubscriber(iface ethernet.Interface) *Subscriber {
	return &Subscriber{iface: iface}
}

// Subscribe delivers each matching ASDU to cb from the subscriber's
// reader goroutine. The callback must not block: it delays every other
// subscription. The *ASDU is shared with every other subscription the
// frame matches, so cb must not modify it. The returned stop function ends delivery: no frame read
// after it returns is delivered. The reader itself exits when the
// interface closes.
func (s *Subscriber) Subscribe(f Filter, cb func(*ASDU)) (stop func(), err error) {
	if cb == nil {
		return nil, errors.New("sv: nil callback")
	}
	return s.add(&subscription{f: f, asdu: cb})
}

// SubscribeLE delivers matching ASDUs decoded as 9-2LE samples. The
// *LESample passed to cb is reused between calls (zero-allocation steady
// state); copy it if you retain it beyond the callback. stop is as
// Subscribe's.
func (s *Subscriber) SubscribeLE(f Filter, cb func(*LESample)) (stop func(), err error) {
	if cb == nil {
		return nil, errors.New("sv: nil callback")
	}
	return s.add(&subscription{f: f, le: cb})
}

func (s *Subscriber) add(sub *subscription) (func(), error) {
	if s.iface == nil {
		return nil, errors.New("sv: subscriber has no interface")
	}
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
	sub.stopped.Store(true)
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
		if fr.EtherType != ethernet.EtherTypeSV {
			continue
		}
		s.mu.Lock()
		subs := s.subs
		s.mu.Unlock()
		if len(subs) == 0 {
			continue
		}
		pdu, err := Parse(fr.Payload)
		if err != nil {
			continue
		}
		for _, a := range pdu.ASDUs {
			for _, sub := range subs {
				if sub.stopped.Load() || !sub.f.match(pdu, a) {
					continue
				}
				if sub.asdu != nil {
					sub.asdu(a)
					continue
				}
				if err := decodeLEInto(a, &sub.sample); err != nil {
					continue
				}
				sub.le(&sub.sample)
			}
		}
	}
}
