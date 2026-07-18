package sv

import (
	"errors"
	"sync/atomic"

	"github.com/dscsystems/go-iec61850/ethernet"
)

// Filter selects sampled-value streams. Zero fields match everything.
type Filter struct {
	AppID uint16
	SvID  string
}

func (f Filter) match(appID uint16, a *ASDU) bool {
	if f.AppID != 0 && appID != f.AppID {
		return false
	}
	if f.SvID != "" && a.SvID != f.SvID {
		return false
	}
	return true
}

// Subscriber receives sampled-value APDUs from a shared interface.
type Subscriber struct {
	iface ethernet.Interface
}

// NewSubscriber returns a subscriber over iface.
func NewSubscriber(iface ethernet.Interface) *Subscriber {
	return &Subscriber{iface: iface}
}

// Subscribe delivers each matching ASDU to cb from a background
// goroutine. The callback must not block. The returned stop function ends
// delivery.
func (s *Subscriber) Subscribe(f Filter, cb func(*ASDU)) (stop func(), err error) {
	if s.iface == nil {
		return nil, errors.New("sv: subscriber has no interface")
	}
	var stopped atomic.Bool
	go func() {
		for {
			fr, err := s.iface.ReadFrame()
			if err != nil {
				return
			}
			if stopped.Load() {
				return
			}
			if fr.EtherType != ethernet.EtherTypeSV {
				continue
			}
			pdu, err := Parse(fr.Payload)
			if err != nil {
				continue
			}
			for _, a := range pdu.ASDUs {
				if f.match(pdu.AppID, a) {
					cb(a)
				}
			}
		}
	}()
	return func() { stopped.Store(true) }, nil
}

// SubscribeLE delivers matching ASDUs decoded as 9-2LE samples. The
// *LESample passed to cb is reused between calls (zero-allocation steady
// state); copy it if you retain it beyond the callback.
func (s *Subscriber) SubscribeLE(f Filter, cb func(*LESample)) (stop func(), err error) {
	if s.iface == nil {
		return nil, errors.New("sv: subscriber has no interface")
	}
	var stopped atomic.Bool
	go func() {
		var sample LESample
		for {
			fr, err := s.iface.ReadFrame()
			if err != nil {
				return
			}
			if stopped.Load() {
				return
			}
			if fr.EtherType != ethernet.EtherTypeSV {
				continue
			}
			pdu, err := Parse(fr.Payload)
			if err != nil {
				continue
			}
			for _, a := range pdu.ASDUs {
				if !f.match(pdu.AppID, a) {
					continue
				}
				if err := decodeLEInto(a, &sample); err != nil {
					continue
				}
				cb(&sample)
			}
		}
	}()
	return func() { stopped.Store(true) }, nil
}
