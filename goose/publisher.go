package goose

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/mms"
)

// DefaultRetrans is the default retransmission schedule: exponential
// back-off from 4 ms, stable at 1 s.
var DefaultRetrans = []time.Duration{
	4 * time.Millisecond, 8 * time.Millisecond, 16 * time.Millisecond,
	32 * time.Millisecond, 64 * time.Millisecond, 128 * time.Millisecond,
	256 * time.Millisecond, 512 * time.Millisecond, time.Second,
}

// ErrClosed is returned by Publish after Close.
var ErrClosed = errors.New("goose: publisher closed")

// PublisherConfig identifies one GOOSE control block on the wire.
type PublisherConfig struct {
	DstMAC  [6]byte
	AppID   uint16
	VLAN    *ethernet.VLANTag
	GoCbRef string
	DatSet  string
	GoID    string
	ConfRev uint32
	SrcMAC  [6]byte
	// Retrans is the interval schedule after a state change; the last
	// entry repeats indefinitely. Defaults to DefaultRetrans.
	Retrans []time.Duration
}

// Publisher sends GOOSE messages with the standard retransmission state
// machine: each Publish increments stNum and restarts the schedule, and
// a background goroutine retransmits with increasing sqNum until the
// next Publish or Close. Safe for concurrent use.
type Publisher struct {
	iface ethernet.Interface
	cfg   PublisherConfig

	mu     sync.Mutex
	stNum  uint32
	stop   chan struct{} // stops the current retransmission loop
	closed bool
	wg     sync.WaitGroup
}

// NewPublisher returns a publisher over iface. The interface is shared,
// not owned: Close stops retransmission but leaves iface open.
func NewPublisher(iface ethernet.Interface, cfg PublisherConfig) (*Publisher, error) {
	if iface == nil {
		return nil, errors.New("goose: nil interface")
	}
	if cfg.GoCbRef == "" {
		return nil, errors.New("goose: PublisherConfig.GoCbRef is required")
	}
	if len(cfg.Retrans) == 0 {
		cfg.Retrans = DefaultRetrans
	} else {
		cfg.Retrans = append([]time.Duration(nil), cfg.Retrans...)
	}
	for _, d := range cfg.Retrans {
		if d <= 0 {
			return nil, fmt.Errorf("goose: retransmission interval %v not positive", d)
		}
	}
	return &Publisher{iface: iface, cfg: cfg}, nil
}

// Publish announces a state change: stNum increments, sqNum resets to
// zero, the message is sent immediately and retransmission restarts.
// The values must not be mutated until the next Publish or Close.
func (p *Publisher) Publish(values []*mms.Value) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	if p.stop != nil {
		close(p.stop)
	}
	p.stNum++
	msg := Message{
		GoCbRef:           p.cfg.GoCbRef,
		DatSet:            p.cfg.DatSet,
		GoID:              p.cfg.GoID,
		TimeAllowedToLive: p.tatl(0),
		T:                 time.Now(),
		StNum:             p.stNum,
		SqNum:             0,
		ConfRev:           p.cfg.ConfRev,
		NumDatSetEntries:  uint32(len(values)),
		Values:            values,
		AppID:             p.cfg.AppID,
	}
	if err := p.send(&msg); err != nil {
		return err
	}
	stop := make(chan struct{})
	p.stop = stop
	p.wg.Add(1)
	go p.retransmit(msg, stop)
	return nil
}

// Close stops retransmission and waits for the loop to exit. It does
// not close the underlying interface.
func (p *Publisher) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		if p.stop != nil {
			close(p.stop)
			p.stop = nil
		}
	}
	p.mu.Unlock()
	p.wg.Wait()
	return nil
}

// retransmit re-sends msg with incrementing sqNum on the configured
// schedule until stop is closed. T stays at the state-change time.
func (p *Publisher) retransmit(msg Message, stop chan struct{}) {
	defer p.wg.Done()
	for i := 0; ; i++ {
		idx := min(i, len(p.cfg.Retrans)-1)
		select {
		case <-stop:
			return
		case <-time.After(p.cfg.Retrans[idx]):
		}
		msg.SqNum++
		msg.TimeAllowedToLive = p.tatl(i + 1)
		// Send under the publisher lock and re-check stop, so a stale
		// retransmission can never follow the next Publish on the wire.
		p.mu.Lock()
		select {
		case <-stop:
			p.mu.Unlock()
			return
		default:
		}
		err := p.send(&msg)
		p.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// tatl returns timeAllowedToLive in milliseconds for transmission n of
// the current state: twice the interval until the next retransmission.
func (p *Publisher) tatl(n int) uint32 {
	d := p.cfg.Retrans[min(n, len(p.cfg.Retrans)-1)]
	ms := (2 * d).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return uint32(ms)
}

func (p *Publisher) send(msg *Message) error {
	return p.iface.WriteFrame(&ethernet.Frame{
		Dst:       p.cfg.DstMAC,
		Src:       p.cfg.SrcMAC,
		EtherType: ethernet.EtherTypeGOOSE,
		VLAN:      p.cfg.VLAN,
		Payload:   msg.Marshal(),
	})
}
