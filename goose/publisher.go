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
	// entry repeats indefinitely. Defaults to DefaultRetrans. MinTime and
	// MaxTime from the SCL build this schedule: the first interval is the
	// minimum time between transmissions and the steady one the maximum,
	// with the doubling between them that makes the receiver back off
	// smoothly. See NewPublisherFromModel.
	Retrans []time.Duration
	// Test and NdsCom set the corresponding GOOSE fields, which tell a
	// receiver that the publisher is in test or commissioning state. A
	// receiver is expected to act on them, so they are only set
	// deliberately.
	Test   bool
	NdsCom bool
	// TimeQuality is the quality of the time stamp in the message. The
	// zero value carries the library's default: leap seconds known and an
	// accuracy of 10.
	TimeQuality mms.TimeQuality
}

// Publisher sends GOOSE messages with the standard retransmission state
// machine. Publish announces a state change: it increments stNum, resets
// sqNum and restarts the schedule. Refresh repeats the current state: it
// leaves stNum alone and only restarts the schedule, which is what
// IEC 61850-8-1 requires a publisher to do when nothing has changed. A
// background goroutine retransmits with increasing sqNum until the next
// Publish, Refresh or Close. Safe for concurrent use.
type Publisher struct {
	iface ethernet.Interface
	cfg   PublisherConfig

	mu     sync.Mutex
	stNum  uint32
	sqNum  uint32
	msg    Message       // the state currently being advertised
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
// The values must not be mutated until the next Publish, Refresh or Close.
//
// stNum starts at 1 and never returns to 0. IEC 61850-8-1 reserves 0 for
// "no state change yet", so a receiver that treats it as a state change
// would report one where the publisher has made none; on wrap the counter
// goes to 1, skipping 0.
func (p *Publisher) Publish(values []*mms.Value) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	p.stNum++
	if p.stNum == 0 {
		p.stNum = 1
	}
	p.sqNum = 0
	return p.publishLocked(values, true)
}

// Refresh repeats the current state without announcing a change: stNum
// stays where it is, sqNum resets, and the retransmission schedule
// restarts. Use it to re-advertise a value that has not changed, for
// instance after a subscriber has evidently lost the stream.
//
// The values must not be mutated until the next Publish, Refresh or Close.
// A Refresh before any Publish has nothing to repeat, so it behaves as one.
func (p *Publisher) Refresh(values []*mms.Value) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	if p.stNum == 0 {
		p.stNum = 1
	}
	p.sqNum = 0
	return p.publishLocked(values, false)
}

// publishLocked sends the message and starts a new retransmission loop.
func (p *Publisher) publishLocked(values []*mms.Value, stateChange bool) error {
	if p.stop != nil {
		close(p.stop)
	}
	t := time.Now()
	if !stateChange && !p.msg.T.IsZero() {
		// A refresh keeps the timestamp of the change it repeats, so a
		// receiver can tell how old the state is.
		t = p.msg.T
	}
	p.msg = Message{
		GoCbRef:           p.cfg.GoCbRef,
		DatSet:            p.cfg.DatSet,
		GoID:              p.cfg.GoID,
		TimeAllowedToLive: p.tatl(0),
		T:                 t,
		StNum:             p.stNum,
		SqNum:             0,
		ConfRev:           p.cfg.ConfRev,
		NumDatSetEntries:  uint32(len(values)),
		Values:            values,
		AppID:             p.cfg.AppID,
		Test:              p.cfg.Test,
		NdsCom:            p.cfg.NdsCom,
		TimeQuality:       p.cfg.TimeQuality,
	}
	msg := p.msg
	if err := p.send(&msg); err != nil {
		return err
	}
	stop := make(chan struct{})
	p.stop = stop
	p.wg.Add(1)
	go p.retransmit(msg, stop)
	return nil
}

// State returns the stNum and sqNum the publisher is currently
// advertising.
func (p *Publisher) State() (stNum, sqNum uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stNum, p.sqNum
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
		// The state is updated inside the same critical section, so a
		// goroutine whose state has been superseded cannot overwrite the
		// counters of the state that replaced it.
		p.mu.Lock()
		select {
		case <-stop:
			p.mu.Unlock()
			return
		default:
		}
		p.sqNum = msg.SqNum
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
