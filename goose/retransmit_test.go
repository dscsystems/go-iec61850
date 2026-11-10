package goose

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/mms"
)

// flaky fails the writes numbered in fail and counts the rest.
type flaky struct {
	ethernet.Interface
	writes atomic.Int32
	failAt int32
}

func (f *flaky) WriteFrame(*ethernet.Frame) error {
	n := f.writes.Add(1)
	if n == f.failAt {
		return errors.New("transient send failure")
	}
	return nil
}
func (f *flaky) ReadFrame() (*ethernet.Frame, error) { select {} }
func (f *flaky) Close() error                        { return nil }

// A retransmission that fails to send does not end the stream: the next
// one still goes out, or subscribers would time out on a transient error.
func TestRetransmissionSurvivesSendError(t *testing.T) {
	f := &flaky{failAt: 2} // the first retransmission
	p, err := NewPublisher(f, PublisherConfig{GoCbRef: "LD/LLN0$GO$g", DatSet: "LD/LLN0$ds",
		Retrans: []time.Duration{5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Publish([]*mms.Value{mms.NewBool(true)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for f.writes.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := f.writes.Load(); n < 5 {
		t.Errorf("%d frames sent; retransmission stopped after the failed one", n)
	}
}

// The simulation bit of the header survives a round trip.
func TestSimulationBitRoundTrip(t *testing.T) {
	m := sampleMessage()
	for _, sim := range []bool{false, true} {
		m.Simulation = sim
		got, err := Parse(m.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if got.Simulation != sim {
			t.Errorf("Simulation = %v, want %v", got.Simulation, sim)
		}
	}
}

// A subscription does not track more streams than MaxStreams, but still
// delivers them.
func TestSubscriberStreamLimit(t *testing.T) {
	a, b := ethernet.Pipe()
	defer a.Close()
	var got atomic.Int32
	sub := &subscription{cb: func(*Message) { got.Add(1) }, states: map[string]*seqState{}}
	go sub.run(b)
	m := sampleMessage()
	total := MaxStreams + 50
	for i := range total {
		m.GoCbRef = "LD/LLN0$GO$g" + time.Duration(i).String()
		if err := a.WriteFrame(&ethernet.Frame{EtherType: ethernet.EtherTypeGOOSE, Payload: m.Marshal()}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for int(got.Load()) < total && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	sub.mu.Lock()
	n := len(sub.states)
	sub.mu.Unlock()
	if int(got.Load()) != total || n != MaxStreams {
		t.Errorf("delivered %d of %d, tracking %d streams (limit %d)", got.Load(), total, n, MaxStreams)
	}
}
