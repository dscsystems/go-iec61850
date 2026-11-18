package goose

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/mms"
)

// A publisher that falls silent is noticed once its timeAllowedToLive
// passes (IEC 61850-8-1), once, and not while it is retransmitting.
func TestSubscriberSupervisesTimeAllowedToLive(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	var expired atomic.Int32
	sub := NewSubscriber(subIf)
	stop, err := sub.SubscribeSupervised(Filter{AppID: 0x1000}, func(*Message) {}, func(ref string) {
		if ref == "IED1LD0/LLN0$GO$gcb01" {
			expired.Add(1)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	pub, err := NewPublisher(pubIf, PublisherConfig{
		AppID: 0x1000, GoCbRef: "IED1LD0/LLN0$GO$gcb01", DatSet: "ds", GoID: "g",
		// TAL 200 ms: a 100 ms margin over the retransmission absorbs
		// scheduler stalls on loaded CI runners.
		Retrans: []time.Duration{100 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish([]*mms.Value{mms.NewBool(true)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	if n := expired.Load(); n != 0 {
		t.Fatalf("expired %d times while the publisher was retransmitting", n)
	}
	pub.Close()
	deadline := time.Now().Add(3 * time.Second)
	for expired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond) // a second expiry would show here
	if n := expired.Load(); n != 1 {
		t.Fatalf("expired %d times after the publisher stopped, want 1", n)
	}
}

// numDatSetEntries that disagrees with allData is flagged.
func TestSubscriberFlagsEntriesMismatch(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	got := make(chan *Message, 1)
	stop, _ := NewSubscriber(subIf).Subscribe(Filter{}, func(m *Message) { got <- m })
	defer stop()

	m := sampleMessage() // two values
	m.NumDatSetEntries = 3
	pubIf.WriteFrame(&ethernet.Frame{EtherType: ethernet.EtherTypeGOOSE, Payload: m.Marshal()})
	select {
	case r := <-got:
		if !r.Anomalies.EntriesMismatch {
			t.Error("3 entries declared, 2 sent: not flagged")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no message")
	}
}

// Simulated traffic for a live goCbRef stays out of the live
// subscription: it is not delivered, and it does not keep the silent live
// stream from expiring.
func TestSimulatedTrafficDoesNotMaskLiveExpiry(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	const ref = "IED1LD0/LLN0$GO$gcb01"
	var expired, liveSimulated atomic.Int32
	sub := NewSubscriber(subIf)
	stop, err := sub.SubscribeSupervised(Filter{GoCbRef: ref}, func(m *Message) {
		if m.Simulation {
			liveSimulated.Add(1)
		}
	}, func(string) { expired.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	cfg := PublisherConfig{
		AppID: 0x1000, GoCbRef: ref, DatSet: "ds", GoID: "g",
		Retrans: []time.Duration{100 * time.Millisecond},
	}
	live, err := NewPublisher(pubIf, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Publish([]*mms.Value{mms.NewBool(true)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	live.Close()

	cfg.Simulation = true
	sim, err := NewPublisher(pubIf, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	if err := sim.Publish([]*mms.Value{mms.NewBool(false)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for expired.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if expired.Load() != 1 {
		t.Fatalf("live stream expired %d times while simulated traffic ran, want 1", expired.Load())
	}
	if liveSimulated.Load() != 0 {
		t.Error("simulated message delivered to a live subscription")
	}

	// A simulated subscription sees the simulated stream.
	got := make(chan *Message, 1)
	stopSim, _ := sub.Subscribe(Filter{GoCbRef: ref, Simulated: true}, func(m *Message) {
		select {
		case got <- m:
		default:
		}
	})
	defer stopSim()
	select {
	case m := <-got:
		if !m.Simulation {
			t.Error("live message delivered to a simulated subscription")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("simulated subscription received nothing")
	}
}

// A Refresh continues the sequence of the state it repeats, so the
// project's own subscriber sees no sqNum gap across it.
func TestRefreshKeepsSequence(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	got := make(chan *Message, 64)
	stop, _ := NewSubscriber(subIf).Subscribe(Filter{}, func(m *Message) { got <- m })
	defer stop()

	pub, err := NewPublisher(pubIf, PublisherConfig{
		AppID: 0x1000, GoCbRef: "IED1LD0/LLN0$GO$gcb01", DatSet: "ds", GoID: "g",
		Retrans: []time.Duration{20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	values := []*mms.Value{mms.NewBool(true)}
	if err := pub.Publish(values); err != nil {
		t.Fatal(err)
	}
	time.Sleep(70 * time.Millisecond)
	if err := pub.Refresh(values); err != nil {
		t.Fatal(err)
	}
	time.Sleep(70 * time.Millisecond)
	pub.Close()

	var prev uint32
	n := 0
	for len(got) > 0 {
		m := <-got
		if m.Anomalies.SqNumGap {
			t.Errorf("sqNum gap at stNum %d sqNum %d after sqNum %d", m.StNum, m.SqNum, prev)
		}
		if m.StNum != 1 {
			t.Errorf("stNum = %d, want 1 throughout", m.StNum)
		}
		prev = m.SqNum
		n++
	}
	if n < 4 {
		t.Fatalf("only %d messages received", n)
	}
}

// Subscriptions on one Subscriber each see every message they match, so
// two of them on the same stream both track an unbroken sequence instead
// of seeing the gaps left by frames the other consumed.
func TestSubscriberFansOut(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	sub := NewSubscriber(subIf)
	var counts [2]atomic.Int32
	var gaps atomic.Int32
	for i := range counts {
		stop, err := sub.Subscribe(Filter{AppID: 0x1000}, func(m *Message) {
			if m.Anomalies.SqNumGap || m.Anomalies.StNumRegressed {
				gaps.Add(1)
			}
			counts[i].Add(1)
		})
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
	}

	m := sampleMessage()
	m.AppID = 0x1000
	const n = 40
	for i := range n {
		m.StNum, m.SqNum = 1, uint32(i)
		if err := pubIf.WriteFrame(&ethernet.Frame{EtherType: ethernet.EtherTypeGOOSE, Payload: m.Marshal()}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for (counts[0].Load() < n || counts[1].Load() < n) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if counts[0].Load() != n || counts[1].Load() != n {
		t.Fatalf("delivered %d and %d of %d", counts[0].Load(), counts[1].Load(), n)
	}
	if g := gaps.Load(); g != 0 {
		t.Errorf("%d sequence anomalies on an unbroken stream", g)
	}
}
