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
		Retrans: []time.Duration{20 * time.Millisecond}, // TAL 40 ms
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Publish([]*mms.Value{mms.NewBool(true)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := expired.Load(); n != 0 {
		t.Fatalf("expired %d times while the publisher was retransmitting", n)
	}
	pub.Close()
	time.Sleep(200 * time.Millisecond)
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
