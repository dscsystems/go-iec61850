package goose

import (
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

func sampleMessage() *Message {
	return &Message{
		GoCbRef:           "IED1LD0/LLN0$GO$gcb01",
		DatSet:            "IED1LD0/LLN0$Events",
		GoID:              "events",
		TimeAllowedToLive: 2000,
		T:                 time.Unix(1_700_000_000, 500_000_000).UTC(),
		StNum:             7,
		SqNum:             3,
		ConfRev:           1,
		Test:              false,
		NumDatSetEntries:  2,
		AppID:             0x1000,
		Values:            []*mms.Value{mms.NewBool(true), model.QualityGood.Value()},
	}
}

func TestMessageRoundTrip(t *testing.T) {
	m := sampleMessage()
	apdu := m.Marshal()

	// Header sanity: APPID and length.
	if apdu[0] != 0x10 || apdu[1] != 0x00 {
		t.Fatalf("APPID header = %x %x", apdu[0], apdu[1])
	}
	length := int(apdu[2])<<8 | int(apdu[3])
	if length != len(apdu) {
		t.Fatalf("length field %d != apdu len %d", length, len(apdu))
	}
	if apdu[8] != 0x61 {
		t.Fatalf("goosePdu tag = %x, want 61", apdu[8])
	}

	got, err := Parse(apdu)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.GoCbRef != m.GoCbRef || got.DatSet != m.DatSet || got.GoID != m.GoID ||
		got.StNum != m.StNum || got.SqNum != m.SqNum || got.ConfRev != m.ConfRev ||
		got.NumDatSetEntries != m.NumDatSetEntries || got.AppID != m.AppID {
		t.Fatalf("field mismatch: %+v", got)
	}
	if len(got.Values) != 2 || !got.Values[0].Bool() {
		t.Fatalf("values mismatch: %v", got.Values)
	}
	if d := got.T.Sub(m.T); d > time.Millisecond || d < -time.Millisecond {
		t.Fatalf("timestamp drift %v", d)
	}
}

func TestPublishSubscribeLoopback(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	var mu sync.Mutex
	var got []*Message
	done := make(chan struct{})

	sub := NewSubscriber(subIf)
	stop, err := sub.Subscribe(Filter{AppID: 0x1000}, func(m *Message) {
		mu.Lock()
		got = append(got, m)
		n := len(got)
		mu.Unlock()
		if n == 3 {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	pub, err := NewPublisher(pubIf, PublisherConfig{
		AppID: 0x1000, GoCbRef: "IED1LD0/LLN0$GO$gcb01", DatSet: "ds", GoID: "g",
		Retrans: []time.Duration{5 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	if err := pub.Publish([]*mms.Value{mms.NewBool(true)}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive 3 messages")
	}

	mu.Lock()
	defer mu.Unlock()
	// First message is the state change (stNum=1, sqNum=0); retransmissions
	// increment sqNum.
	if got[0].StNum != 1 || got[0].SqNum != 0 {
		t.Fatalf("first message stNum/sqNum = %d/%d", got[0].StNum, got[0].SqNum)
	}
	if got[1].SqNum != 1 || got[2].SqNum != 2 {
		t.Fatalf("retransmission sqNums = %d,%d", got[1].SqNum, got[2].SqNum)
	}
}

func TestSubscriberAnomalies(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	msgs := make(chan *Message, 8)
	sub := NewSubscriber(subIf)
	stop, _ := sub.Subscribe(Filter{}, func(m *Message) { msgs <- m })
	defer stop()

	send := func(stNum, sqNum uint32) {
		m := sampleMessage()
		m.StNum, m.SqNum, m.TimeAllowedToLive = stNum, sqNum, 2000
		pubIf.WriteFrame(&ethernet.Frame{EtherType: ethernet.EtherTypeGOOSE, Payload: m.Marshal()})
	}

	send(5, 0) // first: no anomaly baseline
	<-msgs
	send(5, 2) // sqNum gap (expected 1)
	if m := <-msgs; !m.Anomalies.SqNumGap {
		t.Error("expected SqNumGap")
	}
	send(3, 0) // stNum regression
	if m := <-msgs; !m.Anomalies.StNumRegressed {
		t.Error("expected StNumRegressed")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sampleMessage().Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := Parse(data); err == nil {
			m.Marshal()
		}
	})
}
