package sv

import (
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
)

func svFrame(appID uint16, svID string, sim bool) *ethernet.Frame {
	pdu := &PDU{AppID: appID, Simulation: sim, ASDUs: []*ASDU{{
		SvID: svID, ConfRev: 1, Sample: EncodeLESample(&LESample{}),
	}}}
	return &ethernet.Frame{
		Dst: DefaultMAC(1), EtherType: ethernet.EtherTypeSV, Payload: pdu.Marshal(),
	}
}

func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatalf("no %s", what)
	}
	var zero T
	return zero
}

// Two subscriptions on one Subscriber each see every frame they match,
// instead of racing for frames with a reader each.
func TestSubscriberFansOut(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	sub := NewSubscriber(subIf)
	a := make(chan string, 64)
	b := make(chan string, 64)
	stopA, err := sub.Subscribe(Filter{SvID: "A"}, func(x *ASDU) { a <- x.SvID })
	if err != nil {
		t.Fatal(err)
	}
	defer stopA()
	stopB, err := sub.SubscribeLE(Filter{SvID: "B"}, func(*LESample) { b <- "B" })
	if err != nil {
		t.Fatal(err)
	}
	defer stopB()

	const n = 20
	for i := 0; i < n; i++ {
		if err := pubIf.WriteFrame(svFrame(0x4000, "A", false)); err != nil {
			t.Fatal(err)
		}
		if err := pubIf.WriteFrame(svFrame(0x4000, "B", false)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		recv(t, a, "frame for A")
		recv(t, b, "frame for B")
	}
}

// Simulated frames reach only subscriptions that ask for them, and live
// frames only those that do not.
func TestSubscriberSimulation(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	sub := NewSubscriber(subIf)
	live := make(chan bool, 8)
	sim := make(chan bool, 8)
	stop1, _ := sub.Subscribe(Filter{AppID: 0x4000, SvID: "MU"}, func(*ASDU) { live <- true })
	defer stop1()
	stop2, _ := sub.Subscribe(Filter{AppID: 0x4000, SvID: "MU", Simulated: true}, func(*ASDU) { sim <- true })
	defer stop2()

	pubIf.WriteFrame(svFrame(0x4000, "MU", true))
	recv(t, sim, "simulated frame")
	pubIf.WriteFrame(svFrame(0x4000, "MU", false))
	recv(t, live, "live frame")
	// A further frame of each kind, then check neither leaked across.
	pubIf.WriteFrame(svFrame(0x4000, "MU", true))
	recv(t, sim, "second simulated frame")
	if len(live) != 0 {
		t.Error("simulated frame delivered to a live subscription")
	}
	pubIf.WriteFrame(svFrame(0x4000, "MU", false))
	recv(t, live, "second live frame")
	if len(sim) != 0 {
		t.Error("live frame delivered to a simulated subscription")
	}
}
