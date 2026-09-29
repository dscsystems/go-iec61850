package goose

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// capture records the messages a publisher sends.
type capture struct {
	mu   sync.Mutex
	msgs []Message
	net  []ethernet.Frame
}

func (c *capture) WriteFrame(f *ethernet.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.net = append(c.net, *f)
	if m, err := Parse(f.Payload); err == nil {
		c.msgs = append(c.msgs, *m)
	}
	return nil
}

func (c *capture) Close() error { return nil }

// ReadFrame is part of ethernet.Interface; a publisher never reads.
func (c *capture) ReadFrame() (*ethernet.Frame, error) { return nil, nil }

func (c *capture) messages() []Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Message(nil), c.msgs...)
}

func testPublisher(t *testing.T, cfg PublisherConfig) (*Publisher, *capture) {
	t.Helper()
	if cfg.GoCbRef == "" {
		cfg.GoCbRef = "LD/LLN0.gcb01"
	}
	if cfg.Retrans == nil {
		cfg.Retrans = []time.Duration{time.Hour} // one send, no retransmission
	}
	cap := &capture{}
	p, err := NewPublisher(cap, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, cap
}

// A state change increments stNum; a refresh does not. IEC 61850-8-1 keeps
// the two apart so a receiver can tell a new value from a re-advertisement
// of the same one, and a publisher that conflated them would make every
// receiver's state-change counters meaningless.
func TestPublishVersusRefresh(t *testing.T) {
	p, cap := testPublisher(t, PublisherConfig{})
	values := []*mms.Value{mms.NewBool(true)}

	if err := p.Publish(values); err != nil {
		t.Fatal(err)
	}
	if err := p.Refresh(values); err != nil {
		t.Fatal(err)
	}
	if err := p.Publish(values); err != nil {
		t.Fatal(err)
	}
	msgs := cap.messages()
	if len(msgs) != 3 {
		t.Fatalf("%d messages sent, want 3", len(msgs))
	}
	if msgs[0].StNum == 0 {
		t.Error("the first state change has stNum 0; 0 is reserved")
	}
	if msgs[0].StNum != msgs[1].StNum {
		t.Errorf("Refresh changed stNum: %d then %d", msgs[0].StNum, msgs[1].StNum)
	}
	if msgs[1].StNum == msgs[2].StNum {
		t.Error("Publish after a Refresh did not change stNum")
	}
	// A refresh repeats the state as it was, keeping the time of the
	// change it repeats so a receiver can judge its age.
	if !msgs[1].T.Equal(msgs[0].T) {
		t.Errorf("Refresh moved the timestamp: %v then %v", msgs[0].T, msgs[1].T)
	}
	if msgs[2].T.Before(msgs[1].T) {
		t.Error("a state change moved the timestamp backwards")
	}
}

// stNum starts at 1 and skips 0 on wrap, since 0 means "no state change
// yet" to a receiver.
func TestStNumNeverZero(t *testing.T) {
	p, _ := testPublisher(t, PublisherConfig{})
	// Drive the counter to the top directly: reaching the wrap through
	// the public API would take four billion state changes.
	p.mu.Lock()
	p.stNum = ^uint32(0) // one short of the wrap
	p.mu.Unlock()
	if err := p.Publish(nil); err != nil {
		t.Fatal(err)
	}
	stNum, _ := p.State()
	if stNum != 1 {
		t.Errorf("stNum = %d after the wrap, want 1", stNum)
	}
}

// A refresh before any publish has nothing to repeat, so it behaves as one
// rather than advertising stNum 0.
func TestRefreshBeforePublish(t *testing.T) {
	p, cap := testPublisher(t, PublisherConfig{})
	if err := p.Refresh(nil); err != nil {
		t.Fatal(err)
	}
	msgs := cap.messages()
	if len(msgs) != 1 {
		t.Fatalf("%d messages, want 1", len(msgs))
	}
	if msgs[0].StNum != 1 {
		t.Errorf("stNum = %d, want 1", msgs[0].StNum)
	}
}

// The test and needs-commissioning flags are part of the message and tell a
// receiver that the publisher is in test or commissioning state; a
// publisher that cannot set them cannot report either.
func TestTestAndNdsComAreTransmitted(t *testing.T) {
	for _, tc := range []struct {
		test, ndsCom bool
	}{
		{false, false}, {true, false}, {false, true}, {true, true},
	} {
		p, cap := testPublisher(t, PublisherConfig{Test: tc.test, NdsCom: tc.ndsCom})
		if err := p.Publish(nil); err != nil {
			t.Fatal(err)
		}
		msgs := cap.messages()
		if len(msgs) != 1 {
			t.Fatalf("%d messages, want 1", len(msgs))
		}
		if msgs[0].Test != tc.test || msgs[0].NdsCom != tc.ndsCom {
			t.Errorf("Test/NdsCom = %v/%v, want %v/%v",
				msgs[0].Test, msgs[0].NdsCom, tc.test, tc.ndsCom)
		}
	}
}

// The time quality says whether the clock was synchronised and how accurate
// it is. It used to be fixed at accuracy 10 with leap seconds known, so a
// publisher could not report a clock that had lost synchronisation.
func TestTimeQualityIsTransmitted(t *testing.T) {
	tq := mms.TimeClockFailure | mms.TimeClockNotSynchronized | mms.TimeAccuracy(3)
	p, cap := testPublisher(t, PublisherConfig{TimeQuality: &tq})
	if err := p.Publish(nil); err != nil {
		t.Fatal(err)
	}
	msgs := cap.messages()
	if got := msgs[0].TimeQuality; got == nil || *got != tq {
		t.Errorf("TimeQuality = %v, want %08b", got, uint8(tq))
	}
	// The default is unchanged when nothing is configured.
	p2, cap2 := testPublisher(t, PublisherConfig{})
	if err := p2.Publish(nil); err != nil {
		t.Fatal(err)
	}
	if got := cap2.messages()[0].TimeQuality; got == nil || *got != mms.TimeAccuracy(10) {
		t.Errorf("default TimeQuality = %v, want accuracy 10", got)
	}
	// A quality of 0 is a real quality, not "use the default", and a
	// parsed message re-marshals with the quality it arrived with.
	var zero mms.TimeQuality
	p3, cap3 := testPublisher(t, PublisherConfig{TimeQuality: &zero})
	if err := p3.Publish(nil); err != nil {
		t.Fatal(err)
	}
	got := cap3.messages()[0]
	if got.TimeQuality == nil || *got.TimeQuality != 0 {
		t.Fatalf("TimeQuality = %v, want 0", got.TimeQuality)
	}
	again, err := Parse(got.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if *again.TimeQuality != 0 {
		t.Errorf("re-marshalled TimeQuality = %08b, want 0", uint8(*again.TimeQuality))
	}
}

// The retransmission schedule comes from the control block's MinTime and
// MaxTime, which is how a 100 ms GOOSE is configured.
func TestRetransFromSCL(t *testing.T) {
	// 100 ms GOOSE: heard within 100 ms of a change, and no slower.
	got := RetransFromSCL(20, 100)
	if len(got) == 0 {
		t.Fatal("no schedule")
	}
	if got[0] != 20*time.Millisecond {
		t.Errorf("first interval = %v, want the MinTime of 20ms", got[0])
	}
	if last := got[len(got)-1]; last != 100*time.Millisecond {
		t.Errorf("steady interval = %v, want the MaxTime of 100ms", last)
	}
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Errorf("interval %d (%v) does not exceed the previous (%v)", i, got[i], got[i-1])
		}
	}
	// A block configuring neither gets the library default.
	if d := RetransFromSCL(0, 0); len(d) != len(DefaultRetrans) {
		t.Errorf("default schedule has %d entries, want %d", len(d), len(DefaultRetrans))
	}
	// A MaxTime below MinTime is raised rather than producing a schedule
	// that goes backwards.
	if d := RetransFromSCL(500, 100); d[len(d)-1] != 500*time.Millisecond {
		t.Errorf("steady interval = %v, want 500ms", d[len(d)-1])
	}
	// A wide range does not produce an unbounded schedule.
	if d := RetransFromSCL(1, 1<<30); len(d) > maxRetransSteps+1 {
		t.Errorf("schedule has %d entries, want at most %d", len(d), maxRetransSteps+1)
	}
}

// A publisher built from a model takes the addressing, identity and timing
// the configuration states.
func TestNewPublisherFromModel(t *testing.T) {
	gc := &model.GSEControl{
		Name: "gcb01", GoID: "LD/LLN0.gcb01", DataSet: "Measurements", ConfRev: 3,
		DstMAC: [6]byte{1, 0x0c, 0xcd, 3, 0, 1}, AppID: 0x2000,
		VLANID: 0x123, VLANPri: 4, MinTime: 20, MaxTime: 100,
	}
	ld := &model.LogicalDevice{Name: "IEDLD0", Inst: "LD0"}
	ln := &model.LogicalNode{Name: "LLN0", Class: "LLN0"}
	cap := &capture{}
	p, err := NewPublisherFromModel(cap, ld, ln, gc, [6]byte{2, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.cfg.Retrans[0] != 20*time.Millisecond {
		t.Errorf("first interval = %v, want 20ms", p.cfg.Retrans[0])
	}
	if p.cfg.VLAN == nil || p.cfg.VLAN.VID != 0x123 || p.cfg.VLAN.Priority != 4 {
		t.Errorf("VLAN = %+v, want VID 0x123 priority 4", p.cfg.VLAN)
	}
	if err := p.Publish(nil); err != nil {
		t.Fatal(err)
	}
	frames := cap.net
	if len(frames) != 1 {
		t.Fatalf("%d frames, want 1", len(frames))
	}
	if frames[0].Dst != gc.DstMAC || frames[0].EtherType != ethernet.EtherTypeGOOSE {
		t.Errorf("frame = %+v, want the configured destination and GOOSE type", frames[0])
	}
	if frames[0].VLAN == nil || frames[0].VLAN.VID != 0x123 {
		t.Error("the frame carries no VLAN")
	}
	msgs := cap.messages()
	if len(msgs) != 1 || msgs[0].GoID != gc.GoID || msgs[0].ConfRev != 3 {
		t.Errorf("message = %+v, want the configured identity and revision", msgs[0])
	}
	// gocbRef and datSet are full references, which is what a subscriber
	// configured from the same SCL filters on.
	if msgs[0].GoCbRef != "IEDLD0/LLN0$GO$gcb01" {
		t.Errorf("gocbRef = %q, want IEDLD0/LLN0$GO$gcb01", msgs[0].GoCbRef)
	}
	if msgs[0].DatSet != "IEDLD0/LLN0$Measurements" {
		t.Errorf("datSet = %q, want IEDLD0/LLN0$Measurements", msgs[0].DatSet)
	}
	if !(Filter{GoCbRef: "IEDLD0/LLN0$GO$gcb01"}).match(&msgs[0]) {
		t.Error("a subscriber filtering on the block's reference rejects the stream")
	}
	if _, err := NewPublisherFromModel(cap, ld, ln, nil, [6]byte{}); err == nil {
		t.Error("a nil control block should be an error")
	}
	if _, err := NewPublisherFromModel(cap, nil, ln, gc, [6]byte{}); err == nil {
		t.Error("a missing logical device should be an error")
	}
}

// sqNum rolls over to 1, not 0: 0 marks the first transmission of a
// state, so a wrapped 0 would read as a state change that did not happen.
func TestSqNumRollsOverToOne(t *testing.T) {
	p, cap := testPublisher(t, PublisherConfig{Retrans: []time.Duration{time.Millisecond}})
	stop := make(chan struct{})
	p.wg.Add(1)
	go p.retransmit(Message{GoCbRef: p.cfg.GoCbRef, StNum: 1, SqNum: math.MaxUint32 - 1}, stop)
	deadline := time.Now().Add(5 * time.Second)
	for len(cap.messages()) < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(stop)
	p.wg.Wait()
	msgs := cap.messages()
	if len(msgs) < 2 {
		t.Fatalf("%d retransmissions, want at least 2", len(msgs))
	}
	if msgs[0].SqNum != math.MaxUint32 || msgs[1].SqNum != 1 {
		t.Errorf("sqNum went %d then %d, want %d then 1", msgs[0].SqNum, msgs[1].SqNum, uint32(math.MaxUint32))
	}
}
