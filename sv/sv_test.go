package sv

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
)

func TestPDURoundTrip(t *testing.T) {
	pdu := &PDU{AppID: 0x4000, ASDUs: []*ASDU{
		{SvID: "MU01", SmpCnt: 42, ConfRev: 1, SmpSynch: SmpSynchGlobal, Sample: make([]byte, leSampleLen)},
		{SvID: "MU01", SmpCnt: 43, ConfRev: 1, SmpSynch: SmpSynchGlobal, Sample: make([]byte, leSampleLen)},
	}}
	apdu := pdu.Marshal()
	if apdu[8] != 0x60 {
		t.Fatalf("savPdu tag = %x, want 60", apdu[8])
	}
	got, err := Parse(apdu)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.AppID != 0x4000 || len(got.ASDUs) != 2 {
		t.Fatalf("got AppID=%x asdus=%d", got.AppID, len(got.ASDUs))
	}
	if got.ASDUs[1].SmpCnt != 43 || got.ASDUs[0].SvID != "MU01" {
		t.Fatalf("asdu fields: %+v", got.ASDUs)
	}
}

func TestLESampleRoundTrip(t *testing.T) {
	s := &LESample{SmpCnt: 10, SmpSynch: SmpSynchGlobal}
	s.I = [4]int32{1000, -2000, 3000, 0}
	s.V = [4]int32{230000, 229500, 230500, 1}
	s.Q[0] = 0
	s.Q[4] = 0x0800 // validity questionable-ish bit for test

	enc := EncodeLESample(s)
	if len(enc) != leSampleLen {
		t.Fatalf("encoded %d octets", len(enc))
	}
	dec, err := DecodeLESample(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.I != s.I || dec.V != s.V || dec.Q != s.Q {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", dec, s)
	}
}

func TestLEPublishSubscribeLoopback(t *testing.T) {
	pubIf, subIf := ethernet.Pipe()
	defer pubIf.Close()
	defer subIf.Close()

	got := make(chan LESample, 16)
	sub := NewSubscriber(subIf)
	stop, err := sub.SubscribeLE(Filter{AppID: 0x4000}, func(s *LESample) {
		got <- *s // copy out of the reused buffer
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	pub, err := NewLEPublisher(pubIf, LEConfig{
		AppID: 0x4000, SvID: "MU01", ConfRev: 1,
		SamplesPerCycle: 80, NominalHz: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pub.SampleRate() != 4000 {
		t.Fatalf("sample rate = %d, want 4000", pub.SampleRate())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pub.Run(ctx, func(smpCnt uint16, out *LESample) {
		out.I[0] = int32(smpCnt) * 10
		out.V[0] = 230000
	})

	// Collect a few samples and verify smpCnt sequencing and values.
	var first LESample
	select {
	case first = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("no samples received")
	}
	var second LESample
	select {
	case second = <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("only one sample received")
	}
	if second.SmpCnt != first.SmpCnt+1 {
		t.Fatalf("smpCnt not sequential: %d then %d", first.SmpCnt, second.SmpCnt)
	}
	if second.V[0] != 230000 || second.I[0] != int32(second.SmpCnt)*10 {
		t.Fatalf("sample values wrong: %+v", second)
	}
}

func FuzzParse(f *testing.F) {
	pdu := &PDU{AppID: 0x4000, ASDUs: []*ASDU{{SvID: "MU01", SmpCnt: 1, Sample: make([]byte, leSampleLen)}}}
	f.Add(pdu.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		if p, err := Parse(data); err == nil {
			p.Marshal()
		}
	})
}
