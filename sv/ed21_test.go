package sv

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// The quality word orientation is pinned by the masks Wireshark's SV
// dissector decodes and libiec61850 writes under IEC 61850-9-2:2011:
// invalid = 0x0002, questionable = 0x0003, test = 0x0800, derived =
// 0x2000. Reading the 13 quality bits from the other end of the word
// produces plausible nonsense rather than an error, so these are the
// regression tests for it.
func TestLEQualityWordOrientation(t *testing.T) {
	invalid := model.QualityGood.WithValidity(model.ValidityInvalid)
	for _, tc := range []struct {
		name string
		word uint32
		want model.Quality
	}{
		{"validity invalid", 0x0002, invalid},
		{"validity invalid, first 9-2LE guideline", 0x0001, invalid},
		{"validity questionable", 0x0003, model.QualityGood.WithValidity(model.ValidityQuestionable)},
		{"overflow", 0x0004, model.QualityOverflow},
		{"substituted", 0x0400, model.QualitySubstituted},
		{"test", 0x0800, model.QualityTest},
		{"operator blocked", 0x1000, model.QualityOperatorBlocked},
		{"derived is outside the 13 bits", 0x2000, 0},
		{"all clear", 0x0000, 0},
	} {
		s := &LESample{}
		s.Q[0] = tc.word
		if got := s.Quality(0); got != tc.want {
			t.Errorf("%s: word %04x gave quality %013b, want %013b",
				tc.name, tc.word, uint16(got), uint16(tc.want))
		}
	}

	// And the writer puts invalid where 9-2:2011 has it.
	s := &LESample{}
	s.SetQuality(0, invalid|model.QualityTest)
	if s.Q[0] != 0x0802 {
		t.Errorf("SetQuality(invalid|test) wrote %04x, want 0802", s.Q[0])
	}
}

// The quality round-trips through the encoder, and the reserved bits of the
// word survive a write to the quality.
func TestLESampleQualityRoundTrip(t *testing.T) {
	s := &LESample{}
	s.I[0] = 1234
	s.SetQuality(0, model.Quality(1<<11|1<<2))
	s.Q[0] |= 0x2000 // the derived bit, outside the 13
	b := EncodeLESample(s)
	got, err := DecodeLESample(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Q[0]&0x2000 == 0 {
		t.Error("the derived bit was lost")
	}
	want := model.Quality(1<<11 | 1<<2)
	if got.Quality(0) != want {
		t.Errorf("quality = %013b, want %013b", uint16(got.Quality(0)), uint16(want))
	}
	if got.I[0] != 1234 {
		t.Errorf("value = %d, want 1234", got.I[0])
	}
}

// smpMod [8] is the Edition 2 field that says how to read smpRate. It is
// optional, so an Edition 1 stream without it must still parse, and one
// with it must round-trip, including mode 0, which is a mode and not
// absence.
func TestSmpModRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mod     SmpMod
		present bool
		want    string
	}{
		{"absent", SmpPerPeriod, false, "SmpPerPeriod"},
		{"per period", SmpPerPeriod, true, "SmpPerPeriod"},
		{"per second", SmpPerSec, true, "SmpPerSec"},
		{"seconds per sample", SecPerSmp, true, "SecPerSmp"},
	} {
		a := &ASDU{
			SvID: "MU1", ConfRev: 1, SmpCnt: 7, SmpSynch: SmpSynchGlobal,
			SmpRate: 4000, SmpMod: tc.mod, HasSmpMod: tc.present, Sample: make([]byte, 4),
		}
		pdu := &PDU{AppID: 0x4000, ASDUs: []*ASDU{a}}
		got, err := Parse(pdu.Marshal())
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(got.ASDUs) != 1 {
			t.Fatalf("%s: %d ASDUs", tc.name, len(got.ASDUs))
		}
		asdu := got.ASDUs[0]
		if asdu.HasSmpMod != tc.present {
			t.Errorf("%s: HasSmpMod = %v, want %v", tc.name, asdu.HasSmpMod, tc.present)
		}
		if asdu.SmpMod != tc.mod {
			t.Errorf("%s: SmpMod = %v, want %v", tc.name, asdu.SmpMod, tc.mod)
		}
		if asdu.SmpMod.String() != tc.want {
			t.Errorf("%s: String() = %q, want %q", tc.name, asdu.SmpMod.String(), tc.want)
		}
		// The fields before it must be unaffected.
		if asdu.SmpRate != 4000 || asdu.SmpCnt != 7 || asdu.SvID != "MU1" {
			t.Errorf("%s: fields before smpMod disturbed: %+v", tc.name, asdu)
		}
	}
}

// The wire values are the standard's: samplesPerNominalPeriod (0),
// samplesPerSecond (1), secondsPerSample (2), as a two-octet field after
// the sample. A one-based numbering reads as the next mode up.
func TestSmpModWireValues(t *testing.T) {
	for _, tc := range []struct {
		mod  SmpMod
		wire []byte
	}{
		{SmpPerPeriod, []byte{0x88, 0x02, 0x00, 0x00}},
		{SmpPerSec, []byte{0x88, 0x02, 0x00, 0x01}},
		{SecPerSmp, []byte{0x88, 0x02, 0x00, 0x02}},
	} {
		sample := []byte{0xde, 0xad}
		a := &ASDU{SvID: "MU1", ConfRev: 1, Sample: sample, SmpMod: tc.mod, HasSmpMod: true}
		raw := (&PDU{AppID: 0x4000, ASDUs: []*ASDU{a}}).Marshal()
		// smpMod is the last field of the last ASDU, so the frame ends
		// with the sample and then smpMod.
		tail := append([]byte{0x87, 0x02, 0xde, 0xad}, tc.wire...)
		if !bytes.HasSuffix(raw, tail) {
			t.Errorf("%v: APDU ends % x, want % x", tc.mod, raw[len(raw)-len(tail):], tail)
		}
	}
}

// smpMod follows the sample on the wire, so a stream carrying it has to be
// longer than one without.
func TestSmpModIsLastField(t *testing.T) {
	base := &ASDU{SvID: "MU1", ConfRev: 1, Sample: make([]byte, 4)}
	short := len((&PDU{AppID: 0x4000, ASDUs: []*ASDU{base}}).Marshal())
	long := len((&PDU{AppID: 0x4000, ASDUs: []*ASDU{{
		SvID: "MU1", ConfRev: 1, Sample: make([]byte, 4), SmpMod: SmpPerSec, HasSmpMod: true,
	}}}).Marshal())
	if long <= short {
		t.Errorf("adding smpMod did not grow the APDU: %d then %d octets", short, long)
	}
}

// The publisher emits only the optional fields its configuration asks for,
// so a 9-2LE receiver is not handed a field it does not expect.
func TestPublisherOptionalFields(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     SVOpts
		wantRate bool
		wantTime bool
		wantDS   bool
		wantMod  bool
	}{
		{"9-2LE profile", SVOpts{}, false, false, false, false},
		{"full", SVOpts{SampleRate: true, RefreshTime: true, DataSet: true, SmpMod: true},
			true, true, true, true},
	} {
		p := &LEPublisher{rate: 4000, cfg: LEConfig{
			SvID: "MU1", ConfRev: 1, AppID: 0x4000,
			DatSet: "PhsMeas1", SmpMod: SmpPerSec, Opts: tc.opts,
		}}
		a := p.asdu(&LESample{SmpCnt: 1, SmpSynch: SmpSynchGlobal})
		if (a.SmpRate != 0) != tc.wantRate {
			t.Errorf("%s: SmpRate = %d, want rate=%v", tc.name, a.SmpRate, tc.wantRate)
		}
		if (!a.RefrTm.IsZero()) != tc.wantTime {
			t.Errorf("%s: RefrTm zero = %v, want time=%v", tc.name, a.RefrTm.IsZero(), tc.wantTime)
		}
		if (a.DatSet != "") != tc.wantDS {
			t.Errorf("%s: DatSet = %q, want dataset=%v", tc.name, a.DatSet, tc.wantDS)
		}
		if a.HasSmpMod != tc.wantMod {
			t.Errorf("%s: HasSmpMod = %v, want %v", tc.name, a.HasSmpMod, tc.wantMod)
		}
		if tc.wantMod && a.SmpMod != SmpPerSec {
			t.Errorf("%s: SmpMod = %v, want SmpPerSec", tc.name, a.SmpMod)
		}
		if tc.wantTime && time.Since(a.RefrTm) > time.Minute {
			t.Errorf("%s: RefrTm %v is not the current time", tc.name, a.RefrTm)
		}
	}
}

// refrTm carries the publisher's clock quality, and a parsed ASDU the
// quality it arrived with, 0 included.
func TestRefrTmQuality(t *testing.T) {
	lost := mms.TimeClockNotSynchronized | mms.TimeAccuracyUnspecified
	for _, q := range []*mms.TimeQuality{nil, &lost, new(mms.TimeQuality)} {
		p := &LEPublisher{rate: 4000, cfg: LEConfig{
			SvID: "MU1", ConfRev: 1, TimeQuality: q, Opts: SVOpts{RefreshTime: true},
		}}
		a := p.asdu(&LESample{SmpCnt: 1})
		got, err := Parse((&PDU{AppID: 0x4000, ASDUs: []*ASDU{a}}).Marshal())
		if err != nil {
			t.Fatal(err)
		}
		want := mms.DefaultTimeQuality
		if q != nil {
			want = *q
		}
		if tq := got.ASDUs[0].RefrTmQuality; tq == nil || *tq != want {
			t.Errorf("refrTm quality = %v, want %08b", tq, uint8(want))
		}
	}
}

// frameCapture records the frames a publisher writes.
type frameCapture struct {
	mu     sync.Mutex
	frames []ethernet.Frame
}

func (c *frameCapture) WriteFrame(f *ethernet.Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frames = append(c.frames, *f)
	return nil
}
func (c *frameCapture) ReadFrame() (*ethernet.Frame, error) { return nil, nil }
func (c *frameCapture) Close() error                        { return nil }

// smpRate is in the unit smpMod names. Without smpMod a receiver reads it
// as samples per period, so a publisher that sent samples per second there
// would claim 4000 samples in each 20 ms cycle.
func TestSmpRateFollowsSmpMod(t *testing.T) {
	for _, tc := range []struct {
		mod  SmpMod
		opts SVOpts
		want uint16
	}{
		{SmpPerPeriod, SVOpts{SampleRate: true}, 80},
		{SmpPerPeriod, SVOpts{SampleRate: true, SmpMod: true}, 80},
		{SmpPerSec, SVOpts{SampleRate: true, SmpMod: true}, 4000},
	} {
		p, err := NewLEPublisher(&frameCapture{}, LEConfig{
			SvID: "MU1", SamplesPerCycle: 80, NominalHz: 50, SmpMod: tc.mod, Opts: tc.opts,
		})
		if err != nil {
			t.Fatal(err)
		}
		if a := p.asdu(&LESample{}); a.SmpRate != tc.want {
			t.Errorf("%v: smpRate = %d, want %d", tc.mod, a.SmpRate, tc.want)
		}
	}
	if _, err := NewLEPublisher(&frameCapture{}, LEConfig{SvID: "MU1", SmpMod: SecPerSmp}); err == nil {
		t.Error("SecPerSmp at 4000 samples per second should be refused")
	}
}

// gmIdentity [9] (9-2 Amendment 1) round-trips as eight octets, follows
// SetGmIdentity, and a wrong length is an error rather than a truncation.
func TestGmIdentity(t *testing.T) {
	id := [8]byte{0x00, 0x1b, 0x19, 0xff, 0xfe, 0x01, 0x02, 0x03}
	p, err := NewLEPublisher(&frameCapture{}, LEConfig{
		SvID: "MU1", GmIdentity: id, Opts: SVOpts{SynchSourceID: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := p.asdu(&LESample{})
	got, err := Parse((&PDU{AppID: 0x4000, ASDUs: []*ASDU{a}}).Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if g := got.ASDUs[0]; !g.HasGmIdentity || g.GmIdentity != id {
		t.Errorf("gmIdentity = %x (present %v), want %x", g.GmIdentity, g.HasGmIdentity, id)
	}
	id2 := [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
	p.SetGmIdentity(id2)
	if a := p.asdu(&LESample{}); a.GmIdentity != id2 {
		t.Errorf("after SetGmIdentity: %x, want %x", a.GmIdentity, id2)
	}

	off, _ := NewLEPublisher(&frameCapture{}, LEConfig{SvID: "MU1", GmIdentity: id})
	if off.asdu(&LESample{}).HasGmIdentity {
		t.Error("gmIdentity sent without SynchSourceID")
	}

	a.HasGmIdentity = false
	el := a.element()
	el.Add(asn1.Prim(asn1.ContextPrimitive(9), []byte{1, 2, 3}))
	seq := asn1.Cons(asn1.ContextConstructed(2), el)
	sav := asn1.Cons(savPduTag, asn1.UintElem(asn1.ContextPrimitive(0), 1), seq)
	n := headerLen + sav.Size()
	if _, err := Parse(sav.Append([]byte{0x40, 0, byte(n >> 8), byte(n), 0, 0, 0, 0})); err == nil {
		t.Error("a 3-octet gmIdentity parsed")
	}
}

// With NoASDU above 1, a frame carries that many consecutive samples,
// oldest first.
func TestMultipleASDUsPerFrame(t *testing.T) {
	cap := &frameCapture{}
	p, err := NewLEPublisher(cap, LEConfig{SvID: "MU1", SamplesPerCycle: 256, NominalHz: 50, NoASDU: 8})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	p.Run(ctx, func(uint16, *LESample) {})
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.frames) == 0 {
		t.Fatal("no frames")
	}
	pdu, err := Parse(cap.frames[0].Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(pdu.ASDUs) != 8 {
		t.Fatalf("%d ASDUs, want 8", len(pdu.ASDUs))
	}
	for i, a := range pdu.ASDUs {
		if a.SmpCnt != uint16(i) {
			t.Errorf("ASDU %d has smpCnt %d", i, a.SmpCnt)
		}
	}
}

// The publisher built from a model follows its SmvOpts, rate, mode and
// addressing, and refuses what it cannot honour.
func TestNewLEPublisherFromModel(t *testing.T) {
	ld := &model.LogicalDevice{Name: "MU01LD0"}
	ln := &model.LogicalNode{Name: "LLN0"}
	sc := &model.SVControl{
		Name: "MSVCB01", SvID: "MU01", DataSet: "PhsMeas1", ConfRev: 2,
		SmpRate: 4800, SmpMod: model.SmpPerSec, NoASDU: 2, Multicast: true,
		Opts:   model.SVOpts{SampleRate: true, DataSet: true, SynchSourceID: true},
		DstMAC: [6]byte{1, 0x0c, 0xcd, 4, 0, 1}, AppID: 0x4001, VLANID: 5, VLANPri: 4,
	}
	p, err := NewLEPublisherFromModel(&frameCapture{}, ld, ln, sc, [6]byte{}, 60)
	if err != nil {
		t.Fatal(err)
	}
	if p.SampleRate() != 4800 || p.cfg.SamplesPerCycle != 80 || p.cfg.NoASDU != 2 {
		t.Errorf("rate %d, %d per cycle, %d ASDUs; want 4800, 80, 2",
			p.SampleRate(), p.cfg.SamplesPerCycle, p.cfg.NoASDU)
	}
	if p.cfg.VLAN == nil || p.cfg.VLAN.VID != 5 || p.cfg.AppID != 0x4001 || p.cfg.DstMAC != sc.DstMAC {
		t.Errorf("addressing = %+v", p.cfg)
	}
	a := p.asdu(&LESample{})
	if a.DatSet != "MU01LD0/LLN0$PhsMeas1" || a.SmpRate != 4800 ||
		!a.HasSmpMod || a.SmpMod != SmpPerSec || !a.HasGmIdentity || !a.RefrTm.IsZero() {
		t.Errorf("ASDU = %+v, want datSet, smpRate 4800 SmpPerSec and gmIdentity, no refrTm", a)
	}

	for name, mutate := range map[string]func(*model.SVControl){
		"unicast to a group": func(s *model.SVControl) { s.Multicast = false },
		"security":           func(s *model.SVControl) { s.Opts.Security = true },
		"SecPerSmp":          func(s *model.SVControl) { s.SmpMod = model.SecPerSmp },
		"fractional rate":    func(s *model.SVControl) { s.SmpRate = 4000 },
	} {
		bad := *sc
		mutate(&bad)
		if _, err := NewLEPublisherFromModel(&frameCapture{}, ld, ln, &bad, [6]byte{}, 60); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
