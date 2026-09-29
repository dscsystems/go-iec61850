package sv

import (
	"bytes"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// The 9-2LE quality word orientation is pinned by the masks the 9-2LE test
// procedures name: validity Invalid = 0x0001, test = 0x0800, derived =
// 0x2000. Reading the 13 quality bits from the other end of the word
// produces plausible nonsense rather than an error, so these are the
// regression tests for it.
func TestLEQualityWordOrientation(t *testing.T) {
	for _, tc := range []struct {
		name string
		word uint32
		want model.Quality
	}{
		{"validity invalid", 0x0001, qualityForValidity(model.ValidityInvalid)},
		{"overflow", 0x0004, model.Quality(1 << 2)},
		{"test", 0x0800, model.Quality(1 << 11)},
		{"operator blocked", 0x1000, model.Quality(1 << 12)},
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
}

// qualityForValidity builds the Quality word value whose Validity is v.
// Validity occupies positions 0 and 1 of the quality string, position 0
// being the most significant bit of the string and of Validity, so the two
// bits of v are reversed when they become two positions of the word:
// ValidityInvalid (10) is position 0 set, which is bit 0 of the word.
func qualityForValidity(v model.Validity) model.Quality {
	return model.Quality((v&1)<<1 | (v&2)>>1)
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
