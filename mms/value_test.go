package mms

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

func roundTrip(t *testing.T, v *Value) *Value {
	t.Helper()
	enc := AppendData(nil, v)
	dec, err := DecodeData(asn1.NewDecoder(enc))
	if err != nil {
		t.Fatalf("decode %s: %v (bytes %x)", v, err, enc)
	}
	if !dec.Equal(v) {
		t.Fatalf("round trip: got %s, want %s (bytes %x)", dec, v, enc)
	}
	return dec
}

func TestValueRoundTrip(t *testing.T) {
	bs := NewBitString(13)
	bs.SetBit(0, true)
	bs.SetBit(3, true)

	utc := NewUTCTime(time.Date(2026, 7, 17, 12, 0, 0, 500_000_000, time.UTC), TimeAccuracy(10))

	values := []*Value{
		NewBool(true), NewBool(false),
		NewInt32(-42), NewInt64(1 << 40), NewInt8(0),
		NewUint32(3_000_000_000), NewUint8(255),
		NewFloat32(230.5), NewFloat64(-1e300),
		bs,
		NewOctetString([]byte{1, 2, 3}),
		NewVisibleString("IED1LD0/LLN0$ST$Beh"),
		NewMMSString("héllo"),
		utc,
		NewBinaryTime(time.Date(2026, 7, 17, 6, 30, 0, 0, time.UTC)),
		NewStructure(NewFloat32(1.5), NewStructure(NewBool(true)), NewInt32(9)),
		NewArray(NewInt32(1), NewInt32(2), NewInt32(3)),
	}
	for _, v := range values {
		roundTrip(t, v)
	}
}

func TestValueKnownEncodings(t *testing.T) {
	cases := []struct {
		v   *Value
		hex string
	}{
		{NewBool(true), "8301ff"},
		{NewInt32(5), "850105"},
		{NewInt32(-1), "8501ff"},
		{NewUint8(200), "860200c8"},
		{NewFloat32(0), "87050800000000"},
		{NewVisibleString("ab"), "8a026162"},
		{NewStructure(NewBool(false)), "a203830100"},
	}
	for _, c := range cases {
		got := AppendData(nil, c.v)
		want, _ := hex.DecodeString(c.hex)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: got %x, want %x", c.v, got, want)
		}
	}
}

func TestUTCTimeSemantics(t *testing.T) {
	when := time.Date(2026, 7, 17, 12, 0, 0, 250_000_000, time.UTC)
	v := NewUTCTime(when, TimeClockNotSynchronized)
	got := v.Time()
	if d := got.Sub(when); d > time.Microsecond || d < -time.Microsecond {
		t.Fatalf("time drift %v", d)
	}
	if v.TimeQualityFlags()&TimeClockNotSynchronized == 0 {
		t.Fatal("quality flag lost")
	}
}

func TestAccessResult(t *testing.T) {
	// failure [0] IMPLICIT DataAccessError(10)
	enc := asn1.UintElem(asn1.ContextPrimitive(0), 10).Encode()
	v, err := DecodeAccessResult(asn1.NewDecoder(enc))
	if err != nil {
		t.Fatal(err)
	}
	code, isErr := v.AccessError()
	if !isErr || code != AccessObjectNonExistent {
		t.Fatalf("got %v %v", code, isErr)
	}

	enc = AppendData(nil, NewInt32(7))
	v, err = DecodeAccessResult(asn1.NewDecoder(enc))
	if err != nil || v.Int32() != 7 {
		t.Fatalf("success case: %v %v", v, err)
	}
}

func TestTypeSpecRoundTrip(t *testing.T) {
	ts := &TypeSpec{Kind: TypeStructure, Components: []Component{
		{Name: "mag", Spec: &TypeSpec{Kind: TypeStructure, Components: []Component{
			{Name: "f", Spec: &TypeSpec{Kind: TypeFloat32}},
		}}},
		{Name: "q", Spec: &TypeSpec{Kind: TypeBitString, Size: -13}},
		{Name: "t", Spec: &TypeSpec{Kind: TypeUTCTime}},
		{Name: "arr", Spec: &TypeSpec{Kind: TypeArray, Elements: 3,
			Element: &TypeSpec{Kind: TypeInteger, Size: 32}}},
	}}
	enc := ts.BER().Encode()
	dec, err := DecodeTypeSpec(asn1.NewDecoder(enc))
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Components) != 4 || dec.Components[0].Name != "mag" ||
		dec.Components[0].Spec.Components[0].Spec.Kind != TypeFloat32 ||
		dec.Components[1].Spec.Size != -13 ||
		dec.Components[3].Spec.Elements != 3 ||
		dec.Components[3].Spec.Element.Size != 32 {
		t.Fatalf("decoded %+v", dec)
	}

	// Default value materialisation matches the shape.
	v := dec.DefaultValue()
	if v.Type() != TypeStructure || v.Len() != 4 || v.Index(3).Len() != 3 {
		t.Fatalf("default value %s", v)
	}
	if v.Index(1).BitLen() != 13 {
		t.Fatalf("bitstring default length %d", v.Index(1).BitLen())
	}
}

func TestValueClone(t *testing.T) {
	orig := NewStructure(NewBitString(4), NewVisibleString("x"))
	c := orig.Clone()
	c.Index(0).SetBit(0, true)
	if orig.Index(0).Bit(0) {
		t.Fatal("clone shares bit string storage")
	}
	if !orig.Equal(orig.Clone()) {
		t.Fatal("clone not equal")
	}
}

func FuzzDecodeData(f *testing.F) {
	f.Add(AppendData(nil, NewStructure(NewInt32(5), NewBool(true))))
	f.Add(AppendData(nil, NewUTCTimeNow()))
	f.Fuzz(func(t *testing.T, data []byte) {
		d := asn1.NewDecoder(data)
		v, err := DecodeData(d)
		if err != nil {
			return
		}
		// Whatever decodes must re-encode without panicking.
		AppendData(nil, v)
		_ = v.String()
	})
}

func FuzzDecodeTypeSpec(f *testing.F) {
	f.Add((&TypeSpec{Kind: TypeStructure, Components: []Component{
		{Name: "f", Spec: &TypeSpec{Kind: TypeFloat32}},
	}}).BER().Encode())
	f.Fuzz(func(t *testing.T, data []byte) {
		ts, err := DecodeTypeSpec(asn1.NewDecoder(data))
		if err != nil {
			return
		}
		if el := ts.BER(); el != nil {
			el.Encode()
		}
		ts.DefaultValue()
	})
}
