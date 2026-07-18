package asn1

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"testing"
)

func TestTagRoundTrip(t *testing.T) {
	tags := []Tag{
		TagBoolean, TagInteger, TagSequence,
		ContextPrimitive(0), ContextConstructed(12), ContextPrimitive(30),
		ContextPrimitive(31), ContextPrimitive(127), ContextPrimitive(128),
		ContextConstructed(16383), ApplicationConstructed(1),
		{ClassPrivate, false, 99999},
	}
	for _, tag := range tags {
		enc := AppendTag(nil, tag)
		if len(enc) != TagSize(tag) {
			t.Errorf("%v: TagSize=%d, encoded %d", tag, TagSize(tag), len(enc))
		}
		enc = AppendLength(enc, 0)
		d := NewDecoder(enc)
		got, _, err := d.ReadTLV()
		if err != nil {
			t.Fatalf("%v: %v", tag, err)
		}
		if got != tag {
			t.Errorf("round trip: got %v, want %v", got, tag)
		}
	}
}

func TestLengthRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffff, 0x1000000} {
		enc := AppendLength(nil, n)
		if len(enc) != LengthSize(n) {
			t.Errorf("n=%d: LengthSize=%d, encoded %d", n, LengthSize(n), len(enc))
		}
		d := NewDecoder(enc)
		got, indef, err := d.readLength()
		if err != nil || indef || got != n {
			t.Errorf("n=%d: got %d indef=%v err=%v", n, got, indef, err)
		}
	}
}

func TestElementEncode(t *testing.T) {
	// SEQUENCE { [0] INTEGER 5, [1] BOOLEAN TRUE }
	el := Cons(TagSequence,
		IntElem(ContextPrimitive(0), 5),
		BoolElem(ContextPrimitive(1), true),
	)
	want, _ := hex.DecodeString("30068001058101ff")
	got := el.Encode()
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
	if el.Size() != len(want) {
		t.Fatalf("Size=%d, want %d", el.Size(), len(want))
	}

	// Nil children skipped.
	el2 := Cons(TagSequence, nil, IntElem(ContextPrimitive(0), 5), nil)
	if len(el2.Children) != 1 {
		t.Fatalf("nil children not skipped")
	}
}

func TestIntRoundTrip(t *testing.T) {
	for _, v := range []int64{0, 1, -1, 127, 128, -128, -129, 255, 256,
		math.MaxInt32, math.MinInt32, math.MaxInt64, math.MinInt64} {
		enc := AppendInt(nil, v)
		if len(enc) != IntSize(v) {
			t.Errorf("v=%d: IntSize=%d, len=%d", v, IntSize(v), len(enc))
		}
		got, err := DecodeInt(enc)
		if err != nil || got != v {
			t.Errorf("v=%d: got %d, err=%v", v, got, err)
		}
	}
	// Known encodings.
	if !bytes.Equal(AppendInt(nil, 128), []byte{0x00, 0x80}) {
		t.Error("128 must encode with leading zero")
	}
	if !bytes.Equal(AppendInt(nil, -129), []byte{0xff, 0x7f}) {
		t.Error("-129 encoding wrong")
	}
}

func TestUintRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 127, 128, 255, 256, math.MaxUint32, math.MaxUint64} {
		enc := AppendUint(nil, v)
		got, err := DecodeUint(enc)
		if err != nil || got != v {
			t.Errorf("v=%d: got %d, err=%v", v, got, err)
		}
	}
}

func TestBitString(t *testing.T) {
	bs := NewBitString(13)
	bs.SetBit(0, true)
	bs.SetBit(12, true)
	enc := AppendBitString(nil, bs)
	if enc[0] != 3 { // 16-13 padding bits
		t.Fatalf("padding = %d, want 3", enc[0])
	}
	dec, err := DecodeBitString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Length != 13 || !dec.Bit(0) || !dec.Bit(12) || dec.Bit(1) {
		t.Fatalf("bit string round trip failed: %+v", dec)
	}
	if dec.Bit(13) || dec.Bit(-1) {
		t.Fatal("out-of-range Bit must be false")
	}
}

func TestFloat(t *testing.T) {
	for _, v := range []float32{0, 1.5, -3.25, math.MaxFloat32} {
		got, err := DecodeFloat(AppendFloat32(nil, v))
		if err != nil || got != float64(v) {
			t.Errorf("f32 %v: got %v err=%v", v, got, err)
		}
	}
	for _, v := range []float64{0, 1.5, -3.25, math.MaxFloat64, math.SmallestNonzeroFloat64} {
		got, err := DecodeFloat(AppendFloat64(nil, v))
		if err != nil || got != v {
			t.Errorf("f64 %v: got %v err=%v", v, got, err)
		}
	}
}

func TestOIDRoundTrip(t *testing.T) {
	cases := []struct {
		oid OID
		hex string
	}{
		{OID{1, 0, 9506, 2, 3}, "28ca220203"}, // MMS abstract syntax
		{OID{2, 2, 1, 0, 1}, "52010001"},      // ACSE ASO context style
		{OID{1, 0, 9506, 2, 1}, "28ca220201"}, // MMS application context
		{OID{2, 1, 1}, "5101"},                // ACSE abstract syntax "joint-iso-itu-t association-control(2) abstract-syntax(1)"... first arcs only
	}
	for _, c := range cases {
		enc := AppendOID(nil, c.oid)
		want, _ := hex.DecodeString(c.hex)
		if !bytes.Equal(enc, want) {
			t.Errorf("%v: got %x, want %x", c.oid, enc, want)
		}
		dec, err := DecodeOID(enc)
		if err != nil || !dec.Equal(c.oid) {
			t.Errorf("%v: decoded %v, err=%v", c.oid, dec, err)
		}
	}
}

func TestDecoderIndefinite(t *testing.T) {
	// SEQUENCE (indefinite) { INTEGER 5 } EOC
	data, _ := hex.DecodeString("30800201050000")
	d := NewDecoder(data)
	tag, content, err := d.ReadTLV()
	if err != nil {
		t.Fatal(err)
	}
	if tag != TagSequence || !bytes.Equal(content, []byte{0x02, 0x01, 0x05}) {
		t.Fatalf("tag=%v content=%x", tag, content)
	}
	if d.More() {
		t.Fatal("trailing data")
	}
}

func TestDecoderErrors(t *testing.T) {
	cases := []string{
		"",         // empty is fine for More() but Expect fails
		"30",       // tag without length
		"3005",     // truncated content
		"02890000", // length octets count 9 > 4
		"0280",     // indefinite on primitive
		"3080",     // unterminated indefinite
	}
	for _, c := range cases {
		data, _ := hex.DecodeString(c)
		d := NewDecoder(data)
		if _, _, err := d.ReadTLV(); err == nil {
			t.Errorf("%s: expected error", c)
		}
	}

	d := NewDecoder([]byte{0x02, 0x01, 0x05})
	if _, err := d.Expect(TagBoolean); !errors.Is(err, ErrUnexpected) {
		t.Fatalf("Expect wrong tag: %v", err)
	}
}

func TestOptional(t *testing.T) {
	data := Cons(TagSequence, IntElem(ContextPrimitive(1), 7)).Encode()
	d := NewDecoder(data)
	inner, err := d.Expect(TagSequence)
	if err != nil {
		t.Fatal(err)
	}
	dd := NewDecoder(inner)
	if _, ok, _ := dd.Optional(ContextPrimitive(0)); ok {
		t.Fatal("Optional matched wrong tag")
	}
	content, ok, err := dd.Optional(ContextPrimitive(1))
	if err != nil || !ok || len(content) != 1 || content[0] != 7 {
		t.Fatalf("Optional: content=%x ok=%v err=%v", content, ok, err)
	}
	if _, ok, _ := dd.Optional(ContextPrimitive(2)); ok {
		t.Fatal("Optional matched past end")
	}
}
