package asn1

import (
	"bytes"
	"testing"
)

// A five-octet tag number or OID arc carries 35 bits: one past 32 must be
// refused, not wrap into a valid-looking value.
func TestNoWrapAround(t *testing.T) {
	// 0x1f: high tag number; 0x90 0x80 0x80 0x80 0x00 is 1<<32.
	if _, _, err := NewDecoder([]byte{0x9f, 0x90, 0x80, 0x80, 0x80, 0x00, 0x00}).ReadTLV(); err == nil {
		t.Error("tag number 1<<32 accepted")
	}
	// The largest 32-bit tag number still decodes.
	tag, _, err := NewDecoder([]byte{0x9f, 0x8f, 0xff, 0xff, 0xff, 0x7f, 0x00}).ReadTLV()
	if err != nil || tag.Number != 0xffffffff {
		t.Errorf("tag 0xffffffff: %v, %v", tag, err)
	}
	if _, err := DecodeOID([]byte{0x2a, 0x90, 0x80, 0x80, 0x80, 0x00}); err == nil {
		t.Error("OID arc 1<<32 accepted")
	}
	if o, err := DecodeOID([]byte{0x2a, 0x8f, 0xff, 0xff, 0xff, 0x7f}); err != nil || o[2] != 0xffffffff {
		t.Errorf("OID arc 0xffffffff: %v, %v", o, err)
	}
}

func TestAppendLengthRefusesNegative(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a negative length encoded")
		}
	}()
	AppendLength(nil, -1)
}

// Length decides a bit string's octets, whatever Bits holds.
func TestAppendBitStringFollowsLength(t *testing.T) {
	for _, c := range []struct {
		bs   BitString
		want []byte
	}{
		{BitString{Bits: []byte{0xff}, Length: 8}, []byte{0, 0xff}},
		{BitString{Bits: []byte{0xc0}, Length: 2}, []byte{6, 0xc0}},
		{BitString{Bits: []byte{0xff}, Length: 12}, []byte{4, 0xff, 0x00}}, // Bits too short
		{BitString{Bits: []byte{0xff, 0xff}, Length: 3}, []byte{5, 0xff}},  // Bits too long
		{BitString{Length: 0}, []byte{0}},
	} {
		if got := AppendBitString(nil, c.bs); !bytes.Equal(got, c.want) {
			t.Errorf("%+v: % x, want % x", c.bs, got, c.want)
		}
	}
}

// The exponent-width octet must match the format (IEC 61850-8-1).
func TestDecodeFloatChecksExponentWidth(t *testing.T) {
	if _, err := DecodeFloat(AppendFloat32(nil, 1.5)); err != nil {
		t.Errorf("float32: %v", err)
	}
	if _, err := DecodeFloat(AppendFloat64(nil, 1.5)); err != nil {
		t.Errorf("float64: %v", err)
	}
	if _, err := DecodeFloat([]byte{11, 0x3f, 0xc0, 0, 0}); err == nil {
		t.Error("float32 with exponent width 11 accepted")
	}
	if _, err := DecodeFloat([]byte{8, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Error("float64 with exponent width 8 accepted")
	}
}
