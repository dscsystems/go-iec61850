package asn1

import (
	"fmt"
	"math"
)

// AppendInt appends the minimal two's-complement content octets for v
// (no tag or length).
func AppendInt(dst []byte, v int64) []byte {
	n := IntSize(v)
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, byte(v>>(uint(i)*8)))
	}
	return dst
}

// IntSize returns the minimal two's-complement octet count for v.
func IntSize(v int64) int {
	n := 1
	for v > 0x7f || v < -0x80 {
		v >>= 8
		n++
	}
	return n
}

// DecodeInt decodes two's-complement content octets.
func DecodeInt(content []byte) (int64, error) {
	if len(content) == 0 || len(content) > 8 {
		return 0, fmt.Errorf("integer of %d octets: %w", len(content), ErrBadValue)
	}
	v := int64(int8(content[0])) // sign-extend
	for _, b := range content[1:] {
		v = v<<8 | int64(b)
	}
	return v, nil
}

// AppendUint appends minimal unsigned content octets for v, adding a
// leading zero octet when the high bit would otherwise read as a sign.
func AppendUint(dst []byte, v uint64) []byte {
	n := UintSize(v)
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, byte(v>>(uint(i)*8)))
	}
	return dst
}

// UintSize returns the octet count AppendUint produces for v.
func UintSize(v uint64) int {
	n := 1
	for v > 0x7f {
		v >>= 8
		n++
	}
	return n
}

// DecodeUint decodes unsigned content octets (a leading zero octet is
// permitted, as produced for values with the top bit set).
func DecodeUint(content []byte) (uint64, error) {
	if len(content) == 0 {
		return 0, fmt.Errorf("empty unsigned: %w", ErrBadValue)
	}
	if len(content) > 9 || (len(content) == 9 && content[0] != 0) {
		return 0, fmt.Errorf("unsigned of %d octets: %w", len(content), ErrBadValue)
	}
	var v uint64
	for _, b := range content {
		v = v<<8 | uint64(b)
	}
	return v, nil
}

// IntElem returns an INTEGER-content primitive element with tag t.
func IntElem(t Tag, v int64) *Element { return Prim(t, AppendInt(nil, v)) }

// UintElem returns an unsigned-content primitive element with tag t.
func UintElem(t Tag, v uint64) *Element { return Prim(t, AppendUint(nil, v)) }

// BoolElem returns a BOOLEAN-content primitive element with tag t.
func BoolElem(t Tag, v bool) *Element {
	if v {
		return Prim(t, []byte{0xff})
	}
	return Prim(t, []byte{0x00})
}

// DecodeBool decodes BOOLEAN content octets.
func DecodeBool(content []byte) (bool, error) {
	if len(content) != 1 {
		return false, fmt.Errorf("boolean of %d octets: %w", len(content), ErrBadValue)
	}
	return content[0] != 0, nil
}

// BitString is a BER bit string: Bits holds the packed bits MSB-first,
// Length is the number of valid bits.
type BitString struct {
	Bits   []byte
	Length int
}

// NewBitString returns an all-zero bit string of n bits.
func NewBitString(n int) BitString {
	return BitString{Bits: make([]byte, (n+7)/8), Length: n}
}

// Bit returns bit i (0 = MSB of the first octet), false when out of range.
func (bs BitString) Bit(i int) bool {
	if i < 0 || i >= bs.Length {
		return false
	}
	return bs.Bits[i/8]&(0x80>>uint(i%8)) != 0
}

// SetBit sets bit i to v; out-of-range indices are ignored.
func (bs BitString) SetBit(i int, v bool) {
	if i < 0 || i >= bs.Length {
		return
	}
	if v {
		bs.Bits[i/8] |= 0x80 >> uint(i%8)
	} else {
		bs.Bits[i/8] &^= 0x80 >> uint(i%8)
	}
}

// AppendBitString appends bit string content octets (padding count prefix
// then packed bits).
func AppendBitString(dst []byte, bs BitString) []byte {
	pad := len(bs.Bits)*8 - bs.Length
	dst = append(dst, byte(pad))
	return append(dst, bs.Bits...)
}

// DecodeBitString decodes bit string content octets. The returned Bits
// slice aliases content.
func DecodeBitString(content []byte) (BitString, error) {
	if len(content) == 0 {
		return BitString{}, fmt.Errorf("empty bit string: %w", ErrBadValue)
	}
	pad := int(content[0])
	bits := content[1:]
	if pad > 7 || (len(bits) == 0 && pad != 0) {
		return BitString{}, fmt.Errorf("bit string padding %d: %w", pad, ErrBadValue)
	}
	return BitString{Bits: bits, Length: len(bits)*8 - pad}, nil
}

// BitStringElem returns a bit-string-content primitive element with tag t.
func BitStringElem(t Tag, bs BitString) *Element {
	return Prim(t, AppendBitString(nil, bs))
}

// AppendFloat32 appends MMS FloatingPoint content octets for a 32-bit
// IEEE 754 value: one exponent-width octet (8) then the big-endian value.
// MMS floats are not ASN.1 REALs; this format is shared by MMS, GOOSE
// and SV, so it lives here.
func AppendFloat32(dst []byte, v float32) []byte {
	b := math.Float32bits(v)
	return append(dst, 8, byte(b>>24), byte(b>>16), byte(b>>8), byte(b))
}

// AppendFloat64 appends MMS FloatingPoint content octets for a 64-bit
// IEEE 754 value (exponent width 11).
func AppendFloat64(dst []byte, v float64) []byte {
	b := math.Float64bits(v)
	return append(dst, 11, byte(b>>56), byte(b>>48), byte(b>>40), byte(b>>32),
		byte(b>>24), byte(b>>16), byte(b>>8), byte(b))
}

// DecodeFloat decodes MMS FloatingPoint content octets into a float64
// (exact for both widths).
func DecodeFloat(content []byte) (float64, error) {
	switch len(content) {
	case 5: // exponent width octet + float32
		v := uint32(content[1])<<24 | uint32(content[2])<<16 | uint32(content[3])<<8 | uint32(content[4])
		return float64(math.Float32frombits(v)), nil
	case 9:
		var v uint64
		for _, b := range content[1:] {
			v = v<<8 | uint64(b)
		}
		return math.Float64frombits(v), nil
	default:
		return 0, fmt.Errorf("floating point of %d octets: %w", len(content), ErrBadValue)
	}
}
