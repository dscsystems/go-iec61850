// Package mms implements the subset of MMS (ISO 9506) required by
// IEC 61850-8-1: the Data value model, PDU codecs and a client
// connection with the confirmed/unconfirmed service set used by ACSI.
package mms

import (
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Type identifies the concrete kind of a Value, mirroring the MMS Data
// CHOICE (plus DataAccessError, which surfaces per-element failures in
// read results).
type Type uint8

const (
	TypeNone Type = iota
	TypeArray
	TypeStructure
	TypeBoolean
	TypeBitString
	TypeInteger
	TypeUnsigned
	TypeFloat32
	TypeFloat64
	TypeOctetString
	TypeVisibleString
	TypeGeneralizedTime
	TypeBinaryTime
	TypeMMSString
	TypeUTCTime
	TypeDataAccessError
)

var typeNames = [...]string{
	TypeNone: "none", TypeArray: "array", TypeStructure: "structure",
	TypeBoolean: "boolean", TypeBitString: "bit-string", TypeInteger: "integer",
	TypeUnsigned: "unsigned", TypeFloat32: "float32", TypeFloat64: "float64",
	TypeOctetString: "octet-string", TypeVisibleString: "visible-string",
	TypeGeneralizedTime: "generalized-time", TypeBinaryTime: "binary-time",
	TypeMMSString: "mms-string", TypeUTCTime: "utc-time",
	TypeDataAccessError: "data-access-error",
}

func (t Type) String() string {
	if int(t) < len(typeNames) && typeNames[t] != "" {
		return typeNames[t]
	}
	return fmt.Sprintf("type(%d)", uint8(t))
}

// Value is an MMS data value: a tagged union over the MMS Data CHOICE.
// The zero Value has TypeNone and is not valid on the wire.
//
// Values are not synchronised; a Value must not be mutated while another
// goroutine reads it. Clone before sharing across goroutines that write.
type Value struct {
	typ      Type
	num      int64   // boolean (0/1), integer, unsigned, data-access-error code
	flt      float64 // float32/float64
	bytes    []byte  // bit-string bits, octet-string, strings, utc/binary time
	bitLen   int     // bit-string only
	children []*Value
}

// Constructors.

func NewBool(v bool) *Value {
	n := int64(0)
	if v {
		n = 1
	}
	return &Value{typ: TypeBoolean, num: n}
}

func NewInt8(v int8) *Value   { return &Value{typ: TypeInteger, num: int64(v)} }
func NewInt16(v int16) *Value { return &Value{typ: TypeInteger, num: int64(v)} }
func NewInt32(v int32) *Value { return &Value{typ: TypeInteger, num: int64(v)} }
func NewInt64(v int64) *Value { return &Value{typ: TypeInteger, num: v} }

func NewUint8(v uint8) *Value   { return &Value{typ: TypeUnsigned, num: int64(v)} }
func NewUint16(v uint16) *Value { return &Value{typ: TypeUnsigned, num: int64(v)} }
func NewUint32(v uint32) *Value { return &Value{typ: TypeUnsigned, num: int64(v)} }

func NewFloat32(v float32) *Value { return &Value{typ: TypeFloat32, flt: float64(v)} }
func NewFloat64(v float64) *Value { return &Value{typ: TypeFloat64, flt: v} }

// NewBitString returns a bit string of length bits, all zero.
func NewBitString(length int) *Value {
	return &Value{typ: TypeBitString, bytes: make([]byte, (length+7)/8), bitLen: length}
}

// NewBitStringBits returns a bit string over a copy of bits.
func NewBitStringBits(bits []byte, length int) *Value {
	b := make([]byte, len(bits))
	copy(b, bits)
	return &Value{typ: TypeBitString, bytes: b, bitLen: length}
}

func NewOctetString(b []byte) *Value {
	c := make([]byte, len(b))
	copy(c, b)
	return &Value{typ: TypeOctetString, bytes: c}
}

func NewVisibleString(s string) *Value { return &Value{typ: TypeVisibleString, bytes: []byte(s)} }
func NewMMSString(s string) *Value     { return &Value{typ: TypeMMSString, bytes: []byte(s)} }

// NewUTCTime returns an IEC 61850 UtcTime value (8 octets: seconds,
// 24-bit second fraction, time quality).
func NewUTCTime(t time.Time, q TimeQuality) *Value {
	b := make([]byte, 8)
	secs := t.Unix()
	frac := uint32((uint64(t.Nanosecond()) << 24) / 1_000_000_000)
	b[0], b[1], b[2], b[3] = byte(secs>>24), byte(secs>>16), byte(secs>>8), byte(secs)
	b[4], b[5], b[6] = byte(frac>>16), byte(frac>>8), byte(frac)
	b[7] = byte(q)
	return &Value{typ: TypeUTCTime, bytes: b}
}

// NewUTCTimeNow returns the current time with 10 bits of declared accuracy.
func NewUTCTimeNow() *Value { return NewUTCTime(time.Now(), TimeAccuracy(10)) }

// NewUTCTimeRaw wraps 8 raw UtcTime octets (copied).
func NewUTCTimeRaw(b []byte) (*Value, error) {
	if len(b) != 8 {
		return nil, fmt.Errorf("mms: UtcTime needs 8 octets, got %d", len(b))
	}
	c := make([]byte, 8)
	copy(c, b)
	return &Value{typ: TypeUTCTime, bytes: c}, nil
}

// NewBinaryTime returns an MMS TimeOfDay (6 octets: ms since midnight,
// days since 1984-01-01).
func NewBinaryTime(t time.Time) *Value {
	epoch := time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC)
	days := uint16(t.Sub(epoch).Hours() / 24)
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	ms := uint32(t.Sub(midnight).Milliseconds())
	return &Value{typ: TypeBinaryTime, bytes: []byte{
		byte(ms >> 24), byte(ms >> 16), byte(ms >> 8), byte(ms), byte(days >> 8), byte(days),
	}}
}

func NewArray(elements ...*Value) *Value {
	return &Value{typ: TypeArray, children: elements}
}

func NewStructure(members ...*Value) *Value {
	return &Value{typ: TypeStructure, children: members}
}

// NewDataAccessError wraps a DataAccessError code as a value, as it
// appears inside read AccessResults.
func NewDataAccessError(code DataAccessError) *Value {
	return &Value{typ: TypeDataAccessError, num: int64(code)}
}

// Accessors. Numeric accessors convert between integer widths; accessing
// a Value with the wrong family returns the zero value.

func (v *Value) Type() Type {
	if v == nil {
		return TypeNone
	}
	return v.typ
}

func (v *Value) Bool() bool { return v != nil && v.typ == TypeBoolean && v.num != 0 }

func (v *Value) Int64() int64 {
	if v == nil {
		return 0
	}
	switch v.typ {
	case TypeInteger, TypeUnsigned, TypeBoolean:
		return v.num
	case TypeFloat32, TypeFloat64:
		return int64(v.flt)
	}
	return 0
}

func (v *Value) Int32() int32   { return int32(v.Int64()) }
func (v *Value) Uint64() uint64 { return uint64(v.Int64()) }

func (v *Value) Float64() float64 {
	if v == nil {
		return 0
	}
	switch v.typ {
	case TypeFloat32, TypeFloat64:
		return v.flt
	case TypeInteger, TypeUnsigned:
		return float64(v.num)
	}
	return 0
}

func (v *Value) Float32() float32 { return float32(v.Float64()) }

// Text returns the string content for string types, and a best-effort
// rendering otherwise.
func (v *Value) Text() string {
	if v == nil {
		return ""
	}
	switch v.typ {
	case TypeVisibleString, TypeMMSString, TypeGeneralizedTime:
		return string(v.bytes)
	default:
		return v.String()
	}
}

// Bytes returns the raw content octets for bit strings (packed bits),
// octet strings and time types. The slice is the value's backing store;
// do not modify.
func (v *Value) Bytes() []byte {
	if v == nil {
		return nil
	}
	return v.bytes
}

// BitLen returns the number of valid bits for bit strings.
func (v *Value) BitLen() int {
	if v == nil {
		return 0
	}
	return v.bitLen
}

// Bit returns bit i of a bit string (0 = MSB of first octet).
func (v *Value) Bit(i int) bool {
	if v == nil || v.typ != TypeBitString || i < 0 || i >= v.bitLen {
		return false
	}
	return v.bytes[i/8]&(0x80>>uint(i%8)) != 0
}

// SetBit sets bit i of a bit string.
func (v *Value) SetBit(i int, on bool) {
	if v == nil || v.typ != TypeBitString || i < 0 || i >= v.bitLen {
		return
	}
	if on {
		v.bytes[i/8] |= 0x80 >> uint(i%8)
	} else {
		v.bytes[i/8] &^= 0x80 >> uint(i%8)
	}
}

// Len returns the number of children for arrays and structures.
func (v *Value) Len() int {
	if v == nil {
		return 0
	}
	return len(v.children)
}

// Index returns child i of an array or structure, or nil.
func (v *Value) Index(i int) *Value {
	if v == nil || i < 0 || i >= len(v.children) {
		return nil
	}
	return v.children[i]
}

// Children returns the backing child slice (do not modify).
func (v *Value) Children() []*Value {
	if v == nil {
		return nil
	}
	return v.children
}

// SetIndex replaces child i; out-of-range is ignored.
func (v *Value) SetIndex(i int, c *Value) {
	if v == nil || i < 0 || i >= len(v.children) {
		return
	}
	v.children[i] = c
}

// AccessError returns the DataAccessError code and true when the value
// is a per-element error.
func (v *Value) AccessError() (DataAccessError, bool) {
	if v == nil || v.typ != TypeDataAccessError {
		return 0, false
	}
	return DataAccessError(v.num), true
}

// Time converts UTCTime and BinaryTime values to time.Time (zero
// otherwise).
func (v *Value) Time() time.Time {
	if v == nil {
		return time.Time{}
	}
	switch v.typ {
	case TypeUTCTime:
		if len(v.bytes) != 8 {
			return time.Time{}
		}
		secs := int64(uint32(v.bytes[0])<<24 | uint32(v.bytes[1])<<16 | uint32(v.bytes[2])<<8 | uint32(v.bytes[3]))
		frac := uint64(v.bytes[4])<<16 | uint64(v.bytes[5])<<8 | uint64(v.bytes[6])
		ns := (frac * 1_000_000_000) >> 24
		return time.Unix(secs, int64(ns)).UTC()
	case TypeBinaryTime:
		if len(v.bytes) != 6 && len(v.bytes) != 4 {
			return time.Time{}
		}
		ms := uint32(v.bytes[0])<<24 | uint32(v.bytes[1])<<16 | uint32(v.bytes[2])<<8 | uint32(v.bytes[3])
		days := 0
		if len(v.bytes) == 6 {
			days = int(v.bytes[4])<<8 | int(v.bytes[5])
		}
		epoch := time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC)
		return epoch.AddDate(0, 0, days).Add(time.Duration(ms) * time.Millisecond)
	}
	return time.Time{}
}

// TimeQualityFlags returns the quality octet of a UTCTime value.
func (v *Value) TimeQualityFlags() TimeQuality {
	if v == nil || v.typ != TypeUTCTime || len(v.bytes) != 8 {
		return 0
	}
	return TimeQuality(v.bytes[7])
}

// Clone returns a deep copy.
func (v *Value) Clone() *Value {
	if v == nil {
		return nil
	}
	c := &Value{typ: v.typ, num: v.num, flt: v.flt, bitLen: v.bitLen}
	if v.bytes != nil {
		c.bytes = make([]byte, len(v.bytes))
		copy(c.bytes, v.bytes)
	}
	if v.children != nil {
		c.children = make([]*Value, len(v.children))
		for i, ch := range v.children {
			c.children[i] = ch.Clone()
		}
	}
	return c
}

// Equal reports deep equality of type and content.
func (v *Value) Equal(o *Value) bool {
	if v == nil || o == nil {
		return v == o
	}
	if v.typ != o.typ || v.num != o.num || v.bitLen != o.bitLen ||
		len(v.children) != len(o.children) {
		return false
	}
	if v.typ == TypeFloat32 || v.typ == TypeFloat64 {
		if v.flt != o.flt && !(math.IsNaN(v.flt) && math.IsNaN(o.flt)) {
			return false
		}
	}
	if string(v.bytes) != string(o.bytes) {
		return false
	}
	for i := range v.children {
		if !v.children[i].Equal(o.children[i]) {
			return false
		}
	}
	return true
}

// String renders the value for diagnostics.
func (v *Value) String() string {
	if v == nil {
		return "<nil>"
	}
	switch v.typ {
	case TypeBoolean:
		return strconv.FormatBool(v.num != 0)
	case TypeInteger:
		return strconv.FormatInt(v.num, 10)
	case TypeUnsigned:
		return strconv.FormatUint(uint64(v.num), 10)
	case TypeFloat32, TypeFloat64:
		return strconv.FormatFloat(v.flt, 'g', -1, 64)
	case TypeVisibleString, TypeMMSString, TypeGeneralizedTime:
		return strconv.Quote(string(v.bytes))
	case TypeOctetString:
		return hex.EncodeToString(v.bytes)
	case TypeBitString:
		var sb strings.Builder
		for i := 0; i < v.bitLen; i++ {
			if v.Bit(i) {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
		return sb.String()
	case TypeUTCTime:
		return v.Time().Format(time.RFC3339Nano)
	case TypeBinaryTime:
		return v.Time().Format(time.RFC3339Nano)
	case TypeArray, TypeStructure:
		var sb strings.Builder
		if v.typ == TypeArray {
			sb.WriteByte('[')
		} else {
			sb.WriteByte('{')
		}
		for i, c := range v.children {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(c.String())
		}
		if v.typ == TypeArray {
			sb.WriteByte(']')
		} else {
			sb.WriteByte('}')
		}
		return sb.String()
	case TypeDataAccessError:
		return "error:" + DataAccessError(v.num).String()
	}
	return "<invalid>"
}

// TimeQuality is the IEC 61850 UtcTime quality octet.
type TimeQuality uint8

const (
	TimeLeapSecondsKnown     TimeQuality = 0x80
	TimeClockFailure         TimeQuality = 0x40
	TimeClockNotSynchronized TimeQuality = 0x20
)

// TimeAccuracy returns a TimeQuality declaring n bits of fraction
// accuracy (0..24; use TimeAccuracyUnspecified for none).
func TimeAccuracy(n int) TimeQuality {
	if n < 0 {
		n = 0
	}
	if n > 24 {
		n = 24
	}
	return TimeLeapSecondsKnown | TimeQuality(n)
}

// TimeAccuracyUnspecified declares no fraction accuracy.
const TimeAccuracyUnspecified TimeQuality = 0x1f
