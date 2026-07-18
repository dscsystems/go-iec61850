// Package asn1 implements the minimal BER (ISO 8825-1) runtime used by the
// MMS, ACSE, presentation, GOOSE and SV codecs in this module.
//
// It is deliberately small: tag/length/value framing, bounds-checked
// decoding of untrusted input, and primitive value helpers. Typed PDU
// grammars live in the packages that own them.
package asn1

import (
	"errors"
	"fmt"
)

// Class is the tag class of a BER element.
type Class uint8

const (
	ClassUniversal       Class = 0
	ClassApplication     Class = 1
	ClassContextSpecific Class = 2
	ClassPrivate         Class = 3
)

// Tag identifies a BER element.
type Tag struct {
	Class       Class
	Constructed bool
	Number      uint32
}

// Common universal tags.
var (
	TagBoolean       = Tag{ClassUniversal, false, 1}
	TagInteger       = Tag{ClassUniversal, false, 2}
	TagBitString     = Tag{ClassUniversal, false, 3}
	TagOctetString   = Tag{ClassUniversal, false, 4}
	TagNull          = Tag{ClassUniversal, false, 5}
	TagOID           = Tag{ClassUniversal, false, 6}
	TagSequence      = Tag{ClassUniversal, true, 16}
	TagSet           = Tag{ClassUniversal, true, 17}
	TagVisibleString = Tag{ClassUniversal, false, 26}
	TagGraphicString = Tag{ClassUniversal, false, 25}
	TagUTF8String    = Tag{ClassUniversal, false, 12}
	TagGeneralTime   = Tag{ClassUniversal, false, 24}
)

// ContextPrimitive returns a primitive context-specific tag [n].
func ContextPrimitive(n uint32) Tag { return Tag{ClassContextSpecific, false, n} }

// ContextConstructed returns a constructed context-specific tag [n].
func ContextConstructed(n uint32) Tag { return Tag{ClassContextSpecific, true, n} }

// ApplicationConstructed returns a constructed application-class tag.
func ApplicationConstructed(n uint32) Tag { return Tag{ClassApplication, true, n} }

func (t Tag) String() string {
	class := [...]string{"UNIVERSAL", "APPLICATION", "CONTEXT", "PRIVATE"}[t.Class&3]
	pc := "primitive"
	if t.Constructed {
		pc = "constructed"
	}
	return fmt.Sprintf("[%s %d %s]", class, t.Number, pc)
}

// Errors returned by the decoder. All are wrapped with positional context;
// match with errors.Is.
var (
	ErrTruncated   = errors.New("asn1: truncated element")
	ErrBadTag      = errors.New("asn1: malformed tag")
	ErrBadLength   = errors.New("asn1: malformed length")
	ErrTooDeep     = errors.New("asn1: nesting too deep")
	ErrUnexpected  = errors.New("asn1: unexpected element")
	ErrBadValue    = errors.New("asn1: malformed value")
	errLenOverflow = errors.New("asn1: length overflows")
)

// MaxDepth is the nesting limit enforced by depth-aware helpers.
const MaxDepth = 64

// AppendTag appends the identifier octets of t to dst.
func AppendTag(dst []byte, t Tag) []byte {
	b := byte(t.Class) << 6
	if t.Constructed {
		b |= 0x20
	}
	if t.Number < 31 {
		return append(dst, b|byte(t.Number))
	}
	dst = append(dst, b|0x1f)
	// Base-128, big-endian, high bit set on all but the last octet.
	n := t.Number
	var tmp [5]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			break
		}
	}
	for j := i; j < len(tmp)-1; j++ {
		tmp[j] |= 0x80
	}
	return append(dst, tmp[i:]...)
}

// AppendLength appends definite-form length octets for content length n.
func AppendLength(dst []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(dst, byte(n))
	case n <= 0xff:
		return append(dst, 0x81, byte(n))
	case n <= 0xffff:
		return append(dst, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		return append(dst, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(dst, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// TagSize returns the encoded size of the identifier octets of t.
func TagSize(t Tag) int {
	switch {
	case t.Number < 31:
		return 1
	case t.Number < 1<<7:
		return 2
	case t.Number < 1<<14:
		return 3
	case t.Number < 1<<21:
		return 4
	default:
		return 5
	}
}

// LengthSize returns the encoded size of the length octets for content length n.
func LengthSize(n int) int {
	switch {
	case n < 0x80:
		return 1
	case n <= 0xff:
		return 2
	case n <= 0xffff:
		return 3
	case n <= 0xffffff:
		return 4
	default:
		return 5
	}
}

// TLVSize returns the total encoded size of an element with tag t and
// content length n.
func TLVSize(t Tag, n int) int { return TagSize(t) + LengthSize(n) + n }

// AppendTLV appends a complete element with the given content.
func AppendTLV(dst []byte, t Tag, content []byte) []byte {
	dst = AppendTag(dst, t)
	dst = AppendLength(dst, len(content))
	return append(dst, content...)
}
