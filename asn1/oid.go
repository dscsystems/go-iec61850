package asn1

import (
	"fmt"
	"strconv"
	"strings"
)

// OID is an object identifier as a slice of arcs.
type OID []uint32

func (o OID) String() string {
	var sb strings.Builder
	for i, arc := range o {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(strconv.FormatUint(uint64(arc), 10))
	}
	return sb.String()
}

// Equal reports arc-wise equality.
func (o OID) Equal(other OID) bool {
	if len(o) != len(other) {
		return false
	}
	for i := range o {
		if o[i] != other[i] {
			return false
		}
	}
	return true
}

// AppendOID appends OID content octets (first two arcs combined, then
// base-128).
func AppendOID(dst []byte, o OID) []byte {
	if len(o) < 2 {
		return dst
	}
	dst = appendBase128(dst, o[0]*40+o[1])
	for _, arc := range o[2:] {
		dst = appendBase128(dst, arc)
	}
	return dst
}

func appendBase128(dst []byte, v uint32) []byte {
	var tmp [5]byte
	i := len(tmp)
	for {
		i--
		tmp[i] = byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			break
		}
	}
	for j := i; j < len(tmp)-1; j++ {
		tmp[j] |= 0x80
	}
	return append(dst, tmp[i:]...)
}

// DecodeOID decodes OID content octets.
func DecodeOID(content []byte) (OID, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("empty OID: %w", ErrBadValue)
	}
	var o OID
	var v uint32
	n := 0
	for _, b := range content {
		if n >= 5 {
			return nil, fmt.Errorf("OID arc too large: %w", ErrBadValue)
		}
		v = v<<7 | uint32(b&0x7f)
		n++
		if b&0x80 == 0 {
			if len(o) == 0 {
				first := v / 40
				if first > 2 {
					first = 2
				}
				o = append(o, first, v-first*40)
			} else {
				o = append(o, v)
			}
			v, n = 0, 0
		}
	}
	if n != 0 {
		return nil, fmt.Errorf("truncated OID arc: %w", ErrTruncated)
	}
	return o, nil
}

// OIDElem returns an OBJECT IDENTIFIER-content primitive element with tag t.
func OIDElem(t Tag, o OID) *Element { return Prim(t, AppendOID(nil, o)) }
