package mms

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// MMS Data CHOICE context tags (ISO 9506-2).
const (
	tagDataArray       = 1
	tagDataStructure   = 2
	tagDataBoolean     = 3
	tagDataBitString   = 4
	tagDataInteger     = 5
	tagDataUnsigned    = 6
	tagDataFloat       = 7
	tagDataOctetString = 9
	tagDataVisString   = 10
	tagDataGenTime     = 11
	tagDataBinTime     = 12
	tagDataBCD         = 13
	tagDataBoolArray   = 14
	tagDataObjID       = 15
	tagDataMMSString   = 16
	tagDataUTCTime     = 17
)

const maxValueDepth = 32

// DataElement converts a Value into its BER element as an MMS Data
// CHOICE. Returns nil for nil or TypeNone values.
func DataElement(v *Value) *asn1.Element {
	if v == nil || v.typ == TypeNone {
		return nil
	}
	switch v.typ {
	case TypeArray, TypeStructure:
		n := uint32(tagDataStructure)
		if v.typ == TypeArray {
			n = tagDataArray
		}
		el := asn1.Cons(asn1.ContextConstructed(n))
		for _, c := range v.children {
			el.Add(DataElement(c))
		}
		return el
	case TypeBoolean:
		return asn1.BoolElem(asn1.ContextPrimitive(tagDataBoolean), v.num != 0)
	case TypeBitString:
		return asn1.BitStringElem(asn1.ContextPrimitive(tagDataBitString),
			asn1.BitString{Bits: v.bytes, Length: v.bitLen})
	case TypeInteger:
		return asn1.IntElem(asn1.ContextPrimitive(tagDataInteger), v.num)
	case TypeUnsigned:
		return asn1.UintElem(asn1.ContextPrimitive(tagDataUnsigned), uint64(v.num))
	case TypeFloat32:
		return asn1.Prim(asn1.ContextPrimitive(tagDataFloat), asn1.AppendFloat32(nil, float32(v.flt)))
	case TypeFloat64:
		return asn1.Prim(asn1.ContextPrimitive(tagDataFloat), asn1.AppendFloat64(nil, v.flt))
	case TypeOctetString:
		return asn1.Prim(asn1.ContextPrimitive(tagDataOctetString), v.bytes)
	case TypeVisibleString:
		return asn1.Prim(asn1.ContextPrimitive(tagDataVisString), v.bytes)
	case TypeGeneralizedTime:
		return asn1.Prim(asn1.ContextPrimitive(tagDataGenTime), v.bytes)
	case TypeBinaryTime:
		return asn1.Prim(asn1.ContextPrimitive(tagDataBinTime), v.bytes)
	case TypeMMSString:
		return asn1.Prim(asn1.ContextPrimitive(tagDataMMSString), v.bytes)
	case TypeUTCTime:
		return asn1.Prim(asn1.ContextPrimitive(tagDataUTCTime), v.bytes)
	case TypeDataAccessError:
		// Only valid inside AccessResult; encoded there as [0] INTEGER.
		return asn1.UintElem(asn1.ContextPrimitive(0), uint64(v.num))
	}
	return nil
}

// AppendData encodes v as an MMS Data CHOICE element.
func AppendData(dst []byte, v *Value) []byte {
	el := DataElement(v)
	if el == nil {
		return dst
	}
	return el.Append(dst)
}

// DecodeData decodes one MMS Data CHOICE element from dec.
func DecodeData(dec *asn1.Decoder) (*Value, error) {
	return decodeData(dec, 0)
}

func decodeData(dec *asn1.Decoder, depth int) (*Value, error) {
	if depth > maxValueDepth {
		return nil, fmt.Errorf("mms: data nesting exceeds %d: %w", maxValueDepth, asn1.ErrTooDeep)
	}
	tag, content, err := dec.ReadTLV()
	if err != nil {
		return nil, err
	}
	return decodeDataTLV(tag, content, depth)
}

func decodeDataTLV(tag asn1.Tag, content []byte, depth int) (*Value, error) {
	if tag.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("mms: data with tag %v: %w", tag, asn1.ErrUnexpected)
	}
	switch tag.Number {
	case tagDataArray, tagDataStructure:
		typ := TypeStructure
		if tag.Number == tagDataArray {
			typ = TypeArray
		}
		v := &Value{typ: typ}
		inner := asn1.NewDecoder(content)
		for inner.More() {
			c, err := decodeData(inner, depth+1)
			if err != nil {
				return nil, err
			}
			v.children = append(v.children, c)
		}
		return v, nil
	case tagDataBoolean:
		b, err := asn1.DecodeBool(content)
		if err != nil {
			return nil, err
		}
		return NewBool(b), nil
	case tagDataBitString:
		bs, err := asn1.DecodeBitString(content)
		if err != nil {
			return nil, err
		}
		return NewBitStringBits(bs.Bits, bs.Length), nil
	case tagDataInteger:
		n, err := asn1.DecodeInt(content)
		if err != nil {
			return nil, err
		}
		return &Value{typ: TypeInteger, num: n}, nil
	case tagDataUnsigned:
		n, err := asn1.DecodeUint(content)
		if err != nil {
			return nil, err
		}
		return &Value{typ: TypeUnsigned, num: int64(n)}, nil
	case tagDataFloat:
		f, err := asn1.DecodeFloat(content)
		if err != nil {
			return nil, err
		}
		if len(content) == 5 {
			return &Value{typ: TypeFloat32, flt: f}, nil
		}
		return &Value{typ: TypeFloat64, flt: f}, nil
	case tagDataOctetString:
		return NewOctetString(content), nil
	case tagDataVisString:
		return NewVisibleString(string(content)), nil
	case tagDataGenTime:
		return &Value{typ: TypeGeneralizedTime, bytes: append([]byte(nil), content...)}, nil
	case tagDataBinTime:
		if len(content) != 4 && len(content) != 6 {
			return nil, fmt.Errorf("mms: binary-time of %d octets: %w", len(content), asn1.ErrBadValue)
		}
		return &Value{typ: TypeBinaryTime, bytes: append([]byte(nil), content...)}, nil
	case tagDataMMSString:
		return NewMMSString(string(content)), nil
	case tagDataUTCTime:
		return NewUTCTimeRaw(content)
	default:
		return nil, fmt.Errorf("mms: unsupported data tag [%d]: %w", tag.Number, asn1.ErrUnexpected)
	}
}

// DecodeAccessResult decodes one MMS AccessResult: either [0] failure
// (returned as a TypeDataAccessError value) or a Data success.
func DecodeAccessResult(dec *asn1.Decoder) (*Value, error) {
	tag, err := dec.Peek()
	if err != nil {
		return nil, err
	}
	if tag.Class == asn1.ClassContextSpecific && tag.Number == 0 && !tag.Constructed {
		_, content, err := dec.ReadTLV()
		if err != nil {
			return nil, err
		}
		code, err := asn1.DecodeUint(content)
		if err != nil {
			return nil, err
		}
		return NewDataAccessError(DataAccessError(code)), nil
	}
	return DecodeData(dec)
}
