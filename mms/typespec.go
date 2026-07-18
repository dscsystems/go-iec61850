package mms

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// TypeSpec describes an MMS variable type as reported by
// getVariableAccessAttributes (ISO 9506-2 TypeSpecification). It is the
// raw material the client uses to reconstruct a server's data model.
type TypeSpec struct {
	Kind Type
	// Size is type-dependent: bit width for integer/unsigned, declared
	// length for strings and octet strings (negative = variable up to
	// -Size), bit count for bit strings (negative = variable).
	Size int
	// Array fields.
	Elements int
	Element  *TypeSpec
	// Structure components in declaration order.
	Components []Component
}

// Component is a named member of a structure TypeSpec.
type Component struct {
	Name string
	Spec *TypeSpec
}

// BER encodes the TypeSpec as a BER TypeSpecification CHOICE element.
func (ts *TypeSpec) BER() *asn1.Element {
	switch ts.Kind {
	case TypeArray:
		return asn1.Cons(asn1.ContextConstructed(tagDataArray),
			asn1.UintElem(asn1.ContextPrimitive(1), uint64(ts.Elements)),
			asn1.Cons(asn1.ContextConstructed(2), ts.Element.BER()),
		)
	case TypeStructure:
		comps := asn1.Cons(asn1.ContextConstructed(1))
		for _, c := range ts.Components {
			comps.Add(asn1.Cons(asn1.TagSequence,
				asn1.Prim(asn1.ContextPrimitive(0), []byte(c.Name)),
				asn1.Cons(asn1.ContextConstructed(1), c.Spec.BER()),
			))
		}
		return asn1.Cons(asn1.ContextConstructed(tagDataStructure), comps)
	case TypeBoolean:
		return asn1.Prim(asn1.ContextPrimitive(tagDataBoolean), nil)
	case TypeBitString:
		return asn1.IntElem(asn1.ContextPrimitive(tagDataBitString), int64(ts.Size))
	case TypeInteger:
		return asn1.UintElem(asn1.ContextPrimitive(tagDataInteger), uint64(ts.Size))
	case TypeUnsigned:
		return asn1.UintElem(asn1.ContextPrimitive(tagDataUnsigned), uint64(ts.Size))
	case TypeFloat32:
		// floating-point [7] IMPLICIT SEQUENCE { format-width, exponent-width }
		return asn1.Cons(asn1.ContextConstructed(tagDataFloat),
			asn1.IntElem(asn1.TagInteger, 32), asn1.IntElem(asn1.TagInteger, 8))
	case TypeFloat64:
		return asn1.Cons(asn1.ContextConstructed(tagDataFloat),
			asn1.IntElem(asn1.TagInteger, 64), asn1.IntElem(asn1.TagInteger, 11))
	case TypeOctetString:
		return asn1.IntElem(asn1.ContextPrimitive(tagDataOctetString), int64(ts.Size))
	case TypeVisibleString:
		return asn1.IntElem(asn1.ContextPrimitive(tagDataVisString), int64(ts.Size))
	case TypeGeneralizedTime:
		return asn1.Prim(asn1.ContextPrimitive(tagDataGenTime), nil)
	case TypeBinaryTime:
		return asn1.BoolElem(asn1.ContextPrimitive(tagDataBinTime), true)
	case TypeMMSString:
		return asn1.IntElem(asn1.ContextPrimitive(tagDataMMSString), int64(ts.Size))
	case TypeUTCTime:
		return asn1.Prim(asn1.ContextPrimitive(tagDataUTCTime), nil)
	}
	return nil
}

// DecodeTypeSpec decodes one TypeSpecification element from dec.
func DecodeTypeSpec(dec *asn1.Decoder) (*TypeSpec, error) {
	return decodeTypeSpec(dec, 0)
}

func decodeTypeSpec(dec *asn1.Decoder, depth int) (*TypeSpec, error) {
	if depth > maxValueDepth {
		return nil, fmt.Errorf("mms: type nesting exceeds %d: %w", maxValueDepth, asn1.ErrTooDeep)
	}
	tag, content, err := dec.ReadTLV()
	if err != nil {
		return nil, err
	}
	if tag.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("mms: type specification tag %v: %w", tag, asn1.ErrUnexpected)
	}
	switch tag.Number {
	case tagDataArray:
		ts := &TypeSpec{Kind: TypeArray}
		inner := asn1.NewDecoder(content)
		if c, ok, err := inner.Optional(asn1.ContextPrimitive(0)); err != nil {
			return nil, err
		} else if ok {
			_ = c // packed flag, ignored
		}
		nc, err := inner.Expect(asn1.ContextPrimitive(1))
		if err != nil {
			return nil, err
		}
		n, err := asn1.DecodeUint(nc)
		if err != nil {
			return nil, err
		}
		ts.Elements = int(n)
		ec, err := inner.Expect(asn1.ContextConstructed(2))
		if err != nil {
			return nil, err
		}
		ts.Element, err = decodeTypeSpec(asn1.NewDecoder(ec), depth+1)
		if err != nil {
			return nil, err
		}
		return ts, nil
	case tagDataStructure:
		ts := &TypeSpec{Kind: TypeStructure}
		inner := asn1.NewDecoder(content)
		if _, _, err := inner.Optional(asn1.ContextPrimitive(0)); err != nil { // packed
			return nil, err
		}
		compsContent, err := inner.Expect(asn1.ContextConstructed(1))
		if err != nil {
			return nil, err
		}
		comps := asn1.NewDecoder(compsContent)
		for comps.More() {
			seq, err := comps.Expect(asn1.TagSequence)
			if err != nil {
				return nil, err
			}
			cd := asn1.NewDecoder(seq)
			var comp Component
			if name, ok, err := cd.Optional(asn1.ContextPrimitive(0)); err != nil {
				return nil, err
			} else if ok {
				comp.Name = string(name)
			}
			specContent, err := cd.Expect(asn1.ContextConstructed(1))
			if err != nil {
				return nil, err
			}
			comp.Spec, err = decodeTypeSpec(asn1.NewDecoder(specContent), depth+1)
			if err != nil {
				return nil, err
			}
			ts.Components = append(ts.Components, comp)
		}
		return ts, nil
	case tagDataBoolean:
		return &TypeSpec{Kind: TypeBoolean}, nil
	case tagDataBitString:
		n, err := asn1.DecodeInt(content)
		if err != nil {
			return nil, err
		}
		return &TypeSpec{Kind: TypeBitString, Size: int(n)}, nil
	case tagDataInteger:
		n, err := asn1.DecodeUint(content)
		if err != nil {
			return nil, err
		}
		return &TypeSpec{Kind: TypeInteger, Size: int(n)}, nil
	case tagDataUnsigned:
		n, err := asn1.DecodeUint(content)
		if err != nil {
			return nil, err
		}
		return &TypeSpec{Kind: TypeUnsigned, Size: int(n)}, nil
	case tagDataFloat:
		// floating-point [7] IMPLICIT SEQUENCE { format-width, exponent-width }
		fd := asn1.NewDecoder(content)
		fw, err := fd.Expect(asn1.TagInteger)
		if err != nil {
			return nil, err
		}
		width, err := asn1.DecodeInt(fw)
		if err != nil {
			return nil, err
		}
		if width > 32 {
			return &TypeSpec{Kind: TypeFloat64}, nil
		}
		return &TypeSpec{Kind: TypeFloat32}, nil
	case tagDataOctetString:
		n, err := asn1.DecodeInt(content)
		if err != nil {
			return nil, err
		}
		return &TypeSpec{Kind: TypeOctetString, Size: int(n)}, nil
	case tagDataVisString:
		n, err := asn1.DecodeInt(content)
		if err != nil {
			return nil, err
		}
		return &TypeSpec{Kind: TypeVisibleString, Size: int(n)}, nil
	case tagDataGenTime:
		return &TypeSpec{Kind: TypeGeneralizedTime}, nil
	case tagDataBinTime:
		return &TypeSpec{Kind: TypeBinaryTime}, nil
	case tagDataMMSString:
		n, err := asn1.DecodeInt(content)
		if err != nil {
			return nil, err
		}
		return &TypeSpec{Kind: TypeMMSString, Size: int(n)}, nil
	case tagDataUTCTime:
		return &TypeSpec{Kind: TypeUTCTime}, nil
	default:
		return nil, fmt.Errorf("mms: unsupported type specification tag [%d]: %w", tag.Number, asn1.ErrUnexpected)
	}
}

// DefaultValue returns a zero value matching the type specification,
// used by servers and tests to materialise a model.
func (ts *TypeSpec) DefaultValue() *Value {
	switch ts.Kind {
	case TypeArray:
		children := make([]*Value, ts.Elements)
		for i := range children {
			children[i] = ts.Element.DefaultValue()
		}
		return &Value{typ: TypeArray, children: children}
	case TypeStructure:
		children := make([]*Value, len(ts.Components))
		for i, c := range ts.Components {
			children[i] = c.Spec.DefaultValue()
		}
		return &Value{typ: TypeStructure, children: children}
	case TypeBoolean:
		return NewBool(false)
	case TypeBitString:
		n := ts.Size
		if n < 0 {
			n = -n
		}
		return NewBitString(n)
	case TypeInteger:
		return NewInt64(0)
	case TypeUnsigned:
		return NewUint32(0)
	case TypeFloat32:
		return NewFloat32(0)
	case TypeFloat64:
		return NewFloat64(0)
	case TypeOctetString:
		return NewOctetString(nil)
	case TypeVisibleString:
		return NewVisibleString("")
	case TypeMMSString:
		return NewMMSString("")
	case TypeGeneralizedTime:
		return &Value{typ: TypeGeneralizedTime}
	case TypeBinaryTime:
		return &Value{typ: TypeBinaryTime, bytes: make([]byte, 6)}
	case TypeUTCTime:
		v, _ := NewUTCTimeRaw(make([]byte, 8))
		return v
	}
	return nil
}
