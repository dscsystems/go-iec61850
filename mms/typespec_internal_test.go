package mms

import (
	"errors"
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// hostileSpecs are type specifications whose declared sizes are far
// larger than any real model, encoded as a peer could send them. Each is
// only a handful of octets, so the cost of accepting one is unbounded
// relative to the cost of sending it.
func hostileSpecs() map[string]*TypeSpec {
	return map[string]*TypeSpec{
		// int(n) of a 64-bit all-ones length went negative, and
		// make([]*Value, -1) panics.
		"array/negative": {Kind: TypeArray, Elements: -1, Element: &TypeSpec{Kind: TypeBoolean}},
		// 16 GiB of pointers from 13 octets.
		"array/huge": {Kind: TypeArray, Elements: 1 << 31, Element: &TypeSpec{Kind: TypeBoolean}},
		// Each dimension is individually plausible; the product is not.
		"array/nested": {Kind: TypeArray, Elements: maxArrayElements, Element: &TypeSpec{
			Kind: TypeArray, Elements: maxArrayElements, Element: &TypeSpec{Kind: TypeBoolean}}},
		// NewBitString allocates Size/8 bytes: a fatal OOM, not a panic,
		// so it kills the process rather than unwinding.
		"bitstring/huge":   {Kind: TypeBitString, Size: 1 << 40},
		"bitstring/minint": {Kind: TypeBitString, Size: -1 << 62},
	}
}

func TestDecodeTypeSpecRejectsHostileSizes(t *testing.T) {
	for name, ts := range hostileSpecs() {
		t.Run(name, func(t *testing.T) {
			enc := ts.BER().Encode()
			got, err := DecodeTypeSpec(asn1.NewDecoder(enc))
			if err == nil {
				t.Fatalf("accepted %d-octet spec declaring %d elements / size %d",
					len(enc), got.Elements, got.Size)
			}
			if !errors.Is(err, asn1.ErrBadLength) {
				t.Errorf("error = %v, want ErrBadLength", err)
			}
		})
	}
}

// A spec within the limits still decodes and materialises.
func TestDecodeTypeSpecAcceptsRealisticSizes(t *testing.T) {
	ts := &TypeSpec{Kind: TypeStructure, Components: []Component{
		{Name: "arr", Spec: &TypeSpec{Kind: TypeArray, Elements: 256,
			Element: &TypeSpec{Kind: TypeBoolean}}},
		{Name: "q", Spec: &TypeSpec{Kind: TypeBitString, Size: 13}},
		{Name: "neg", Spec: &TypeSpec{Kind: TypeBitString, Size: -64}},
	}}
	got, err := DecodeTypeSpec(asn1.NewDecoder(ts.BER().Encode()))
	if err != nil {
		t.Fatalf("DecodeTypeSpec: %v", err)
	}
	v := got.DefaultValue()
	if v == nil || v.Len() != 3 {
		t.Fatalf("DefaultValue = %v", v)
	}
	if n := v.Index(0).Len(); n != 256 {
		t.Errorf("array materialised %d elements, want 256", n)
	}
	if n := v.Index(1).BitLen(); n != 13 {
		t.Errorf("bit string materialised %d bits, want 13", n)
	}
	// A negative Size is a variable-length declaration: the default value
	// is the full width, not an error.
	if n := v.Index(2).BitLen(); n != 64 {
		t.Errorf("variable bit string materialised %d bits, want 64", n)
	}
}
