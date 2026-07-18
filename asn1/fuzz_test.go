package asn1

import "testing"

// FuzzReadTLV drives the decoder over arbitrary input: it must never
// panic and must always terminate.
func FuzzReadTLV(f *testing.F) {
	f.Add([]byte{0x30, 0x06, 0x80, 0x01, 0x05, 0x81, 0x01, 0xff})
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00})
	f.Add([]byte{0x1f, 0x81, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		d := NewDecoder(data)
		for d.More() {
			tag, content, err := d.ReadTLV()
			if err != nil {
				return
			}
			if tag.Constructed {
				inner := NewDecoder(content)
				for inner.More() {
					if err := inner.Skip(); err != nil {
						break
					}
				}
			}
		}
	})
}

// FuzzPrimitives exercises the primitive decoders.
func FuzzPrimitives(f *testing.F) {
	f.Add([]byte{0x00, 0x80})
	f.Fuzz(func(t *testing.T, data []byte) {
		DecodeInt(data)
		DecodeUint(data)
		DecodeBool(data)
		DecodeBitString(data)
		DecodeFloat(data)
		DecodeOID(data)
	})
}
