package acse

import "testing"

// ACSE APDUs from the peer: AARQ (server), AARE (client), release and
// abort (both).
func FuzzACSE(f *testing.F) {
	f.Add([]byte{0x60, 0x03, 0xa1, 0x01, 0x00})
	f.Add([]byte{0x61, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{0x64, 0x00})
	f.Fuzz(func(t *testing.T, apdu []byte) {
		ParseAARQFull(apdu)
		ParseAARE(apdu)
		ParseABRT(apdu)
		ParseABRTFull(apdu)
		ParseRelease(apdu)
	})
}
