package client

import (
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
)

// TestOperCheckWireBits pins Check to the ordering of IEC 61850-7-2
// Table 51, whose packed list runs synchrocheck then interlock-check, so
// synchrocheck takes bit 0 — the first transmitted bit. Client and server
// agree with each other under either assignment, so no round-trip test
// can catch a transposition here; assert the encoding itself.
func TestOperCheckWireBits(t *testing.T) {
	for _, tc := range []struct {
		name               string
		synchro, interlock bool
		lead               byte // the single octet holding the 2-bit string
	}{
		{"neither", false, false, 0x00},
		{"synchro", true, false, 0x80},
		{"interlock", false, true, 0x40},
		{"both", true, true, 0xc0},
	} {
		p := &controlParams{synchro: tc.synchro, interlock: tc.interlock}
		ck := (&ControlObject{}).buildOper(mms.NewBool(true), p, 1).Index(5)
		if ck == nil || ck.Type() != mms.TypeBitString || ck.BitLen() != 2 {
			t.Fatalf("%s: check is not a 2-bit string: %v", tc.name, ck)
		}
		if ck.Bit(0) != tc.synchro {
			t.Errorf("%s: bit 0 (synchrocheck) = %v, want %v", tc.name, ck.Bit(0), tc.synchro)
		}
		if ck.Bit(1) != tc.interlock {
			t.Errorf("%s: bit 1 (interlock-check) = %v, want %v", tc.name, ck.Bit(1), tc.interlock)
		}
		if got := ck.Bytes()[0]; got != tc.lead {
			t.Errorf("%s: check octet = %#02x, want %#02x", tc.name, got, tc.lead)
		}
	}
}
