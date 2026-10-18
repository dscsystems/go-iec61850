package acse

import "testing"

// result is mandatory in an AARE: without one, or with one that does not
// decode, the association is not accepted.
func TestAAREResultIsRequired(t *testing.T) {
	if _, err := ParseAARE([]byte{0x61, 0x00}); err == nil {
		t.Error("AARE without a result accepted")
	}
	if _, err := ParseAARE([]byte{0x61, 0x04, 0xa2, 0x02, 0x02, 0x00}); err == nil {
		t.Error("AARE with an empty result INTEGER accepted")
	}
	r, err := ParseAARE([]byte{0x61, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x00})
	if err != nil || !r.Accepted {
		t.Errorf("accepted(0): %+v, %v", r, err)
	}
	r, err = ParseAARE([]byte{0x61, 0x05, 0xa2, 0x03, 0x02, 0x01, 0x01})
	if err != nil || r.Accepted {
		t.Errorf("rejected-permanent(1): %+v, %v", r, err)
	}
}
