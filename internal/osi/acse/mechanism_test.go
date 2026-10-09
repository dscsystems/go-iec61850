package acse

import (
	"bytes"
	"testing"
)

// The password mechanism must be encoded as libiec61850 and other IEC 61850
// servers expect it: mechanism-name [11] 2.2.3.1 = 8b 03 52 03 01. An earlier
// 2.2.3.0.1 (8b 04 52 03 00 01) made libiec61850 drop the association at the
// session layer.
func TestPasswordMechanismOID(t *testing.T) {
	apdu := AARQ([]byte{0xa8, 0x00}, "user1@testpw")
	if !bytes.Contains(apdu, []byte{0x8b, 0x03, 0x52, 0x03, 0x01}) {
		t.Fatalf("mechanism-name 2.2.3.1 not found in % x", apdu)
	}
	if bytes.Contains(apdu, []byte{0x52, 0x03, 0x00, 0x01}) {
		t.Fatal("the old 2.2.3.0.1 mechanism is still encoded")
	}
}
