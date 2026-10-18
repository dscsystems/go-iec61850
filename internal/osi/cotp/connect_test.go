package cotp

import (
	"bytes"
	"testing"
)

// The CC must answer our CR: its destination reference is our source
// reference (ISO 8073), and an out-of-range size code is ignored.
func TestConnectChecksCC(t *testing.T) {
	cc := func(destRef byte, size byte) []byte {
		return frames([]byte{0x09, 0xd0, 0, destRef, 0, 7, 0, 0xc0, 1, size})
	}
	if _, err := Connect(fuzzRW{bytes.NewReader(cc(9, 10))}, Options{}); err == nil {
		t.Error("CC for another reference accepted")
	}
	c, err := Connect(fuzzRW{bytes.NewReader(cc(1, 0x40))}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if c.maxTPDU != 1024 {
		t.Errorf("size code 0x40 gave maxTPDU %d, want the proposed 1024", c.maxTPDU)
	}
	c, err = Connect(fuzzRW{bytes.NewReader(cc(1, 7))}, Options{TPDUSizeCode: 200})
	if err != nil {
		t.Fatal(err)
	}
	if c.maxTPDU != 128 {
		t.Errorf("maxTPDU %d after the CC lowered it to 128", c.maxTPDU)
	}
	c, _ = Connect(fuzzRW{bytes.NewReader(cc(1, 11))}, Options{TPDUSizeCode: 200})
	if c.maxTPDU != 2048 {
		t.Errorf("proposal code 200 gave maxTPDU %d, want class 0's 2048", c.maxTPDU)
	}
}
