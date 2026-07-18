package ethernet

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	f := &Frame{
		Dst:       [6]byte{0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01},
		Src:       [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x42},
		EtherType: EtherTypeGOOSE,
		Payload:   []byte{0xde, 0xad, 0xbe, 0xef},
	}
	got, err := ParseFrame(f.Marshal())
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if got.Dst != f.Dst || got.Src != f.Src || got.EtherType != f.EtherType {
		t.Fatalf("header mismatch: got %+v, want %+v", got, f)
	}
	if got.VLAN != nil {
		t.Fatalf("unexpected VLAN tag %+v", got.VLAN)
	}
	if !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("payload mismatch: got %x, want %x", got.Payload, f.Payload)
	}
}

func TestFrameRoundTripVLAN(t *testing.T) {
	f := &Frame{
		Dst:       [6]byte{0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01},
		Src:       [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x43},
		EtherType: EtherTypeSV,
		VLAN:      &VLANTag{Priority: 4, DEI: true, VID: 0x123},
		Payload:   []byte{0x60, 0x00},
	}
	got, err := ParseFrame(f.Marshal())
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if got.VLAN == nil {
		t.Fatal("VLAN tag lost")
	}
	if *got.VLAN != *f.VLAN {
		t.Fatalf("VLAN mismatch: got %+v, want %+v", *got.VLAN, *f.VLAN)
	}
	if got.EtherType != EtherTypeSV || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("frame mismatch: got %+v, want %+v", got, f)
	}
}

func TestFrameMarshalGolden(t *testing.T) {
	f := &Frame{
		Dst:       [6]byte{0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01},
		Src:       [6]byte{0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		EtherType: EtherTypeGOOSE,
		VLAN:      &VLANTag{Priority: 4, VID: 5},
		Payload:   []byte{0x61, 0x00},
	}
	want := []byte{
		0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01, // dst
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // src
		0x81, 0x00, 0x80, 0x05, // 802.1Q, PCP 4, VID 5
		0x88, 0xb8, // GOOSE
		0x61, 0x00, // payload
	}
	if got := f.Marshal(); !bytes.Equal(got, want) {
		t.Fatalf("Marshal: got %x, want %x", got, want)
	}
}

func TestParseFrameErrors(t *testing.T) {
	for _, tc := range [][]byte{
		nil,
		make([]byte, 13), // short header
		append(make([]byte, 12), 0x81, 0x00, 0x00),             // truncated VLAN
		append(make([]byte, 12), 0x81, 0x00, 0x00, 0x05, 0x88), // no inner EtherType
	} {
		if _, err := ParseFrame(tc); err == nil {
			t.Errorf("ParseFrame(%x): expected error", tc)
		}
	}
}
