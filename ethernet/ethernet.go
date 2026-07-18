// Package ethernet provides the raw layer-2 access used by the GOOSE and
// Sampled Values transports: an Interface abstraction over a network
// device, plus pure frame marshalling helpers that are testable without
// a socket.
package ethernet

import (
	"encoding/binary"
	"fmt"
)

// EtherType values used by IEC 61850 layer-2 protocols.
const (
	EtherTypeGOOSE uint16 = 0x88b8
	EtherTypeSV    uint16 = 0x88ba

	etherTypeVLAN uint16 = 0x8100
)

// VLANTag is an IEEE 802.1Q tag.
type VLANTag struct {
	Priority uint8  // PCP, 0..7
	DEI      bool   // drop eligible indicator
	VID      uint16 // VLAN identifier, 0..4095
}

// Frame is an Ethernet II frame with an optional single 802.1Q tag.
type Frame struct {
	Src, Dst  [6]byte
	EtherType uint16
	VLAN      *VLANTag
	Payload   []byte
}

// Interface is a raw layer-2 endpoint able to send and receive frames.
// ReadFrame blocks until a frame arrives, an error occurs or the
// interface is closed; implementations must make Close unblock a
// concurrent ReadFrame.
type Interface interface {
	WriteFrame(*Frame) error
	ReadFrame() (*Frame, error)
	Close() error
}

// Marshal serialises the frame, including the 802.1Q tag when present.
func (f *Frame) Marshal() []byte {
	n := 14 + len(f.Payload)
	if f.VLAN != nil {
		n += 4
	}
	b := make([]byte, 0, n)
	b = append(b, f.Dst[:]...)
	b = append(b, f.Src[:]...)
	if f.VLAN != nil {
		tci := uint16(f.VLAN.Priority&7) << 13
		if f.VLAN.DEI {
			tci |= 1 << 12
		}
		tci |= f.VLAN.VID & 0x0fff
		b = append(b, byte(etherTypeVLAN>>8), byte(etherTypeVLAN&0xff), byte(tci>>8), byte(tci))
	}
	b = append(b, byte(f.EtherType>>8), byte(f.EtherType))
	return append(b, f.Payload...)
}

// ParseFrame parses an Ethernet II frame with an optional single 802.1Q
// tag. The returned Payload aliases b; callers that retain it past the
// lifetime of the buffer must copy.
func ParseFrame(b []byte) (*Frame, error) {
	if len(b) < 14 {
		return nil, fmt.Errorf("ethernet: frame of %d octets too short", len(b))
	}
	f := &Frame{}
	copy(f.Dst[:], b[0:6])
	copy(f.Src[:], b[6:12])
	et := binary.BigEndian.Uint16(b[12:14])
	off := 14
	if et == etherTypeVLAN {
		if len(b) < 18 {
			return nil, fmt.Errorf("ethernet: 802.1Q frame of %d octets too short", len(b))
		}
		tci := binary.BigEndian.Uint16(b[14:16])
		f.VLAN = &VLANTag{
			Priority: uint8(tci >> 13),
			DEI:      tci&(1<<12) != 0,
			VID:      tci & 0x0fff,
		}
		et = binary.BigEndian.Uint16(b[16:18])
		off = 18
	}
	f.EtherType = et
	f.Payload = b[off:]
	return f, nil
}

// htons converts a 16-bit value from host to network byte order, as
// required by AF_PACKET protocol fields.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
