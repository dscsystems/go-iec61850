// Package tpkt implements RFC 1006 (ISO transport service on top of TCP),
// the framing layer beneath COTP for MMS over TCP port 102.
package tpkt

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Header is the 4-octet TPKT header: version(3), reserved(0), length(2).
const (
	headerLen = 4
	version   = 3
	// MaxPacket bounds a single TPKT to guard against hostile length
	// fields; 61850 payloads are far smaller.
	MaxPacket = 1 << 20
)

// WritePacket frames payload as a TPKT and writes it to w.
func WritePacket(w io.Writer, payload []byte) error {
	total := headerLen + len(payload)
	if total > MaxPacket {
		return fmt.Errorf("tpkt: packet of %d bytes exceeds max %d", total, MaxPacket)
	}
	var hdr [headerLen]byte
	hdr[0] = version
	binary.BigEndian.PutUint16(hdr[2:], uint16(total))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadPacket reads one TPKT from r and returns its payload (the COTP
// TPDU). It reads exactly one frame.
func ReadPacket(r io.Reader) ([]byte, error) {
	var hdr [headerLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != version {
		return nil, fmt.Errorf("tpkt: bad version %d", hdr[0])
	}
	total := int(binary.BigEndian.Uint16(hdr[2:]))
	if total < headerLen || total > MaxPacket {
		return nil, fmt.Errorf("tpkt: bad length %d", total)
	}
	payload := make([]byte, total-headerLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
