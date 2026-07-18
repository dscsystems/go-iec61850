// Package cotp implements the ISO 8073 / X.224 Connection-Oriented
// Transport Protocol class 0, as profiled by RFC 1006 for MMS. It
// provides connection establishment (CR/CC) and data transfer (DT) with
// reassembly of the TPDU segments produced by the class-0 EOT mechanism.
package cotp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/dscsystems/go-iec61850/internal/osi/tpkt"
)

// TPDU type codes (high nibble of the type octet).
const (
	tpduCR = 0xe0 // connection request
	tpduCC = 0xd0 // connection confirm
	tpduDR = 0x80 // disconnect request
	tpduDT = 0xf0 // data
	tpduER = 0x70 // error
)

// Parameter codes.
const (
	paramTPDUSize = 0xc0
	paramSrcTSAP  = 0xc1
	paramDstTSAP  = 0xc2
)

// eot is the end-of-transmission flag in a DT TPDU's number octet.
const eot = 0x80

// Conn is a COTP class-0 connection over a byte stream (typically a TCP
// or TLS connection). It is not safe for concurrent use by multiple
// senders; callers serialise sends, and a single reader drains it.
type Conn struct {
	rw      io.ReadWriteCloser
	maxTPDU int
	srcRef  uint16
	dstRef  uint16
	srcTSAP []byte
	dstTSAP []byte
	readBuf bytes.Buffer
}

// Options configures a COTP connection.
type Options struct {
	// SrcTSAP and DstTSAP are the calling/called transport selectors. For
	// MMS these are conventionally 2 octets {0,1} / {0,1}; libiec61850
	// uses {0,1}.
	SrcTSAP []byte
	DstTSAP []byte
	// TPDUSize is the negotiated maximum TPDU size as the power-of-two
	// code (e.g. 10 = 1024). Default 10.
	TPDUSizeCode uint8
}

// DefaultTSAP is the transport selector used by common 61850 stacks.
var DefaultTSAP = []byte{0x00, 0x01}

// Connect performs the CR/CC handshake as the calling side.
func Connect(rw io.ReadWriteCloser, opts Options) (*Conn, error) {
	if opts.SrcTSAP == nil {
		opts.SrcTSAP = DefaultTSAP
	}
	if opts.DstTSAP == nil {
		opts.DstTSAP = DefaultTSAP
	}
	if opts.TPDUSizeCode == 0 {
		opts.TPDUSizeCode = 10 // 1024 octets
	}
	c := &Conn{
		rw:      rw,
		srcRef:  1,
		srcTSAP: opts.SrcTSAP,
		dstTSAP: opts.DstTSAP,
		maxTPDU: 1 << opts.TPDUSizeCode,
	}
	if err := c.sendCR(opts.TPDUSizeCode); err != nil {
		return nil, err
	}
	if err := c.recvCC(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Conn) sendCR(sizeCode uint8) error {
	var b bytes.Buffer
	b.WriteByte(0) // LI placeholder, patched below
	b.WriteByte(tpduCR)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], 0) // destRef
	b.Write(ref[:])
	binary.BigEndian.PutUint16(ref[:], c.srcRef)
	b.Write(ref[:])
	b.WriteByte(0) // class 0, no options
	writeParam(&b, paramTPDUSize, []byte{sizeCode})
	writeParam(&b, paramSrcTSAP, c.srcTSAP)
	writeParam(&b, paramDstTSAP, c.dstTSAP)
	tpdu := b.Bytes()
	tpdu[0] = byte(len(tpdu) - 1) // LI covers everything after the LI octet
	return c.writeTPDU(tpdu)
}

func (c *Conn) recvCC() error {
	tpdu, err := tpkt.ReadPacket(c.rw)
	if err != nil {
		return err
	}
	_, typ, body, err := parseHeader(tpdu)
	if err != nil {
		return err
	}
	if typ != tpduCC {
		if typ == tpduDR {
			return fmt.Errorf("cotp: connection refused (DR)")
		}
		return fmt.Errorf("cotp: expected CC, got type 0x%02x", typ)
	}
	// Fixed part of CC: destRef, srcRef, class. Parameters follow.
	if len(body) < 5 {
		return fmt.Errorf("cotp: short CC")
	}
	// body = destRef(2) srcRef(2) class(1) params...; the peer's srcRef is
	// our destination reference.
	c.dstRef = binary.BigEndian.Uint16(body[2:4])
	if len(body) > 5 {
		c.parseParams(body[5:])
	}
	return nil
}

func (c *Conn) parseParams(params []byte) {
	for len(params) >= 2 {
		code := params[0]
		plen := int(params[1])
		if 2+plen > len(params) {
			return
		}
		val := params[2 : 2+plen]
		if code == paramTPDUSize && plen == 1 {
			if sz := 1 << val[0]; sz > 0 && sz < c.maxTPDU {
				c.maxTPDU = sz
			}
		}
		params = params[2+plen:]
	}
}

// Send transmits a complete transport service data unit, segmenting it
// into class-0 DT TPDUs no larger than the negotiated size.
func (c *Conn) Send(tsdu []byte) error {
	// DT header for class 0 is 3 octets (LI, type, number); the payload
	// per TPDU is maxTPDU minus that header.
	maxData := c.maxTPDU - 3
	if maxData <= 0 {
		maxData = 1024 - 3
	}
	for off := 0; off < len(tsdu) || off == 0; {
		end := off + maxData
		last := false
		if end >= len(tsdu) {
			end = len(tsdu)
			last = true
		}
		var b bytes.Buffer
		num := byte(0)
		if last {
			num |= eot
		}
		b.WriteByte(2) // LI: length of header after LI = type + number
		b.WriteByte(tpduDT)
		b.WriteByte(num)
		b.Write(tsdu[off:end])
		if err := c.writeTPDU(b.Bytes()); err != nil {
			return err
		}
		off = end
		if last {
			break
		}
	}
	return nil
}

// Receive reads DT TPDUs until EOT and returns the reassembled TSDU.
func (c *Conn) Receive() ([]byte, error) {
	c.readBuf.Reset()
	for {
		tpdu, err := tpkt.ReadPacket(c.rw)
		if err != nil {
			return nil, err
		}
		li, typ, body, err := parseHeader(tpdu)
		if err != nil {
			return nil, err
		}
		switch typ {
		case tpduDT:
			if len(body) < 1 {
				return nil, fmt.Errorf("cotp: short DT")
			}
			num := body[0]
			data := tpdu[1+li:]
			c.readBuf.Write(data)
			if num&eot != 0 {
				out := make([]byte, c.readBuf.Len())
				copy(out, c.readBuf.Bytes())
				return out, nil
			}
		case tpduDR:
			return nil, io.EOF
		case tpduER:
			return nil, fmt.Errorf("cotp: received ER TPDU")
		default:
			return nil, fmt.Errorf("cotp: unexpected TPDU type 0x%02x", typ)
		}
	}
}

// Close closes the underlying stream.
func (c *Conn) Close() error { return c.rw.Close() }

// writeTPDU frames a fully-formed COTP TPDU (LI octet already set) as a
// TPKT and writes it.
func (c *Conn) writeTPDU(tpdu []byte) error {
	return tpkt.WritePacket(c.rw, tpdu)
}

func writeParam(b *bytes.Buffer, code byte, val []byte) {
	b.WriteByte(code)
	b.WriteByte(byte(len(val)))
	b.Write(val)
}

// parseHeader splits a COTP TPDU into its length indicator, type and the
// header body (the octets after the type, within the header). It returns
// li = value of the LI octet.
func parseHeader(tpdu []byte) (li int, typ byte, body []byte, err error) {
	if len(tpdu) < 2 {
		return 0, 0, nil, fmt.Errorf("cotp: truncated TPDU")
	}
	li = int(tpdu[0])
	if li == 0 || 1+li > len(tpdu) {
		return 0, 0, nil, fmt.Errorf("cotp: bad LI %d (len %d)", li, len(tpdu))
	}
	typ = tpdu[1] & 0xf0
	// body is the header content after the type octet up to end of header.
	body = tpdu[2 : 1+li]
	return li, typ, body, nil
}
