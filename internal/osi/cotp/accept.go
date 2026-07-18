package cotp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/dscsystems/go-iec61850/internal/osi/tpkt"
)

// Accept performs the CR/CC handshake as the called (server) side: it
// reads the peer's CR, echoes the negotiated TPDU size and TSAPs, and
// returns an established connection.
func Accept(rw io.ReadWriteCloser) (*Conn, error) {
	tpduBytes, err := tpkt.ReadPacket(rw)
	if err != nil {
		return nil, err
	}
	li, typ, body, err := parseHeader(tpduBytes)
	if err != nil {
		return nil, err
	}
	if typ != tpduCR {
		return nil, fmt.Errorf("cotp: expected CR, got type 0x%02x", typ)
	}
	c := &Conn{rw: rw, srcRef: 1, maxTPDU: 1024}
	// body = destRef(2) srcRef(2) class(1) params...
	if len(body) >= 4 {
		c.dstRef = binary.BigEndian.Uint16(body[2:4])
	}
	sizeCode := uint8(10)
	if len(body) > 5 {
		params := body[5:]
		for len(params) >= 2 {
			code := params[0]
			plen := int(params[1])
			if 2+plen > len(params) {
				break
			}
			val := params[2 : 2+plen]
			switch {
			case code == paramTPDUSize && plen == 1:
				sizeCode = val[0]
				c.maxTPDU = 1 << sizeCode
			case code == paramSrcTSAP:
				c.dstTSAP = append([]byte(nil), val...)
			case code == paramDstTSAP:
				c.srcTSAP = append([]byte(nil), val...)
			}
			params = params[2+plen:]
		}
	}
	_ = li
	if err := c.sendCC(sizeCode); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Conn) sendCC(sizeCode uint8) error {
	var b bytes.Buffer
	b.WriteByte(0) // LI placeholder
	b.WriteByte(tpduCC)
	var ref [2]byte
	binary.BigEndian.PutUint16(ref[:], c.dstRef) // echo peer's srcRef as destRef
	b.Write(ref[:])
	binary.BigEndian.PutUint16(ref[:], c.srcRef)
	b.Write(ref[:])
	b.WriteByte(0) // class 0
	writeParam(&b, paramTPDUSize, []byte{sizeCode})
	if c.srcTSAP != nil {
		writeParam(&b, paramSrcTSAP, c.srcTSAP)
	}
	if c.dstTSAP != nil {
		writeParam(&b, paramDstTSAP, c.dstTSAP)
	}
	tpdu := b.Bytes()
	tpdu[0] = byte(len(tpdu) - 1)
	return c.writeTPDU(tpdu)
}
