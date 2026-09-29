package gdoi

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ISAKMP payload types (RFC 2408 3.1, RFC 6407 5).
const (
	pNone     = 0
	pSA       = 1
	pProposal = 2
	pTrans    = 3
	pKE       = 4
	pID       = 5
	pCert     = 6
	pCertReq  = 7
	pHash     = 8
	pSig      = 9
	pNonce    = 10
	pNotify   = 11
	pDelete   = 12
	pVendorID = 13
	pSAK      = 15
	pSAT      = 16
	pKD       = 17
	pSEQ      = 18
	pGAP      = 22
)

// Exchange types.
const (
	xchgMain = 2  // ISAKMP Identity Protection (IKE Main Mode)
	xchgInfo = 5  // Informational
	xchgPull = 32 // GDOI GROUPKEY-PULL
)

const (
	isakmpVersion = 0x10 // major 1, minor 0
	flagEncrypted = 0x01
	headerLen     = 28
	doiGDOI       = 2 // RFC 6407 2.1
	sitIdentity   = 1 // SIT_IDENTITY_ONLY
	protoISAKMP   = 1
	transKeyIKE   = 1
	protoIEC61850 = 3 // GDOI_PROTO_IEC_61850, RFC 8052
	kdTypeTEK     = 1
)

// maxMessage bounds a message the codec accepts: an ISAKMP message fits a
// UDP datagram.
const maxMessage = 65535

var errMalformed = errors.New("gdoi: malformed ISAKMP message")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errMalformed, fmt.Sprintf(format, args...))
}

// header is the fixed ISAKMP header.
type header struct {
	ICookie, RCookie [8]byte
	Next             byte
	Exchange         byte
	Flags            byte
	MsgID            uint32
	Length           uint32
}

func (h *header) marshal(b []byte) []byte {
	b = append(b, h.ICookie[:]...)
	b = append(b, h.RCookie[:]...)
	b = append(b, h.Next, isakmpVersion, h.Exchange, h.Flags)
	b = binary.BigEndian.AppendUint32(b, h.MsgID)
	return binary.BigEndian.AppendUint32(b, h.Length)
}

func parseHeader(b []byte) (*header, error) {
	if len(b) < headerLen {
		return nil, malformed("%d octets, shorter than the header", len(b))
	}
	h := &header{}
	copy(h.ICookie[:], b[0:8])
	copy(h.RCookie[:], b[8:16])
	h.Next = b[16]
	if b[17]>>4 != 1 {
		return nil, malformed("ISAKMP major version %d", b[17]>>4)
	}
	h.Exchange, h.Flags = b[18], b[19]
	h.MsgID = binary.BigEndian.Uint32(b[20:24])
	h.Length = binary.BigEndian.Uint32(b[24:28])
	if h.Length < headerLen || int(h.Length) > len(b) || h.Length > maxMessage {
		return nil, malformed("length %d for %d octets", h.Length, len(b))
	}
	return h, nil
}

// payload is one generic payload: its type and body (after the 4-octet
// generic header). raw is the whole payload, header included, as it was
// on the wire, which HASH computations cover.
type payload struct {
	Type byte
	Body []byte
	raw  []byte
}

// encodeChain encodes payloads as a chain: each generic header names the
// type of the payload after it. next is the type of the payload that
// follows the chain (0 at the end of a message).
func encodeChain(ps []payload, next byte) []byte {
	var b []byte
	for i, p := range ps {
		n := next
		if i+1 < len(ps) {
			n = ps[i+1].Type
		}
		b = append(b, n, 0)
		b = binary.BigEndian.AppendUint16(b, uint16(4+len(p.Body)))
		b = append(b, p.Body...)
	}
	return b
}

// parseChain walks a payload chain starting with type first, until a
// payload names no successor. It returns the payloads and the octets the
// chain occupies; what follows (padding) is not part of it.
func parseChain(b []byte, first byte) ([]payload, int, error) {
	var ps []payload
	off, t := 0, first
	for t != pNone {
		if len(b)-off < 4 {
			return nil, 0, malformed("truncated payload header")
		}
		next := b[off]
		n := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		if n < 4 || n > len(b)-off {
			return nil, 0, malformed("payload of type %d claims %d octets, %d remain", t, n, len(b)-off)
		}
		ps = append(ps, payload{Type: t, Body: b[off+4 : off+n], raw: b[off : off+n]})
		off += n
		t = next
		if len(ps) > 64 {
			return nil, 0, malformed("more than 64 payloads")
		}
	}
	return ps, off, nil
}

// find returns the first payload of type t.
func find(ps []payload, t byte) (payload, bool) {
	for _, p := range ps {
		if p.Type == t {
			return p, true
		}
	}
	return payload{}, false
}

// attribute is an ISAKMP data attribute (RFC 2408 3.3): basic (TV) when
// the value fits 16 bits and the attribute type allows it, variable (TLV)
// otherwise.
type attribute struct {
	Type  uint16
	Value []byte // big-endian
	Basic bool
}

func basicAttr(t uint16, v uint16) attribute {
	return attribute{Type: t, Value: []byte{byte(v >> 8), byte(v)}, Basic: true}
}

func varAttr(t uint16, v []byte) attribute { return attribute{Type: t, Value: v} }

// uintAttr is a variable attribute holding a 32-bit number.
func uintAttr(t uint16, v uint32) attribute {
	return attribute{Type: t, Value: binary.BigEndian.AppendUint32(nil, v)}
}

func (a attribute) uint() uint64 {
	var v uint64
	for _, c := range a.Value {
		v = v<<8 | uint64(c)
	}
	return v
}

func encodeAttrs(as []attribute) []byte {
	var b []byte
	for _, a := range as {
		if a.Basic {
			b = binary.BigEndian.AppendUint16(b, 0x8000|a.Type)
			b = append(b, a.Value[len(a.Value)-2:]...)
			continue
		}
		b = binary.BigEndian.AppendUint16(b, a.Type&0x7fff)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.Value)))
		b = append(b, a.Value...)
	}
	return b
}

func parseAttrs(b []byte) ([]attribute, error) {
	var as []attribute
	for off := 0; off < len(b); {
		if len(b)-off < 4 {
			return nil, malformed("truncated attribute")
		}
		t := binary.BigEndian.Uint16(b[off:])
		if t&0x8000 != 0 {
			as = append(as, attribute{Type: t & 0x7fff, Value: b[off+2 : off+4], Basic: true})
			off += 4
			continue
		}
		n := int(binary.BigEndian.Uint16(b[off+2:]))
		if n > len(b)-off-4 {
			return nil, malformed("attribute %d of %d octets, %d remain", t, n, len(b)-off-4)
		}
		as = append(as, attribute{Type: t, Value: b[off+4 : off+4+n]})
		off += 4 + n
	}
	return as, nil
}

func attrByType(as []attribute, t uint16) (attribute, bool) {
	for _, a := range as {
		if a.Type == t {
			return a, true
		}
	}
	return attribute{}, false
}

// Identification types (RFC 2407 4.6.2.1, RFC 8052 4).
const (
	IDIPv4Addr  = 1
	IDFQDN      = 2
	IDUserFQDN  = 3
	IDIPv6Addr  = 5
	IDDERASN1DN = 9
	IDKeyID     = 11
	IDOID       = 13
)

// idPayload is an identification payload body: type, three octets of
// DOI-specific data (protocol and port in phase 1, zero in GDOI), data.
type idPayload struct {
	Type byte
	Data []byte
}

func (id idPayload) body() []byte {
	return append([]byte{id.Type, 0, 0, 0}, id.Data...)
}

func parseID(b []byte) (idPayload, error) {
	if len(b) < 4 {
		return idPayload{}, malformed("identification of %d octets", len(b))
	}
	return idPayload{Type: b[0], Data: b[4:]}, nil
}

// notify builds a Notification payload body (RFC 2408 3.14) with no SPI.
func notify(doi uint32, typ uint16, data []byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, doi)
	b = append(b, protoISAKMP, 0)
	b = binary.BigEndian.AppendUint16(b, typ)
	return append(b, data...)
}

// Notify message types used (RFC 2408 3.14.1).
const (
	notifyInvalidPayload   = 1
	notifyNoProposalChosen = 14
	notifyInvalidIDInfo    = 18
	notifyInvalidCert      = 19
	notifyInvalidHashInfo  = 23
	notifyAuthFailed       = 24
	notifyInvalidSignature = 25
)

func notifyName(t uint16) string {
	switch t {
	case notifyInvalidPayload:
		return "INVALID-PAYLOAD-TYPE"
	case notifyNoProposalChosen:
		return "NO-PROPOSAL-CHOSEN"
	case notifyInvalidIDInfo:
		return "INVALID-ID-INFORMATION"
	case notifyInvalidCert:
		return "INVALID-CERTIFICATE"
	case notifyInvalidHashInfo:
		return "INVALID-HASH-INFORMATION"
	case notifyAuthFailed:
		return "AUTHENTICATION-FAILED"
	case notifyInvalidSignature:
		return "INVALID-SIGNATURE"
	}
	return fmt.Sprintf("notify %d", t)
}

// NotifyError is a notification the peer sent refusing the exchange.
type NotifyError struct {
	Type uint16
}

func (e *NotifyError) Error() string {
	return "gdoi: peer refused the exchange: " + notifyName(e.Type)
}

func parseNotify(b []byte) (*NotifyError, error) {
	if len(b) < 8 {
		return nil, malformed("notification of %d octets", len(b))
	}
	return &NotifyError{Type: binary.BigEndian.Uint16(b[6:8])}, nil
}
