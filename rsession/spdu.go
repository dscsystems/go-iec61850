package rsession

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// SessionID is the session identifier (SI) of an SPDU: what kind of
// application data it carries.
type SessionID uint8

// The session identifiers of IEC 61850-90-5.
const (
	SITunnelled  SessionID = 0xA0
	SIGOOSE      SessionID = 0xA1
	SISV         SessionID = 0xA2
	SIManagement SessionID = 0xA3
)

func (s SessionID) String() string {
	switch s {
	case SITunnelled:
		return "tunnelled"
	case SIGOOSE:
		return "GOOSE"
	case SISV:
		return "SV"
	case SIManagement:
		return "management"
	}
	return fmt.Sprintf("SessionID(%#02x)", uint8(s))
}

// PayloadType tags one application PDU inside the session user data.
type PayloadType uint8

// The payload types: the session identifier's low nibble with the high
// bit set.
const (
	PayloadTunnelled  PayloadType = 0x80
	PayloadGOOSE      PayloadType = 0x81
	PayloadSV         PayloadType = 0x82
	PayloadManagement PayloadType = 0x83
)

// Payload is one application PDU: a goosePdu or savPdu without the
// layer-2 header, whose APPID and simulation flag the session carries
// instead.
type Payload struct {
	Type       PayloadType
	Simulation bool
	AppID      uint16
	APDU       []byte
}

// SPDU is a decoded session protocol data unit.
type SPDU struct {
	SI      SessionID
	Number  uint32 // increments with every SPDU a sender sends
	Version uint16 // protocol version, 1 or 2
	// KeyID identifies the key the SPDU is secured with; 0 when it is not
	// secured.
	KeyID            uint32
	TimeOfCurrentKey uint32
	TimeToNextKey    int16
	Payloads         []Payload

	// Signed and Encrypted say how the SPDU was protected. They are set by
	// Unmarshal and ignored by Marshal, which protects an SPDU as its key
	// says.
	Signed, Encrypted bool
}

// Wire constants.
const (
	cltpLI        = 0x01 // connectionless transport: length indicator
	cltpUD        = 0x40 // connectionless transport: unit data TPDU
	tagCommon     = 0x80 // common session header parameter
	commonLen     = 10   // SPDU length, SPDU number, version
	tagSignature  = 0x85 // MAC or GCM tag after the user data
	tagPadding    = 0xAF // padding before the signature
	elementHeader = 6    // payload type, simulation, APPID, APDU length
	gcmIVLen      = 12
	gcmTagLen     = 16
)

// Errors of decoding and verification. They are wrapped with detail.
var (
	ErrMalformed       = errors.New("rsession: malformed SPDU")
	ErrVersion         = errors.New("rsession: unsupported protocol version")
	ErrUnknownKey      = errors.New("rsession: unknown key")
	ErrAlgorithm       = errors.New("rsession: security algorithms do not match the key")
	ErrAuthentication  = errors.New("rsession: authentication failed")
	ErrUnsecured       = errors.New("rsession: unsecured SPDU")
	ErrNoActiveKey     = errors.New("rsession: no active key")
	ErrVersion1Encrypt = errors.New("rsession: protocol version 1 carries no encryption")
)

// Marshal encodes an SPDU secured with key: signed when the key has an
// authentication algorithm, encrypted when it has an encryption one, and
// neither when key is nil. The version is s.Version (2 when 0);
// s.KeyID, the key times and the Signed and Encrypted flags are taken from
// key, not from s. random supplies the GCM initialisation vector (nil
// means crypto/rand).
//
// The layout, in network byte order:
//
//	01 40                          connectionless transport header
//	SI LI                          session identifier, session header length
//	80 0A len(4) number(4) ver(2)  common session header
//	security information:
//	  v1: timeOfCurrentKey(4) timeToNextKey(2) sec(1) sig(1) keyID(4)
//	  v2: timeOfCurrentKey(4) timeToNextKey(2) keyID(4) ivLen(1) iv
//	payload length(4)
//	{ type(1) simulation(1) APPID(2) APDU length(2) APDU }...
//	85 len MAC                     when signed or encrypted
//
// A MAC covers everything before its tag. Encryption covers the payload
// elements, with everything before them as additional authenticated data,
// and puts the GCM tag in the trailer.
func Marshal(s *SPDU, key *Key, random io.Reader) ([]byte, error) {
	version := s.Version
	if version == 0 {
		version = 2
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("%w: %d", ErrVersion, version)
	}
	if key != nil {
		if err := key.validate(); err != nil {
			return nil, err
		}
		if version == 1 && key.Sec != SecNone {
			return nil, ErrVersion1Encrypt
		}
	}
	var iv []byte
	if key != nil && key.Sec != SecNone {
		iv = make([]byte, gcmIVLen)
		if random == nil {
			random = rand.Reader
		}
		if _, err := io.ReadFull(random, iv); err != nil {
			return nil, fmt.Errorf("rsession: initialisation vector: %w", err)
		}
	}

	userLen := 0
	for _, p := range s.Payloads {
		if len(p.APDU) > 0xFFFF {
			return nil, fmt.Errorf("rsession: APDU of %d octets exceeds the 16-bit length", len(p.APDU))
		}
		userLen += elementHeader + len(p.APDU)
	}
	secInfoLen := 12
	if version == 2 {
		secInfoLen = 11 + len(iv)
	}
	trailer := 0
	if key != nil {
		if key.Sec != SecNone {
			trailer = 2 + gcmTagLen
		} else {
			trailer = 2 + key.Sig.macLen()
		}
	}
	sessionHdrLen := 2 + commonLen + secInfoLen
	total := 2 + 2 + sessionHdrLen + 4 + userLen + trailer
	b := make([]byte, 0, total)

	b = append(b, cltpLI, cltpUD, byte(s.SI), byte(sessionHdrLen), tagCommon, commonLen)
	// The SPDU length counts the octets that follow it.
	b = binary.BigEndian.AppendUint32(b, uint32(total-len(b)-4))
	b = binary.BigEndian.AppendUint32(b, s.Number)
	b = binary.BigEndian.AppendUint16(b, version)
	var keyID, tock uint32
	var ttnk int16
	if key != nil {
		keyID, tock, ttnk = key.ID, key.TimeOfCurrentKey, key.TimeToNextKey
	}
	b = binary.BigEndian.AppendUint32(b, tock)
	b = binary.BigEndian.AppendUint16(b, uint16(ttnk))
	if version == 1 {
		var sec, sig byte
		if key != nil {
			sec, sig = byte(key.Sec), byte(key.Sig)
		}
		b = append(b, sec, sig)
		b = binary.BigEndian.AppendUint32(b, keyID)
	} else {
		b = binary.BigEndian.AppendUint32(b, keyID)
		b = append(b, byte(len(iv)))
		b = append(b, iv...)
	}
	b = binary.BigEndian.AppendUint32(b, uint32(userLen))
	userStart := len(b)
	for _, p := range s.Payloads {
		sim := byte(0)
		if p.Simulation {
			sim = 1
		}
		b = append(b, byte(p.Type), sim, byte(p.AppID>>8), byte(p.AppID))
		b = binary.BigEndian.AppendUint16(b, uint16(len(p.APDU)))
		b = append(b, p.APDU...)
	}

	switch {
	case key == nil:
	case key.Sec != SecNone:
		aead, err := newGCM(key)
		if err != nil {
			return nil, err
		}
		sealed := aead.Seal(nil, iv, b[userStart:], b[:userStart])
		ct, tag := sealed[:len(sealed)-gcmTagLen], sealed[len(sealed)-gcmTagLen:]
		b = append(b[:userStart], ct...)
		b = append(b, tagSignature, gcmTagLen)
		b = append(b, tag...)
	default:
		mac := computeMAC(key, b)
		b = append(b, tagSignature, byte(len(mac)))
		b = append(b, mac...)
	}
	return b, nil
}

// Unmarshal decodes and verifies an SPDU. A secured SPDU is checked with
// the key it names, which keys must hold: its MAC or GCM tag must verify,
// and in version 1 the algorithms it declares must be the key's. An
// unsecured SPDU (key ID 0) is decoded and returned as it is: whether to
// accept one is the caller's policy (Session refuses them unless
// Config.AllowUnsecured).
//
// The session and common header lengths and the SPDU length are not
// relied on, since implementations disagree on what they count; the
// fields are read in order and every length that delimits data is bounds
// checked. An element whose APDU length exceeds what remains by exactly
// two octets is accepted, as libiec61850 writes one (it counts the length
// field itself).
//
// The payloads alias b.
func Unmarshal(b []byte, keys *KeyStore) (*SPDU, error) {
	r := reader{b: b}
	if r.u8() != cltpLI || r.u8() != cltpUD {
		return nil, fmt.Errorf("%w: not a connectionless transport unit", ErrMalformed)
	}
	s := &SPDU{SI: SessionID(r.u8())}
	r.u8() // session header length
	if r.u8() != tagCommon {
		return nil, fmt.Errorf("%w: no common session header", ErrMalformed)
	}
	r.u8()  // common header length
	r.u32() // SPDU length
	s.Number = r.u32()
	s.Version = r.u16()
	s.TimeOfCurrentKey = r.u32()
	s.TimeToNextKey = int16(r.u16())
	if r.short {
		return nil, fmt.Errorf("%w: truncated session header", ErrMalformed)
	}

	var key *Key
	var iv []byte
	switch s.Version {
	case 1:
		sec, sig := SecAlgorithm(r.u8()), SigAlgorithm(r.u8())
		s.KeyID = r.u32()
		if r.short {
			return nil, fmt.Errorf("%w: truncated security information", ErrMalformed)
		}
		if s.KeyID == 0 {
			if sec != SecNone || sig != SigNone {
				return nil, fmt.Errorf("%w: algorithms without a key", ErrMalformed)
			}
			break
		}
		if key = lookupKey(keys, s.KeyID); key == nil {
			return nil, fmt.Errorf("%w: %d", ErrUnknownKey, s.KeyID)
		}
		// The declared algorithms must be the key's, or a forged header
		// could ask for a weaker check than the key is used with.
		if sec != key.Sec || sig != key.Sig {
			return nil, fmt.Errorf("%w: SPDU declares %v/%v, key %d is %v/%v",
				ErrAlgorithm, sec, sig, s.KeyID, key.Sec, key.Sig)
		}
	case 2:
		s.KeyID = r.u32()
		ivLen := int(r.u8())
		iv = r.bytes(ivLen)
		if r.short {
			return nil, fmt.Errorf("%w: truncated security information", ErrMalformed)
		}
		if s.KeyID == 0 {
			break
		}
		if key = lookupKey(keys, s.KeyID); key == nil {
			return nil, fmt.Errorf("%w: %d", ErrUnknownKey, s.KeyID)
		}
		if key.Sec != SecNone && ivLen != gcmIVLen {
			return nil, fmt.Errorf("%w: %d-octet initialisation vector, GCM uses %d", ErrMalformed, ivLen, gcmIVLen)
		}
	default:
		return nil, fmt.Errorf("%w: %d", ErrVersion, s.Version)
	}

	ul := r.u32()
	if r.short || uint64(ul) > uint64(len(b)-r.off) {
		return nil, fmt.Errorf("%w: payload length %d exceeds the SPDU", ErrMalformed, ul)
	}
	userLen := int(ul)
	userStart := r.off
	userEnd := userStart + userLen
	user := b[userStart:userEnd]

	if key == nil && userEnd != len(b) {
		// Nothing follows the user data of an unsecured SPDU. A trailer
		// here is a secured SPDU whose key identifier was cleared, and is
		// refused as such rather than read as unsecured.
		return nil, fmt.Errorf("%w: %d octets after the user data of an unsecured SPDU", ErrMalformed, len(b)-userEnd)
	}
	if key != nil {
		trailer := b[userEnd:]
		// Padding may precede the trailer.
		if len(trailer) >= 2 && trailer[0] == tagPadding {
			n := 2 + int(trailer[1])
			if n > len(trailer) {
				return nil, fmt.Errorf("%w: truncated padding", ErrMalformed)
			}
			trailer = trailer[n:]
		}
		sigPos := len(b) - len(trailer)
		if len(trailer) < 2 || trailer[0] != tagSignature {
			return nil, fmt.Errorf("%w: no signature trailer", ErrAuthentication)
		}
		n := int(trailer[1])
		if 2+n > len(trailer) {
			return nil, fmt.Errorf("%w: truncated signature", ErrMalformed)
		}
		tag := trailer[2 : 2+n]
		if key.Sec != SecNone {
			if n != gcmTagLen {
				return nil, fmt.Errorf("%w: %d-octet GCM tag", ErrAuthentication, n)
			}
			aead, err := newGCM(key)
			if err != nil {
				return nil, err
			}
			sealed := make([]byte, 0, len(user)+gcmTagLen)
			sealed = append(append(sealed, user...), tag...)
			plain, err := aead.Open(nil, iv, sealed, b[:userStart])
			if err != nil {
				return nil, fmt.Errorf("%w: GCM tag does not verify", ErrAuthentication)
			}
			user = plain
			s.Encrypted = true
		} else {
			if n != key.Sig.macLen() {
				return nil, fmt.Errorf("%w: %d-octet MAC, %v is %d", ErrAuthentication, n, key.Sig, key.Sig.macLen())
			}
			if !hmac.Equal(tag, computeMAC(key, b[:sigPos])) {
				return nil, fmt.Errorf("%w: MAC does not verify", ErrAuthentication)
			}
			s.Signed = true
		}
	}

	for off := 0; off < len(user); {
		if len(user)-off < elementHeader {
			return nil, fmt.Errorf("%w: truncated payload element", ErrMalformed)
		}
		h := user[off : off+elementHeader]
		p := Payload{
			Type:       PayloadType(h[0]),
			Simulation: h[1] != 0,
			AppID:      binary.BigEndian.Uint16(h[2:4]),
		}
		n := int(binary.BigEndian.Uint16(h[4:6]))
		off += elementHeader
		rest := len(user) - off
		if n > rest {
			if n != rest+2 {
				return nil, fmt.Errorf("%w: APDU of %d octets, %d remain", ErrMalformed, n, rest)
			}
			n = rest
		}
		p.APDU = user[off : off+n]
		off += n
		s.Payloads = append(s.Payloads, p)
	}
	return s, nil
}

func lookupKey(keys *KeyStore, id uint32) *Key { return keys.lookup(id) }

func newGCM(key *Key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key.Material)
	if err != nil {
		return nil, fmt.Errorf("rsession: %w", err)
	}
	return cipher.NewGCM(block)
}

// computeMAC is the truncated HMAC of data under key.
func computeMAC(key *Key, data []byte) []byte {
	var h func() hash.Hash
	switch key.Sig {
	case SigHMACSHA3_80, SigHMACSHA3_128, SigHMACSHA3_256:
		h = func() hash.Hash { return sha3.New256() }
	default:
		h = sha256.New
	}
	m := hmac.New(h, key.Material)
	m.Write(data)
	return m.Sum(nil)[:key.Sig.macLen()]
}

// reader reads big-endian fields, recording a read past the end instead
// of panicking.
type reader struct {
	b     []byte
	off   int
	short bool
}

func (r *reader) bytes(n int) []byte {
	if r.short || n > len(r.b)-r.off {
		r.short = true
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

func (r *reader) u8() byte {
	if v := r.bytes(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.bytes(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.bytes(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}
