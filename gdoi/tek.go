package gdoi

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/dscsystems/go-iec61850/rsession"
)

// GroupID names a group: a 4-octet group identifier (ID_KEY_ID, which
// every GDOI implementation supports), or an OID with an optional
// OID-specific selector (ID_OID, RFC 8052), which IEC 62351-9 uses to name
// the GOOSE or sampled value stream a key protects. The OIDs are defined in
// IEC 62351-9, not here: the application passes the one its key server is
// configured with.
type GroupID struct {
	KeyID uint32
	OID   asn1.ObjectIdentifier
	// Selector is the OID-specific payload, DER encoded (a multicast
	// address, say); nil when the OID needs none.
	Selector []byte
}

func (g GroupID) String() string {
	if g.OID == nil {
		return fmt.Sprintf("group %d", g.KeyID)
	}
	if len(g.Selector) > 0 {
		return fmt.Sprintf("group %s [% x]", g.OID, g.Selector)
	}
	return "group " + g.OID.String()
}

// key is the group identity as a map key.
func (g GroupID) key() string {
	if g.OID == nil {
		return fmt.Sprintf("k%d", g.KeyID)
	}
	return "o" + g.OID.String() + "/" + string(g.Selector)
}

// id encodes the group as a GDOI identification payload.
func (g GroupID) id() (idPayload, error) {
	if g.OID == nil {
		return idPayload{Type: IDKeyID, Data: binary.BigEndian.AppendUint32(nil, g.KeyID)}, nil
	}
	data, err := oidAndSelector(g.OID, g.Selector)
	if err != nil {
		return idPayload{}, err
	}
	return idPayload{Type: IDOID, Data: data}, nil
}

// oidAndSelector encodes the OID Length, OID, OID-Specific Payload Length
// and OID-Specific Payload fields shared by the ID_OID identification data
// and the IEC 61850 SA TEK (RFC 8052 figures 2 and 4). The OID is its DER
// encoding, tag and length included.
func oidAndSelector(oid asn1.ObjectIdentifier, sel []byte) ([]byte, error) {
	der, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("gdoi: OID %v: %w", oid, err)
	}
	if len(der) > 255 || len(sel) > 0xffff {
		return nil, fmt.Errorf("gdoi: OID or selector too long")
	}
	b := append([]byte{byte(len(der))}, der...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(sel)))
	return append(b, sel...), nil
}

// parseOIDAndSelector reads the fields oidAndSelector writes and returns
// what follows them.
func parseOIDAndSelector(b []byte) (asn1.ObjectIdentifier, []byte, []byte, error) {
	if len(b) < 1 || int(b[0])+3 > len(b) {
		return nil, nil, nil, malformed("truncated OID")
	}
	n := int(b[0])
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(b[1:1+n], &oid)
	if err != nil || len(rest) != 0 {
		return nil, nil, nil, malformed("OID is not one DER object identifier")
	}
	b = b[1+n:]
	sl := int(binary.BigEndian.Uint16(b))
	if sl > len(b)-2 {
		return nil, nil, nil, malformed("selector of %d octets, %d remain", sl, len(b)-2)
	}
	var sel []byte
	if sl > 0 {
		sel = append([]byte(nil), b[2:2+sl]...)
	}
	return oid, sel, b[2+sl:], nil
}

func groupFromID(id idPayload) (GroupID, error) {
	switch id.Type {
	case IDKeyID:
		if len(id.Data) != 4 {
			return GroupID{}, malformed("ID_KEY_ID of %d octets", len(id.Data))
		}
		return GroupID{KeyID: binary.BigEndian.Uint32(id.Data)}, nil
	case IDOID:
		oid, sel, rest, err := parseOIDAndSelector(id.Data)
		if err != nil {
			return GroupID{}, err
		}
		if len(rest) != 0 {
			return GroupID{}, malformed("%d octets after the ID_OID selector", len(rest))
		}
		return GroupID{OID: oid, Selector: sel}, nil
	}
	return GroupID{}, malformed("group identification of type %d", id.Type)
}

// AuthAlg is an IEC 62351-9 authentication algorithm (RFC 8052 2.2.2).
type AuthAlg uint16

// EncAlg is an IEC 62351-9 confidentiality algorithm (RFC 8052 2.2.3).
type EncAlg uint16

// The algorithm values of the IANA registries RFC 8052 created.
const (
	AuthNone          AuthAlg = 1
	AuthHMACSHA256128 AuthAlg = 2
	AuthHMACSHA256    AuthAlg = 3
	AuthAESGMAC128    AuthAlg = 4
	AuthAESGMAC256    AuthAlg = 5

	EncNone      EncAlg = 1
	EncAESCBC128 EncAlg = 2
	EncAESCBC256 EncAlg = 3
	EncAESGCM128 EncAlg = 4
	EncAESGCM256 EncAlg = 5
)

func (a AuthAlg) String() string {
	switch a {
	case AuthNone:
		return "NONE"
	case AuthHMACSHA256128:
		return "HMAC-SHA256-128"
	case AuthHMACSHA256:
		return "HMAC-SHA256"
	case AuthAESGMAC128:
		return "AES-GMAC-128"
	case AuthAESGMAC256:
		return "AES-GMAC-256"
	}
	return fmt.Sprintf("AuthAlg(%d)", uint16(a))
}

func (e EncAlg) String() string {
	switch e {
	case EncNone:
		return "NONE"
	case EncAESCBC128:
		return "AES-CBC-128"
	case EncAESCBC256:
		return "AES-CBC-256"
	case EncAESGCM128:
		return "AES-GCM-128"
	case EncAESGCM256:
		return "AES-GCM-256"
	}
	return fmt.Sprintf("EncAlg(%d)", uint16(e))
}

// keyLen is the length of the keying material RFC 8052 2.3 gives each
// algorithm: the key, plus a 4-octet salt for GMAC and GCM. 0 for NONE,
// -1 for an unknown algorithm.
func (a AuthAlg) keyLen() int {
	switch a {
	case AuthNone:
		return 0
	case AuthHMACSHA256128, AuthHMACSHA256:
		return 32
	case AuthAESGMAC128:
		return 20
	case AuthAESGMAC256:
		return 36
	}
	return -1
}

func (e EncAlg) keyLen() int {
	switch e {
	case EncNone:
		return 0
	case EncAESCBC128:
		return 16
	case EncAESCBC256:
		return 32
	case EncAESGCM128:
		return 20
	case EncAESGCM256:
		return 36
	}
	return -1
}

func (e EncAlg) authenticated() bool { return e == EncAESGCM128 || e == EncAESGCM256 }

// SA TEK attributes (RFC 8052 2.2.4).
const (
	attrSAATD = 1 // SA Time Activation Delay, variable, seconds
	attrSAKDA = 2 // Key Delivery Assurance, basic, percent
)

// KD key packet attributes (RFC 6407 5.6.1).
const (
	attrTEKAlgorithmKey = 1
	attrTEKIntegrityKey = 2
)

// TEK is one traffic encryption key of a group with its policy: the
// traffic it protects (OID and selector), the SPI a receiver finds it by
// (the IEC 61850 key identifier), the algorithms, and the keying material.
type TEK struct {
	SPI      uint32
	OID      asn1.ObjectIdentifier
	Selector []byte
	Auth     AuthAlg
	Enc      EncAlg
	// Lifetime is how long the key has left when it is sent; 0 means it
	// does not expire. ActivationDelay is how long a member waits before
	// using it (SA_ATD), so a key can be distributed ahead of its use.
	Lifetime        time.Duration
	ActivationDelay time.Duration
	// KDA is the Key Delivery Assurance percentage (SA_KDA), -1 when the
	// policy has none.
	KDA int
	// AlgorithmKey is the confidentiality key (TEK_ALGORITHM_KEY) and
	// IntegrityKey the authentication key (TEK_INTEGRITY_KEY), in the
	// layout RFC 8052 2.3 gives: for GCM and GMAC, the AES key followed by
	// a 4-octet salt.
	AlgorithmKey []byte
	IntegrityKey []byte
}

// Errors of TEK policy.
var (
	ErrTEKPolicy      = errors.New("gdoi: TEK policy not allowed")
	ErrTEKUnsupported = errors.New("gdoi: TEK algorithm the session layer does not implement")
)

// checkPolicy validates the algorithm combination and key lengths RFC
// 8052 requires.
func (t *TEK) checkPolicy() error {
	al, el := t.Auth.keyLen(), t.Enc.keyLen()
	if al < 0 || el < 0 {
		return fmt.Errorf("%w: unknown algorithm %v/%v", ErrTEKPolicy, t.Auth, t.Enc)
	}
	if t.SPI == 0 {
		return fmt.Errorf("%w: SPI 0", ErrTEKPolicy)
	}
	switch {
	case t.Enc.authenticated() && t.Auth != AuthNone:
		return fmt.Errorf("%w: %v is used with authentication NONE", ErrTEKPolicy, t.Enc)
	case (t.Enc == EncAESCBC128 || t.Enc == EncAESCBC256) && t.Auth == AuthNone:
		return fmt.Errorf("%w: %v provides no authentication and needs an authentication algorithm", ErrTEKPolicy, t.Enc)
	case t.Enc == EncNone && t.Auth == AuthNone:
		return fmt.Errorf("%w: neither authentication nor confidentiality", ErrTEKPolicy)
	}
	if len(t.IntegrityKey) != al || len(t.AlgorithmKey) != el {
		return fmt.Errorf("%w: keying material %d/%d octets, %v/%v take %d/%d",
			ErrTEKPolicy, len(t.IntegrityKey), len(t.AlgorithmKey), t.Auth, t.Enc, al, el)
	}
	return nil
}

// NewTEK makes a TEK with a random SPI and fresh keying material for the
// algorithms. A key server rotating keys makes a new one per rotation.
func NewTEK(oid asn1.ObjectIdentifier, selector []byte, auth AuthAlg, enc EncAlg, lifetime time.Duration) (TEK, error) {
	t := TEK{OID: oid, Selector: selector, Auth: auth, Enc: enc, Lifetime: lifetime, KDA: -1}
	al, el := auth.keyLen(), enc.keyLen()
	if al < 0 || el < 0 {
		return TEK{}, fmt.Errorf("%w: unknown algorithm %v/%v", ErrTEKPolicy, auth, enc)
	}
	var spi [4]byte
	for t.SPI == 0 {
		if _, err := rand.Read(spi[:]); err != nil {
			return TEK{}, err
		}
		t.SPI = binary.BigEndian.Uint32(spi[:])
	}
	if al > 0 {
		t.IntegrityKey = make([]byte, al)
		rand.Read(t.IntegrityKey)
	}
	if el > 0 {
		t.AlgorithmKey = make([]byte, el)
		rand.Read(t.AlgorithmKey)
	}
	if err := t.checkPolicy(); err != nil {
		return TEK{}, err
	}
	return t, nil
}

// RSessionKey returns the key the IEC 61850-90-5 session layer (package
// rsession) uses for this TEK: the SPI is the key identifier,
// HMAC-SHA256-128 and HMAC-SHA256 sign, AES-GCM-128 and AES-GCM-256
// encrypt. The GCM salt is not used: the session protocol carries a whole
// random initialisation vector in every SPDU. AES-CBC and AES-GMAC TEKs
// have no session-layer counterpart here and are refused.
func (t *TEK) RSessionKey() (rsession.Key, error) {
	k := rsession.Key{ID: t.SPI}
	switch {
	case t.Enc == EncAESGCM128 && t.Auth == AuthNone:
		k.Sec, k.Material = rsession.SecAES128GCM, clone(t.AlgorithmKey[:16])
	case t.Enc == EncAESGCM256 && t.Auth == AuthNone:
		k.Sec, k.Material = rsession.SecAES256GCM, clone(t.AlgorithmKey[:32])
	case t.Enc == EncNone && t.Auth == AuthHMACSHA256128:
		k.Sig, k.Material = rsession.SigHMACSHA256_128, clone(t.IntegrityKey)
	case t.Enc == EncNone && t.Auth == AuthHMACSHA256:
		k.Sig, k.Material = rsession.SigHMACSHA256_256, clone(t.IntegrityKey)
	default:
		return rsession.Key{}, fmt.Errorf("%w: %v/%v", ErrTEKUnsupported, t.Auth, t.Enc)
	}
	return k, nil
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// satBody encodes the TEK's policy as an IEC 61850 SA TEK payload body
// (RFC 8052 figure 4).
func (t *TEK) satBody() ([]byte, error) {
	sel, err := oidAndSelector(t.OID, t.Selector)
	if err != nil {
		return nil, err
	}
	b := append([]byte{protoIEC61850}, sel...)
	b = binary.BigEndian.AppendUint32(b, t.SPI)
	b = binary.BigEndian.AppendUint16(b, uint16(t.Auth))
	b = binary.BigEndian.AppendUint16(b, uint16(t.Enc))
	b = binary.BigEndian.AppendUint32(b, seconds(t.Lifetime))
	var as []attribute
	if t.ActivationDelay > 0 {
		as = append(as, uintAttr(attrSAATD, seconds(t.ActivationDelay)))
	}
	if t.KDA >= 0 {
		as = append(as, basicAttr(attrSAKDA, uint16(t.KDA)))
	}
	return append(b, encodeAttrs(as)...), nil
}

// seconds rounds a duration up to whole seconds, so a remaining lifetime
// is never reported as zero ("does not expire") while time remains.
func seconds(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	s := (d + time.Second - 1) / time.Second
	if s > 0xffffffff {
		return 0xffffffff
	}
	return uint32(s)
}

// parseSAT decodes an SA TEK payload body. A TEK of another protocol than
// IEC 61850 is returned as nil without error, to be skipped.
func parseSAT(b []byte) (*TEK, error) {
	if len(b) < 1 {
		return nil, malformed("empty SA TEK")
	}
	if b[0] != protoIEC61850 {
		return nil, nil
	}
	oid, sel, rest, err := parseOIDAndSelector(b[1:])
	if err != nil {
		return nil, err
	}
	if len(rest) < 12 {
		return nil, malformed("SA TEK policy of %d octets", len(rest))
	}
	t := &TEK{
		OID: oid, Selector: sel,
		SPI:      binary.BigEndian.Uint32(rest[0:4]),
		Auth:     AuthAlg(binary.BigEndian.Uint16(rest[4:6])),
		Enc:      EncAlg(binary.BigEndian.Uint16(rest[6:8])),
		Lifetime: time.Duration(binary.BigEndian.Uint32(rest[8:12])) * time.Second,
		KDA:      -1,
	}
	as, err := parseAttrs(rest[12:])
	if err != nil {
		return nil, err
	}
	for _, a := range as {
		switch a.Type {
		case attrSAATD:
			if len(a.Value) > 8 {
				return nil, malformed("SA_ATD of %d octets", len(a.Value))
			}
			t.ActivationDelay = time.Duration(a.uint()) * time.Second
		case attrSAKDA:
			t.KDA = int(a.uint())
		}
	}
	return t, nil
}

// saBody encodes the GDOI SA payload body with its SA TEK payloads
// (RFC 6407 5.2): DOI, situation 0, the type of the first SA attribute
// payload, and the chain of SA TEKs.
func saBody(teks []TEK) ([]byte, error) {
	var sats []payload
	for i := range teks {
		body, err := teks[i].satBody()
		if err != nil {
			return nil, err
		}
		sats = append(sats, payload{Type: pSAT, Body: body})
	}
	if len(sats) == 0 {
		return nil, errors.New("gdoi: a group policy needs at least one TEK")
	}
	b := binary.BigEndian.AppendUint32(nil, doiGDOI)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, pSAT)
	b = append(b, 0, 0)
	return append(b, encodeChain(sats, pNone)...), nil
}

// parseSA decodes a GDOI SA payload body into its IEC 61850 TEKs. SA KEK
// and GAP payloads are skipped: this member does not take GROUPKEY-PUSH
// rekeys, and re-registers instead.
func parseSA(b []byte) ([]*TEK, error) {
	if len(b) < 12 {
		return nil, malformed("SA of %d octets", len(b))
	}
	if doi := binary.BigEndian.Uint32(b); doi != doiGDOI {
		return nil, malformed("SA DOI %d, not GDOI", doi)
	}
	first := binary.BigEndian.Uint16(b[8:10])
	if first > 0xff {
		return nil, malformed("SA attribute payload type %d", first)
	}
	ps, _, err := parseChain(b[12:], byte(first))
	if err != nil {
		return nil, err
	}
	var teks []*TEK
	for _, p := range ps {
		if p.Type != pSAT {
			continue
		}
		t, err := parseSAT(p.Body)
		if err != nil {
			return nil, err
		}
		if t != nil {
			teks = append(teks, t)
		}
	}
	return teks, nil
}

// kdBody encodes a Key Download payload body carrying the keys of teks
// (RFC 6407 5.6, RFC 8052 2.3).
func kdBody(teks []TEK) []byte {
	b := binary.BigEndian.AppendUint16(nil, uint16(len(teks)))
	b = append(b, 0, 0)
	for _, t := range teks {
		var as []attribute
		if len(t.AlgorithmKey) > 0 {
			as = append(as, varAttr(attrTEKAlgorithmKey, t.AlgorithmKey))
		}
		if len(t.IntegrityKey) > 0 {
			as = append(as, varAttr(attrTEKIntegrityKey, t.IntegrityKey))
		}
		attrs := encodeAttrs(as)
		kp := []byte{kdTypeTEK, 0}
		kp = binary.BigEndian.AppendUint16(kp, uint16(4+1+4+len(attrs)))
		kp = append(kp, 4)
		kp = binary.BigEndian.AppendUint32(kp, t.SPI)
		b = append(b, append(kp, attrs...)...)
	}
	return b
}

// keyPacket is the keying material of one SPI.
type keyPacket struct {
	algorithm, integrity []byte
}

// parseKD decodes a Key Download payload body into the TEK keys by SPI.
func parseKD(b []byte) (map[uint32]keyPacket, error) {
	if len(b) < 4 {
		return nil, malformed("KD of %d octets", len(b))
	}
	n := int(binary.BigEndian.Uint16(b))
	out := map[uint32]keyPacket{}
	off := 4
	for i := 0; i < n; i++ {
		if len(b)-off < 5 {
			return nil, malformed("truncated key packet")
		}
		typ := b[off]
		kl := int(binary.BigEndian.Uint16(b[off+2:]))
		if kl < 5 || kl > len(b)-off {
			return nil, malformed("key packet of %d octets, %d remain", kl, len(b)-off)
		}
		kp := b[off : off+kl]
		off += kl
		if typ != kdTypeTEK {
			continue
		}
		spiSize := int(kp[4])
		if spiSize != 4 || 5+spiSize > len(kp) {
			return nil, malformed("TEK key packet with a %d-octet SPI", spiSize)
		}
		spi := binary.BigEndian.Uint32(kp[5:9])
		as, err := parseAttrs(kp[9:])
		if err != nil {
			return nil, err
		}
		var p keyPacket
		for _, a := range as {
			switch a.Type {
			case attrTEKAlgorithmKey:
				p.algorithm = clone(a.Value)
			case attrTEKIntegrityKey:
				p.integrity = clone(a.Value)
			}
		}
		out[spi] = p
	}
	return out, nil
}
