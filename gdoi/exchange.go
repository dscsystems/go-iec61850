package gdoi

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// DefaultPort is the GDOI port (RFC 6407 2.2).
const DefaultPort = 848

// phase1Life is the lifetime proposed for the phase 1 SA. A registration
// uses its phase 1 SA once, so it only needs to outlive the exchange.
const phase1Life = 3600

// nonceLen is the length of the nonces sent (RFC 6407 5.8: 8 to 128).
const nonceLen = 32

// Credentials authenticate one end of the phase 1 exchange.
type Credentials struct {
	// Certificate is this end's certificate chain, leaf first, and Key its
	// private key: RSA (2048 bits or more) or ECDSA P-256 or P-384. The
	// leaf's subject is the phase 1 identity.
	Certificate []*x509.Certificate
	Key         crypto.Signer
	// Roots are the authorities a peer's certificate must chain to.
	Roots *x509.CertPool

	// PSK, on a group member, authenticates with a pre-shared key instead
	// of a certificate. Main mode binds a pre-shared key to the peer's
	// address, so a key server looks it up by address (ServerConfig.PSK).
	PSK []byte
}

func (c *Credentials) authMethod() (uint16, error) {
	if len(c.PSK) > 0 {
		if c.Key != nil {
			return 0, errors.New("gdoi: credentials name both a pre-shared key and a certificate")
		}
		return authPSK, nil
	}
	if c.Key == nil || len(c.Certificate) == 0 {
		return 0, errors.New("gdoi: credentials need a certificate and key, or a pre-shared key")
	}
	if c.Roots == nil {
		return 0, errors.New("gdoi: certificate credentials need Roots to verify the peer")
	}
	return authMethodFor(c.Key)
}

// Peer is the authenticated identity at the other end of a phase 1
// exchange.
type Peer struct {
	Addr net.Addr
	// IDType and ID are the identification payload the peer sent: its
	// certificate subject (ID_DER_ASN1_DN) with certificates, or what the
	// peer chose (usually its address) with a pre-shared key.
	IDType byte
	ID     []byte
	// Certificate is the peer's verified leaf certificate, nil with a
	// pre-shared key.
	Certificate *x509.Certificate
}

func (p Peer) String() string {
	if p.Certificate != nil {
		return p.Certificate.Subject.String()
	}
	if p.IDType == IDIPv4Addr && len(p.ID) == 4 || p.IDType == IDIPv6Addr && len(p.ID) == 16 {
		return net.IP(p.ID).String()
	}
	return fmt.Sprintf("%v (ID type %d)", p.Addr, p.IDType)
}

// ownID is this end's phase 1 identification: the certificate subject,
// or with a pre-shared key the local address.
func (c *Credentials) ownID(local net.Addr) idPayload {
	if len(c.Certificate) > 0 {
		return idPayload{Type: IDDERASN1DN, Data: c.Certificate[0].RawSubject}
	}
	if ua, ok := local.(*net.UDPAddr); ok {
		if ip4 := ua.IP.To4(); ip4 != nil {
			return idPayload{Type: IDIPv4Addr, Data: ip4}
		}
		return idPayload{Type: IDIPv6Addr, Data: ua.IP.To16()}
	}
	return idPayload{Type: IDKeyID, Data: []byte{0, 0, 0, 0}}
}

// verifyPeer checks a peer's certificates against the roots and binds the
// identification payload to the leaf.
func (c *Credentials) verifyPeer(id idPayload, certs []*x509.Certificate, now time.Time) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("gdoi: peer sent no certificate")
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, ic := range certs[1:] {
		inter.AddCert(ic)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: c.Roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("gdoi: peer certificate: %w", err)
	}
	if id.Type != IDDERASN1DN || string(id.Data) != string(leaf.RawSubject) {
		return nil, errors.New("gdoi: peer identification does not match its certificate's subject")
	}
	return leaf, nil
}

// transform is one phase 1 transform as offered.
type transform struct {
	body  []byte // the transform payload body, echoed by a responder
	suite Suite
	auth  uint16
}

// phase1SABody builds the phase 1 SA payload body: the GDOI DOI, one
// ISAKMP proposal with a transform per suite.
func phase1SABody(suites []Suite, auth uint16) []byte {
	var ts []payload
	for i, s := range suites {
		b := []byte{byte(i + 1), transKeyIKE, 0, 0}
		b = append(b, encodeAttrs(s.attrs(auth, phase1Life))...)
		ts = append(ts, payload{Type: pTrans, Body: b})
	}
	return phase1SAWith(ts)
}

// phase1DOI is the DOI a member puts in its phase 1 SA: GDOI, as RFC 6407
// 2.1 requires. Tests set it to the IPsec DOI (1) for Wireshark, which
// reads any SA with the GDOI DOI in the phase 2 layout.
var phase1DOI uint32 = doiGDOI

func phase1SAWith(ts []payload) []byte { return phase1SAWithDOI(phase1DOI, ts) }

func phase1SAWithDOI(doi uint32, ts []payload) []byte {
	prop := []byte{1, protoISAKMP, 0, byte(len(ts))}
	prop = append(prop, encodeChain(ts, pNone)...)
	b := binary.BigEndian.AppendUint32(nil, doi)
	b = binary.BigEndian.AppendUint32(b, sitIdentity)
	return append(b, encodeChain([]payload{{Type: pProposal, Body: prop}}, pNone)...)
}

// parsePhase1SA reads a phase 1 SA payload body: its single proposal's
// transforms. The DOI is GDOI by RFC 6407; the IPsec DOI, which some
// implementations put in phase 1, is accepted too.
func parsePhase1SA(b []byte) ([]transform, error) {
	if len(b) < 8 {
		return nil, malformed("SA of %d octets", len(b))
	}
	if doi := binary.BigEndian.Uint32(b); doi != doiGDOI && doi != 1 {
		return nil, malformed("phase 1 SA DOI %d", doi)
	}
	props, _, err := parseChain(b[8:], pProposal)
	if err != nil {
		return nil, err
	}
	if len(props) != 1 {
		return nil, malformed("%d proposals in a phase 1 SA", len(props))
	}
	p := props[0].Body
	if len(p) < 4 || p[1] != protoISAKMP || p[2] != 0 {
		return nil, malformed("phase 1 proposal is not an ISAKMP proposal without SPI")
	}
	ts, _, err := parseChain(p[4:], pTrans)
	if err != nil {
		return nil, err
	}
	var out []transform
	for _, t := range ts {
		if len(t.Body) < 4 || t.Body[1] != transKeyIKE {
			continue
		}
		as, err := parseAttrs(t.Body[4:])
		if err != nil {
			return nil, err
		}
		s, auth, ok := suiteFromAttrs(as)
		if !ok {
			continue
		}
		out = append(out, transform{body: t.Body, suite: s, auth: auth})
	}
	return out, nil
}

// message builds a clear message.
func message(h header, ps []payload) []byte {
	body := encodeChain(ps, pNone)
	if len(ps) > 0 {
		h.Next = ps[0].Type
	}
	h.Flags &^= flagEncrypted
	h.Length = uint32(headerLen + len(body))
	return append(h.marshal(nil), body...)
}

// sealed builds an encrypted message with iv and returns it with the IV
// for the next message of the exchange.
func (k *keys) sealed(h header, ps []payload, iv []byte) ([]byte, []byte) {
	ct, next := k.encrypt(encodeChain(ps, pNone), iv)
	if len(ps) > 0 {
		h.Next = ps[0].Type
	}
	h.Flags |= flagEncrypted
	h.Length = uint32(headerLen + len(ct))
	return append(h.marshal(nil), ct...), next
}

// open parses a message's payloads, decrypting them with iv when the
// message is encrypted, and returns the IV that follows it.
func (k *keys) open(msg []byte, iv []byte) (*header, []payload, []byte, []byte, error) {
	h, err := parseHeader(msg)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	body := msg[headerLen:h.Length]
	next := iv
	if h.Flags&flagEncrypted != 0 {
		if k == nil {
			return nil, nil, nil, nil, malformed("encrypted message before keys exist")
		}
		if body, next, err = k.decrypt(body, iv); err != nil {
			return nil, nil, nil, nil, err
		}
	}
	ps, n, err := parseChain(body, h.Next)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return h, ps, body[:n], next, nil
}

// hashed returns the payloads after a leading HASH payload and the octets
// they occupy, which the HASH covers.
func hashed(ps []payload, chain []byte) (payload, []payload, []byte, error) {
	if len(ps) == 0 || ps[0].Type != pHash {
		return payload{}, nil, nil, malformed("message does not start with a HASH payload")
	}
	return ps[0], ps[1:], chain[len(ps[0].raw):], nil
}

func midBytes(mid uint32) []byte { return binary.BigEndian.AppendUint32(nil, mid) }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return b
}

func randomCookie() [8]byte {
	var c [8]byte
	for c == [8]byte{} {
		copy(c[:], randomBytes(8))
	}
	return c
}

func randomMsgID() uint32 {
	for {
		if v := binary.BigEndian.Uint32(randomBytes(4)); v != 0 {
			return v
		}
	}
}

func certPayloads(chain []*x509.Certificate) []payload {
	var ps []payload
	for _, c := range chain {
		// Encoding 4: X.509 certificate, signature.
		ps = append(ps, payload{Type: pCert, Body: append([]byte{4}, c.Raw...)})
	}
	return ps
}

func parseCerts(ps []payload) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, p := range ps {
		if p.Type != pCert {
			continue
		}
		if len(p.Body) < 1 {
			return nil, malformed("empty certificate payload")
		}
		if p.Body[0] != 4 {
			return nil, malformed("certificate payload of encoding %d", p.Body[0])
		}
		c, err := x509.ParseCertificate(p.Body[1:])
		if err != nil {
			return nil, fmt.Errorf("gdoi: peer certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}

// informational builds an informational exchange carrying a notification:
// protected with HASH(1) = prf(SKEYID_a, M-ID | N) once keys exist, in the
// clear before (RFC 2409 5.7).
func informational(k *keys, ic, rc [8]byte, typ uint16) []byte {
	n := payload{Type: pNotify, Body: notify(doiGDOI, typ, nil)}
	h := header{ICookie: ic, RCookie: rc, Exchange: xchgInfo}
	if k == nil {
		return message(h, []payload{n})
	}
	h.MsgID = randomMsgID()
	hv := prf(k.hash, k.a, midBytes(h.MsgID), encodeChain([]payload{n}, pNone))
	msg, _ := k.sealed(h, []payload{{Type: pHash, Body: hv}, n}, k.phase2IV(h.MsgID))
	return msg
}

// readInformational reads a notification from an informational message,
// verifying its hash when it is protected.
func readInformational(k *keys, msg []byte) (*NotifyError, error) {
	h, err := parseHeader(msg)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if h.Flags&flagEncrypted != 0 {
		if k == nil || k.phase1Last == nil {
			return nil, malformed("protected informational before phase 1 completed")
		}
		iv = k.phase2IV(h.MsgID)
	}
	_, ps, chain, _, err := k.open(msg, iv)
	if err != nil {
		return nil, err
	}
	if h.Flags&flagEncrypted != 0 {
		hp, rest, covered, err := hashed(ps, chain)
		if err != nil {
			return nil, err
		}
		if !constantEqual(hp.Body, prf(k.hash, k.a, midBytes(h.MsgID), covered)) {
			return nil, errors.New("gdoi: informational message with a bad hash")
		}
		ps = rest
	}
	n, ok := find(ps, pNotify)
	if !ok {
		return nil, malformed("informational message without a notification")
	}
	return parseNotify(n.Body)
}
