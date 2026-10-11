// Package pki holds the certificate handling shared by the IEC 62351
// profiles of this module: parsing (including the object-identifier
// subject names of IEC 62351-4 Annex G, which crypto/x509 refuses), the end-
// entity profile checks of IEC 62351-4 Annex G, trust stores, revocation and
// identity binding.
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"errors"
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// MaxCertificateSize is the largest certificate IEC 62351-4 6.2.6 requires
// support for; a larger one terminates the association.
const MaxCertificateSize = 8192

// Errors of certificate handling.
var (
	ErrCertTooLarge    = errors.New("pki: certificate larger than 8192 octets")
	ErrMalformed       = errors.New("pki: malformed certificate")
	ErrProfile         = errors.New("pki: certificate violates the IEC 62351-4 end-entity profile")
	ErrNoAEIdentity    = errors.New("pki: certificate subject is not an AE-title object identifier")
	ErrIdentity        = errors.New("pki: certificate subject does not name the peer")
	ErrPath            = errors.New("pki: certification path invalid")
	ErrRevoked         = errors.New("pki: certificate revoked")
	ErrExpired         = errors.New("pki: certificate expired or not yet valid")
	ErrRevocationState = errors.New("pki: revocation information unavailable")
)

// placeholderSubject is the Name substituted for an object-identifier
// subject so crypto/x509 will parse the rest of the certificate:
// SEQUENCE { SET { SEQUENCE { CN, UTF8String "iec62351-4-ae" } } }.
var placeholderSubject = func() []byte {
	b := (&pkix.Name{CommonName: "iec62351-4-ae"}).ToRDNSequence()
	der, err := stdasn1.Marshal(b)
	if err != nil {
		panic(err)
	}
	return der
}()

// Certificate is a parsed certificate together with the AE-title object
// identifier in its subject, when it has one.
type Certificate struct {
	*x509.Certificate
	// SubjectOID is the value of the single object-identifier attribute
	// forming the subject (IEC 62351-4 G.6.2), nil when the subject is an
	// ordinary distinguished name.
	SubjectOID asn1.OID
	// SubjectOIDType is the attribute type carrying SubjectOID.
	SubjectOIDType asn1.OID
}

// ParseCertificate parses a DER certificate, checking it is DER (IEC
// 62351-4 7.2.2 c)) and at most 8192 octets. A subject consisting of an
// object-identifier attribute, which crypto/x509 cannot parse, is accepted:
// the certificate is parsed with a placeholder subject and its raw fields are
// then restored, so signature and chain checks still cover the octets
// received.
func ParseCertificate(der []byte) (*Certificate, error) {
	if len(der) > MaxCertificateSize {
		return nil, fmt.Errorf("%w (%d)", ErrCertTooLarge, len(der))
	}
	c, err := x509.ParseCertificate(der)
	if err == nil {
		if !bytes.Equal(c.Raw, der) {
			return nil, fmt.Errorf("%w: trailing data", ErrMalformed)
		}
		out := &Certificate{Certificate: c}
		out.SubjectOIDType, out.SubjectOID, _ = parseOIDName(c.RawSubject)
		return out, nil
	}
	// Locate the subject and try again with a placeholder.
	tbs, subject, patched, perr := replaceSubject(der, placeholderSubject)
	if perr != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	typ, oid, oerr := parseOIDName(subject)
	if oerr != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	c, err = x509.ParseCertificate(patched)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	c.Raw = der
	c.RawTBSCertificate = tbs
	c.RawSubject = subject
	c.Subject = pkix.Name{}
	return &Certificate{Certificate: c, SubjectOID: oid, SubjectOIDType: typ}, nil
}

// replaceSubject returns the TBSCertificate and subject octets of der, and
// a copy of der with the subject replaced.
func replaceSubject(der, newSubject []byte) (tbs, subject, patched []byte, err error) {
	d := asn1.NewDecoder(der)
	cert, err := d.ReadSpan()
	if err != nil || cert.Tag != asn1.TagSequence || d.More() || cert.Indefinite {
		return nil, nil, nil, errors.New("certificate not a DER SEQUENCE")
	}
	cd := asn1.NewDecoder(cert.Content)
	tbsSpan, err := cd.ReadSpan()
	if err != nil || tbsSpan.Tag != asn1.TagSequence {
		return nil, nil, nil, errors.New("no TBSCertificate")
	}
	rest := cd.Rest() // signatureAlgorithm, signatureValue
	td := asn1.NewDecoder(tbsSpan.Content)
	var before []byte
	start := 0
	// [0] version (optional), serial, signature, issuer, validity, subject.
	need := 5
	if tag, ok := td.PeekTag(); ok && tag == asn1.ContextConstructed(0) {
		need = 6
	}
	var subj asn1.Span
	for i := 0; i < need; i++ {
		s, err := td.ReadSpan()
		if err != nil {
			return nil, nil, nil, errors.New("bad TBSCertificate")
		}
		if i == need-1 {
			subj = s
		}
	}
	if subj.Tag != asn1.TagSequence {
		return nil, nil, nil, errors.New("subject not a SEQUENCE")
	}
	off := len(tbsSpan.Content) - len(td.Rest()) - len(subj.Full)
	before = tbsSpan.Content[start:off]
	after := td.Rest()
	newTBS := append(append(append([]byte(nil), before...), newSubject...), after...)
	inner := asn1.AppendTLV(nil, asn1.TagSequence, newTBS)
	inner = append(inner, rest...)
	return tbsSpan.Full, subj.Full, asn1.AppendTLV(nil, asn1.TagSequence, inner), nil
}

// parseOIDName decodes a Name consisting of exactly one RDN holding exactly
// one attribute whose value is an OBJECT IDENTIFIER.
func parseOIDName(name []byte) (typ, val asn1.OID, err error) {
	d := asn1.NewDecoder(name)
	seq, err := d.Expect(asn1.TagSequence)
	if err != nil || d.More() {
		return nil, nil, ErrNoAEIdentity
	}
	rd := asn1.NewDecoder(seq)
	set, err := rd.Expect(asn1.TagSet)
	if err != nil || rd.More() {
		return nil, nil, ErrNoAEIdentity
	}
	sd := asn1.NewDecoder(set)
	atv, err := sd.Expect(asn1.TagSequence)
	if err != nil || sd.More() {
		return nil, nil, ErrNoAEIdentity
	}
	ad := asn1.NewDecoder(atv)
	tb, err := ad.Expect(asn1.TagOID)
	if err != nil {
		return nil, nil, ErrNoAEIdentity
	}
	vb, err := ad.Expect(asn1.TagOID)
	if err != nil || ad.More() {
		return nil, nil, ErrNoAEIdentity
	}
	if typ, err = asn1.DecodeOID(tb); err != nil {
		return nil, nil, ErrNoAEIdentity
	}
	if val, err = asn1.DecodeOID(vb); err != nil {
		return nil, nil, ErrNoAEIdentity
	}
	return typ, val, nil
}

// OIDName encodes the subject Name of IEC 62351-4 G.6.2: one RDN with one
// attribute of type attrType whose value is the AE-title object identifier.
func OIDName(attrType, aeTitle asn1.OID) []byte {
	atv := asn1.Cons(asn1.TagSequence,
		asn1.OIDElem(asn1.TagOID, attrType),
		asn1.OIDElem(asn1.TagOID, aeTitle))
	return asn1.Cons(asn1.TagSequence, asn1.Cons(asn1.TagSet, atv)).Encode()
}

// ProvisionalAEAttributeType is the attribute type this module puts in the
// subject of the E2E certificates it generates (test PKI, CSR tool). IEC
// 62351-4 G.6.2 names the objectIdentifier attribute type of ISO/IEC
// 9594-6; the exact object identifier is to be confirmed (implementation
// plan WP0.5). Receivers do not depend on it unless a policy pins the type.
var ProvisionalAEAttributeType = asn1.OID{2, 5, 4, 82}

// EndEntityProfile checks an E2E end-entity certificate against IEC
// 62351-4 Annex G: version 3, positive serial, no unique identifiers,
// SHA-256 or stronger signature, RSA >= 2048 or EC P-256 key, and key usage
// with both digitalSignature and keyAgreement.
func EndEntityProfile(c *Certificate) error {
	if c.Version != 3 {
		return fmt.Errorf("%w: version %d", ErrProfile, c.Version)
	}
	if c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 {
		return fmt.Errorf("%w: serial number not positive", ErrProfile)
	}
	switch c.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
	default:
		return fmt.Errorf("%w: signature algorithm %v", ErrProfile, c.SignatureAlgorithm)
	}
	if err := CheckKey(c.PublicKey); err != nil {
		return err
	}
	if c.KeyUsage&x509.KeyUsageDigitalSignature == 0 || c.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
		return fmt.Errorf("%w: key usage must include digitalSignature and keyAgreement", ErrProfile)
	}
	if hasUniqueIDs(c.RawTBSCertificate) {
		return fmt.Errorf("%w: issuer or subject unique identifier present", ErrProfile)
	}
	return nil
}

// CheckKey checks a public key against the E2E key algorithms of IEC
// 62351-4 G.4.7 (brainpoolP256r1 is not supported by this release).
func CheckKey(pub any) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("%w: %d-bit RSA key", ErrProfile, k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("%w: curve %s", ErrProfile, k.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("%w: key type %T", ErrProfile, pub)
	}
	return nil
}

func hasUniqueIDs(tbs []byte) bool {
	content, err := asn1.NewDecoder(tbs).Expect(asn1.TagSequence)
	if err != nil {
		return false
	}
	d := asn1.NewDecoder(content)
	for d.More() {
		tag, _, err := d.ReadTLV()
		if err != nil {
			return false
		}
		if tag.Class == asn1.ClassContextSpecific && (tag.Number == 1 || tag.Number == 2) {
			return true
		}
	}
	return false
}
