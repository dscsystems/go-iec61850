// Package pkitest generates certificate hierarchies for tests and
// laboratory setups of IEC 62351-4 E2E security: a root CA, optional
// intermediates, and end-entity certificates whose subject is an AE-title
// object identifier (IEC 62351-4 G.6.2).
//
// It is not a certificate authority for production use.
package pkitest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
)

// KeyType selects the key algorithm of a generated certificate.
type KeyType uint8

const (
	ECDSAP256 KeyType = iota
	RSA2048
	RSA1024 // too weak, for negative tests
)

// NewKey generates a private key.
func NewKey(t KeyType) crypto.Signer {
	switch t {
	case RSA2048:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		return k
	case RSA1024:
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		must(err)
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	return k
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// CA is a certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

var serial = big.NewInt(time.Now().UnixNano())

func nextSerial() *big.Int {
	serial = new(big.Int).Add(serial, big.NewInt(1))
	return new(big.Int).Set(serial)
}

// NewRoot creates a self-signed root CA.
func NewRoot(name string, kt KeyType) *CA {
	k := NewKey(kt)
	tpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	must(err)
	c, err := x509.ParseCertificate(der)
	must(err)
	return &CA{Cert: c, Key: k}
}

// NewIntermediate creates a CA signed by ca.
func (ca *CA) NewIntermediate(name string, kt KeyType) *CA {
	k := NewKey(kt)
	tpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, k.Public(), ca.Key)
	must(err)
	c, err := x509.ParseCertificate(der)
	must(err)
	return &CA{Cert: c, Key: k}
}

// LeafOptions adjusts a generated end-entity certificate, for negative tests.
type LeafOptions struct {
	KeyType   KeyType
	KeyUsage  x509.KeyUsage // zero: digitalSignature|keyAgreement
	NotBefore time.Time
	NotAfter  time.Time
	// Subject, when non-nil, replaces the AE-title subject (raw Name DER).
	Subject []byte
	// AttrType, when non-nil, replaces pki.ProvisionalAEAttributeType.
	AttrType asn1.OID
	// Padding adds a non-critical extension of this many octets (oversized
	// certificate tests).
	Padding int
	Key     crypto.Signer
}

// Leaf is an end-entity credential.
type Leaf struct {
	DER  []byte
	Cert *pki.Certificate
	Key  crypto.Signer
}

// NewE2ELeaf issues an end-entity certificate for the AE title
// apTitle||aeQualifier.
func (ca *CA) NewE2ELeaf(apTitle asn1.OID, aeQualifier int32, o LeafOptions) *Leaf {
	k := o.Key
	if k == nil {
		k = NewKey(o.KeyType)
	}
	ku := o.KeyUsage
	if ku == 0 {
		ku = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement
	}
	nb, na := o.NotBefore, o.NotAfter
	if nb.IsZero() {
		nb = time.Now().Add(-time.Hour)
	}
	if na.IsZero() {
		na = time.Now().Add(365 * 24 * time.Hour)
	}
	subject := o.Subject
	if subject == nil {
		at := o.AttrType
		if at == nil {
			at = pki.ProvisionalAEAttributeType
		}
		subject = pki.OIDName(at, pki.AETitleOID(apTitle, aeQualifier))
	}
	tpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		RawSubject:   subject,
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     ku,
	}
	if o.Padding > 0 {
		tpl.ExtraExtensions = []pkix.Extension{{Id: []int{1, 3, 9999, 99}, Value: make([]byte, o.Padding)}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, k.Public(), ca.Key)
	must(err)
	c, err := pki.ParseCertificate(der)
	if err != nil {
		c = nil // oversized certificates are returned unparsed
	}
	return &Leaf{DER: der, Cert: c, Key: k}
}

// CRL issues a CRL revoking the given certificates; nextUpdate may be in
// the past for stale-CRL tests.
func (ca *CA) CRL(nextUpdate time.Time, revoked ...*x509.Certificate) *x509.RevocationList {
	var entries []x509.RevocationListEntry
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    nextSerial(),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, ca.Cert, ca.Key)
	must(err)
	crl, err := x509.ParseRevocationList(der)
	must(err)
	return crl
}

// PEM encodes DER certificate bytes.
func PEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// KeyPEM encodes a private key as PKCS#8 PEM.
func KeyPEM(k crypto.Signer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	must(err)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
