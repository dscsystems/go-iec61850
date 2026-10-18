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
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
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

// nextSerial returns a random positive 127-bit serial number, safe for
// concurrent use.
func nextSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
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
	// AttrType, when non-nil, replaces pki.AEAttributeType.
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
			at = pki.AEAttributeType
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

// StaticDHLeaf is a TLS certificate with a fixed Diffie-Hellman key, for the
// static-DH suites (TLS_DH_RSA_*, IEC 62351-4 Table 10).
type StaticDHLeaf struct {
	DER  []byte
	Cert *x509.Certificate
	// Key is the PKCS #8 DER of the PKCS #3 (dhKeyAgreement) private key.
	Key []byte
}

// ffdhe2048 is the RFC 7919 2048-bit group, generator 2.
var ffdhe2048, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FB"+
	"CC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"+
	"984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D"+
	"4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE"+
	"3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16)

var oidDHKeyAgreement = stdasn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1}

// NewStaticDHLeaf issues a server certificate for cn and ips holding a new
// fixed Diffie-Hellman key on the RFC 7919 ffdhe2048 group, in the PKCS #3
// form OpenSSL 1.0.2 serves. crypto/x509 cannot issue one, so the key goes
// into the TBSCertificate of an ordinary certificate, signed again.
func (ca *CA) NewStaticDHLeaf(cn string, ips ...net.IP) *StaticDHLeaf {
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(ffdhe2048, big.NewInt(3)))
	must(err)
	x.Add(x, big.NewInt(2))
	y := new(big.Int).Exp(big.NewInt(2), x, ffdhe2048)
	params, err := stdasn1.Marshal(struct{ P, G *big.Int }{ffdhe2048, big.NewInt(2)})
	must(err)
	alg := pkix.AlgorithmIdentifier{Algorithm: oidDHKeyAgreement, Parameters: stdasn1.RawValue{FullBytes: params}}
	pub, err := stdasn1.Marshal(y)
	must(err)
	spki, err := stdasn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       stdasn1.BitString
	}{alg, stdasn1.BitString{Bytes: pub, BitLength: 8 * len(pub)}})
	must(err)
	priv, err := stdasn1.Marshal(x)
	must(err)
	key, err := stdasn1.Marshal(struct {
		Version   int
		Algorithm pkix.AlgorithmIdentifier
		Key       []byte
	}{0, alg, priv})
	must(err)

	tpl := &x509.Certificate{
		SerialNumber: nextSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyAgreement,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, NewKey(ECDSAP256).Public(), ca.Key)
	must(err)
	var cert struct {
		TBS    stdasn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    stdasn1.BitString
	}
	_, err = stdasn1.Unmarshal(der, &cert)
	must(err)
	var tbs []stdasn1.RawValue
	_, err = stdasn1.Unmarshal(cert.TBS.FullBytes, &tbs)
	must(err)
	// version, serial, signature, issuer, validity, subject, key, ...
	tbs[6] = stdasn1.RawValue{FullBytes: spki}
	cert.TBS.FullBytes, err = stdasn1.Marshal(tbs)
	must(err)
	digest := sha256.Sum256(cert.TBS.FullBytes)
	sig, err := ca.Key.Sign(rand.Reader, digest[:], crypto.SHA256)
	must(err)
	cert.Sig = stdasn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}
	der, err = stdasn1.Marshal(cert)
	must(err)
	c, err := x509.ParseCertificate(der)
	must(err)
	return &StaticDHLeaf{DER: der, Cert: c, Key: key}
}

// DHKeyPEM encodes a static-DH private key (PKCS #8 DER) as PEM.
func DHKeyPEM(key []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}
