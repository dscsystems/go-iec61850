// Package e2efile loads IEC 62351-4 E2E credentials and trust from PEM or
// DER files: the end-entity certificate and private key, the CA path sent
// to peers, the trust anchors and the CRLs.
package e2efile

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/e2e"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
)

// Files names the credential files. PEM or DER is accepted for every one.
type Files struct {
	Cert string   // end-entity certificate
	Key  string   // private key (PKCS#8, PKCS#1 or SEC 1)
	Path []string // CA certificates sent to the peer, top-down
	CA   []string // trust anchors
	CRL  []string // certificate revocation lists
}

// Loaded is the result of Load.
type Loaded struct {
	Identity   e2e.Identity
	Trust      *pki.TrustStore
	Revocation *pki.RevocationChecker
	Cert       *pki.Certificate
}

// Load reads the files. ae is the local AE title, which the certificate
// must name (IEC 62351-4 G.6.2).
func Load(f Files, ae e2e.AETitle, policy pki.UnavailablePolicy) (*Loaded, error) {
	if f.Cert == "" || f.Key == "" {
		return nil, errors.New("e2e: certificate and key files are required")
	}
	if len(f.CA) == 0 {
		return nil, errors.New("e2e: at least one trust anchor (CA) file is required")
	}
	certDER, err := readOne(f.Cert, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("e2e: certificate %s: %w", f.Cert, err)
	}
	cert, err := pki.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("e2e: certificate %s: %w", f.Cert, err)
	}
	if err := pki.EndEntityProfile(cert); err != nil {
		return nil, fmt.Errorf("e2e: certificate %s: %w", f.Cert, err)
	}
	if err := pki.CheckIdentity(cert, ae.OID(), nil); err != nil {
		return nil, fmt.Errorf("e2e: certificate %s does not name AE %v: %w", f.Cert, ae, err)
	}
	key, err := loadKey(f.Key)
	if err != nil {
		return nil, fmt.Errorf("e2e: key %s: %w", f.Key, err)
	}
	var path [][]byte
	for _, p := range f.Path {
		ders, err := readAll(p, "CERTIFICATE")
		if err != nil {
			return nil, fmt.Errorf("e2e: path %s: %w", p, err)
		}
		path = append(path, ders...)
	}
	var anchors []*x509.Certificate
	for _, p := range f.CA {
		ders, err := readAll(p, "CERTIFICATE")
		if err != nil {
			return nil, fmt.Errorf("e2e: CA %s: %w", p, err)
		}
		for _, d := range ders {
			c, err := x509.ParseCertificate(d)
			if err != nil {
				return nil, fmt.Errorf("e2e: CA %s: %w", p, err)
			}
			anchors = append(anchors, c)
		}
	}
	var crls []*x509.RevocationList
	for _, p := range f.CRL {
		ders, err := readAll(p, "X509 CRL")
		if err != nil {
			return nil, fmt.Errorf("e2e: CRL %s: %w", p, err)
		}
		for _, d := range ders {
			crl, err := x509.ParseRevocationList(d)
			if err != nil {
				return nil, fmt.Errorf("e2e: CRL %s: %w", p, err)
			}
			crls = append(crls, crl)
		}
	}
	return &Loaded{
		Identity:   e2e.Identity{AE: ae, Certificate: certDER, Path: path, Signer: key},
		Trust:      pki.NewTrustStore(anchors...),
		Revocation: pki.NewRevocationChecker(policy, crls...),
		Cert:       cert,
	}, nil
}

// ReloadCRLs re-reads CRL files into r (a periodic refresh, IEC 62351-4
// 6.2.7). On error r is left unchanged.
func ReloadCRLs(r *pki.RevocationChecker, files []string) error {
	var crls []*x509.RevocationList
	for _, p := range files {
		ders, err := readAll(p, "X509 CRL")
		if err != nil {
			return err
		}
		for _, d := range ders {
			crl, err := x509.ParseRevocationList(d)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			crls = append(crls, crl)
		}
	}
	r.Set(crls...)
	return nil
}

func readAll(path, typ string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == typ {
			out = append(out, blk.Bytes)
		}
	}
	if len(out) == 0 {
		if len(b) > 0 && b[0] == 0x30 {
			return [][]byte{b}, nil // DER
		}
		return nil, fmt.Errorf("no %s found", typ)
	}
	return out, nil
}

func readOne(path, typ string) ([]byte, error) {
	all, err := readAll(path, typ)
	if err != nil {
		return nil, err
	}
	return all[0], nil
}

func loadKey(path string) (crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der := b
	if blk, _ := pem.Decode(b); blk != nil {
		der = blk.Bytes
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("key is not a signing key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unrecognised private key format")
}

// ParseAETitle parses "1.3.9999.1/12" or "1.3.9999.1.12" style text: an
// AP-title object identifier and an AE-qualifier separated by '/'.
func ParseAETitle(s string) (e2e.AETitle, error) {
	var ap, q string
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			ap, q = s[:i], s[i+1:]
			break
		}
	}
	if ap == "" {
		return e2e.AETitle{}, fmt.Errorf("AE title %q: want <AP-title OID>/<AE-qualifier>", s)
	}
	oid, err := parseOID(ap)
	if err != nil {
		return e2e.AETitle{}, err
	}
	var n int64
	if _, err := fmt.Sscan(q, &n); err != nil || n < 0 || n > 1<<31-1 {
		return e2e.AETitle{}, fmt.Errorf("AE qualifier %q", q)
	}
	return e2e.AETitle{APTitle: oid, AEQualifier: int32(n)}, nil
}

func parseOID(s string) (asn1.OID, error) {
	var out asn1.OID
	var cur uint64
	digits := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if digits == 0 {
				return nil, fmt.Errorf("object identifier %q", s)
			}
			out = append(out, uint32(cur))
			cur, digits = 0, 0
			continue
		}
		c := s[i]
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("object identifier %q", s)
		}
		cur = cur*10 + uint64(c-'0')
		if cur > 1<<32-1 {
			return nil, fmt.Errorf("object identifier %q", s)
		}
		digits++
	}
	if len(out) < 2 {
		return nil, fmt.Errorf("object identifier %q", s)
	}
	return out, nil
}
