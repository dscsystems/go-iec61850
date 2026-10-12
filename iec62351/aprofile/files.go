package aprofile

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/dscsystems/go-iec61850/iec62351/pki"
)

// Files names the PEM or DER files of an A-profile configuration.
type Files struct {
	Cert string   // this end's certificate
	Key  string   // its RSA private key (PKCS#8 or PKCS#1)
	CA   []string // trust anchors for the peer's certificate
	CRL  []string // certificate revocation lists
	// Intermediates are CA certificates completing the peer's path.
	Intermediates []string
}

// Load reads the files into a Config with a fresh Verifier. A CRL that
// cannot be checked is treated per policy.
func Load(f Files, policy pki.UnavailablePolicy) (*Config, error) {
	cert, err := readOne(f.Cert, "CERTIFICATE")
	if err != nil {
		return nil, fmt.Errorf("aprofile: certificate %s: %w", f.Cert, err)
	}
	key, err := loadKey(f.Key)
	if err != nil {
		return nil, fmt.Errorf("aprofile: key %s: %w", f.Key, err)
	}
	var anchors []*x509.Certificate
	for _, p := range f.CA {
		ders, err := readAll(p, "CERTIFICATE")
		if err != nil {
			return nil, fmt.Errorf("aprofile: CA %s: %w", p, err)
		}
		for _, der := range ders {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("aprofile: CA %s: %w", p, err)
			}
			anchors = append(anchors, c)
		}
	}
	var crls []*x509.RevocationList
	for _, p := range f.CRL {
		ders, err := readAll(p, "X509 CRL")
		if err != nil {
			return nil, fmt.Errorf("aprofile: CRL %s: %w", p, err)
		}
		for _, der := range ders {
			crl, err := x509.ParseRevocationList(der)
			if err != nil {
				return nil, fmt.Errorf("aprofile: CRL %s: %w", p, err)
			}
			crls = append(crls, crl)
		}
	}
	var inter [][]byte
	for _, p := range f.Intermediates {
		ders, err := readAll(p, "CERTIFICATE")
		if err != nil {
			return nil, fmt.Errorf("aprofile: intermediate %s: %w", p, err)
		}
		inter = append(inter, ders...)
	}
	v := &Verifier{Trust: pki.NewTrustStore(anchors...), Intermediates: inter}
	if len(crls) > 0 {
		v.Revocation = pki.NewRevocationChecker(policy, crls...)
	}
	c := &Config{Credential: Credential{Certificate: cert, Signer: key}, Verifier: v}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// readAll returns the PEM blocks of type typ in the file, or the file
// itself when it is DER. Other block types are skipped, so a CA
// certificate bundled with its CRL serves as either.
func readAll(path, typ string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for rest := b; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type == typ {
			out = append(out, blk.Bytes)
		}
	}
	if len(out) == 0 {
		if len(b) > 0 && b[0] == 0x30 {
			return [][]byte{b}, nil
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
	return nil, errors.New("unrecognised private key format (RSA PKCS#8 or PKCS#1 expected)")
}
