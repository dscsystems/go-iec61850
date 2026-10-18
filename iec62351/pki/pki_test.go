package pki_test

import (
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

var ap = asn1.OID{1, 3, 9999, 1, 10}

func TestParseOIDSubject(t *testing.T) {
	root := pkitest.NewRoot("root", pkitest.ECDSAP256)
	leaf := root.NewE2ELeaf(ap, 12, pkitest.LeafOptions{})
	c, err := pki.ParseCertificate(leaf.DER)
	if err != nil {
		t.Fatal(err)
	}
	if !c.SubjectOID.Equal(asn1.OID{1, 3, 9999, 1, 10, 12}) {
		t.Fatalf("subject OID %v", c.SubjectOID)
	}
	if err := c.CheckSignatureFrom(root.Cert); err != nil {
		t.Fatalf("signature over the original TBS: %v", err)
	}
	if err := pki.EndEntityProfile(c); err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckIdentity(c, pki.AETitleOID(ap, 12), nil); err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckIdentity(c, pki.AETitleOID(ap, 13), nil); !errors.Is(err, pki.ErrIdentity) {
		t.Fatalf("mismatch accepted: %v", err)
	}
}

func TestVerifyPath(t *testing.T) {
	root := pkitest.NewRoot("root", pkitest.RSA2048)
	inter := root.NewIntermediate("issuing", pkitest.ECDSAP256)
	leaf := inter.NewE2ELeaf(ap, 1, pkitest.LeafOptions{KeyType: pkitest.RSA2048})
	store := pki.NewTrustStore(root.Cert)
	opts := pki.PathOptions{Roots: store, Intermediates: [][]byte{inter.Cert.Raw}}
	chain, err := pki.Verify(leaf.Cert, opts)
	if err != nil || len(chain) != 3 {
		t.Fatalf("chain %d %v", len(chain), err)
	}
	// Missing intermediate.
	if _, err := pki.Verify(leaf.Cert, pki.PathOptions{Roots: store}); !errors.Is(err, pki.ErrPath) {
		t.Fatalf("missing intermediate: %v", err)
	}
	// Revoked.
	opts.Revocation = pki.NewRevocationChecker(pki.Warn, inter.CRL(time.Now().Add(time.Hour), leaf.Cert.Certificate))
	if _, err := pki.Verify(leaf.Cert, opts); !errors.Is(err, pki.ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	// Stale CRL: warn accepts and reports, fail-closed refuses.
	reported := map[pki.RevocationStatus]bool{}
	opts.Revocation = pki.NewRevocationChecker(pki.Warn, inter.CRL(time.Now().Add(-time.Minute)))
	opts.OnStatus = func(_ *x509.Certificate, s pki.RevocationStatus) { reported[s] = true }
	if _, err := pki.Verify(leaf.Cert, opts); err != nil || !reported[pki.Unavailable] {
		t.Fatalf("stale warn: %v %v", err, reported)
	}
	opts.Revocation.Policy = pki.FailClosed
	if _, err := pki.Verify(leaf.Cert, opts); !errors.Is(err, pki.ErrRevocationState) {
		t.Fatalf("stale fail-closed: %v", err)
	}
	// Expired.
	old := inter.NewE2ELeaf(ap, 1, pkitest.LeafOptions{NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-24 * time.Hour)})
	if _, err := pki.Verify(old.Cert, pki.PathOptions{Roots: store, Intermediates: [][]byte{inter.Cert.Raw}}); !errors.Is(err, pki.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
}

// TestRevocationUnavailable checks that CRLs which cannot show a
// certificate current give Unavailable, not Good or Unknown.
func TestRevocationUnavailable(t *testing.T) {
	root := pkitest.NewRoot("root", pkitest.ECDSAP256)
	leaf := root.NewE2ELeaf(ap, 1, pkitest.LeafOptions{})
	now := time.Now()
	undated := *root.CRL(now.Add(time.Hour))
	undated.NextUpdate = time.Time{}
	impostor := pkitest.NewRoot("root", pkitest.ECDSAP256).CRL(now.Add(time.Hour))
	for name, crl := range map[string]*x509.RevocationList{
		"no next update": &undated,
		"wrong signer":   impostor,
	} {
		r := pki.NewRevocationChecker(pki.Warn, crl)
		if s := r.Status(leaf.Cert.Certificate, root.Cert, now); s != pki.Unavailable {
			t.Errorf("%s: status %v, want Unavailable", name, s)
		}
	}
	current := pki.NewRevocationChecker(pki.Warn, root.CRL(now.Add(time.Hour)))
	if s := current.Status(leaf.Cert.Certificate, root.Cert, now); s != pki.Good {
		t.Errorf("current CRL: status %v", s)
	}
	// Before the CRL's thisUpdate (an hour ago) it is not yet valid.
	if s := current.Status(leaf.Cert.Certificate, root.Cert, now.Add(-2*time.Hour)); s != pki.Unavailable {
		t.Errorf("CRL not yet valid: status %v, want Unavailable", s)
	}
}

func TestProfile(t *testing.T) {
	root := pkitest.NewRoot("root", pkitest.ECDSAP256)
	noKA := root.NewE2ELeaf(ap, 1, pkitest.LeafOptions{KeyUsage: x509.KeyUsageDigitalSignature})
	if err := pki.EndEntityProfile(noKA.Cert); !errors.Is(err, pki.ErrProfile) {
		t.Fatalf("missing keyAgreement accepted: %v", err)
	}
	weak := root.NewE2ELeaf(ap, 1, pkitest.LeafOptions{KeyType: pkitest.RSA1024})
	if err := pki.EndEntityProfile(weak.Cert); !errors.Is(err, pki.ErrProfile) {
		t.Fatalf("1024-bit RSA accepted: %v", err)
	}
	ca := root.NewE2ELeaf(ap, 1, pkitest.LeafOptions{
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign})
	if err := pki.EndEntityProfile(ca.Cert); !errors.Is(err, pki.ErrProfile) {
		t.Fatalf("keyCertSign accepted in an end entity: %v", err)
	}
	big := root.NewE2ELeaf(ap, 1, pkitest.LeafOptions{Padding: 9000})
	if _, err := pki.ParseCertificate(big.DER); !errors.Is(err, pki.ErrCertTooLarge) {
		t.Fatalf("oversized: %v", err)
	}
}
