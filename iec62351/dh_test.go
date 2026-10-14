package iec62351_test

import (
	"crypto/x509"
	"errors"
	"net"
	"testing"

	"github.com/dscsystems/go-iec61850/iec62351"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

// A peer certificate with a fixed Diffie-Hellman key (the static-DH
// suites) passes the profile's checks: crypto/x509 leaves the key
// unparsed, and the prime size stands in for the key strength.
func TestVerifyPeerStaticDHCertificate(t *testing.T) {
	ca := pkitest.NewRoot("dh CA", pkitest.RSA2048)
	dh := ca.NewStaticDHLeaf("ied", net.IPv4(127, 0, 0, 1))
	if bits, ok := iec62351.DHPrimeBits(dh.Cert); !ok || bits != 2048 {
		t.Fatalf("DHPrimeBits = %d, %v", bits, ok)
	}
	if _, ok := iec62351.DHPrimeBits(ca.Cert); ok {
		t.Fatal("an RSA certificate reported as DH")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	o := iec62351.Options{Roots: roots, ServerName: "127.0.0.1"}
	if err := o.VerifyPeer([]*x509.Certificate{dh.Cert}); err != nil {
		t.Fatal(err)
	}
	o.Roots = x509.NewCertPool()
	if err := o.VerifyPeer([]*x509.Certificate{dh.Cert}); err == nil || errors.Is(err, iec62351.ErrWeakKey) {
		t.Fatalf("untrusted DH certificate: %v", err)
	}
}
