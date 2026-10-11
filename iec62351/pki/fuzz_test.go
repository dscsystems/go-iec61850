package pki_test

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

func FuzzParseCertificate(f *testing.F) {
	root := pkitest.NewRoot("root", pkitest.ECDSAP256)
	f.Add(root.NewE2ELeaf(asn1.OID{1, 3, 9999, 1}, 1, pkitest.LeafOptions{}).DER)
	f.Add(root.Cert.Raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		if c, err := pki.ParseCertificate(b); err == nil {
			pki.EndEntityProfile(c)
		}
	})
}
