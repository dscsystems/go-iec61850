// Command e2e-pki creates IEC 62351-4 E2E credentials for laboratories and
// commissioning: a test CA, end-entity certificates whose subject is an
// AE-title object identifier (IEC 62351-4 G.6.2), and certificate signing
// requests with that subject and key usage for a production CA.
//
//	e2e-pki init  -dir pki                                   # test root CA
//	e2e-pki issue -dir pki -ae 1.3.9999.1/1 -name inner      # leaf from the test CA
//	e2e-pki csr   -ae 1.3.9999.1/1 -key inner.key -out inner.csr [-rsa]
//	e2e-pki show  cert.pem                                   # print the AE title
//
// The test CA is not for production use.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dscsystems/go-iec61850/iec62351/e2e/e2efile"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "issue":
		err = cmdIssue(os.Args[2:])
	case "csr":
		err = cmdCSR(os.Args[2:])
	case "show":
		err = cmdShow(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e-pki:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: e2e-pki init|issue|csr|show [flags]")
	os.Exit(2)
}

func keyType(rsa bool) pkitest.KeyType {
	if rsa {
		return pkitest.RSA2048
	}
	return pkitest.ECDSAP256
}

func write(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return err
	}
	fmt.Println("wrote", path)
	return nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "pki", "output directory")
	name := fs.String("name", "IEC 62351-4 test root", "CA common name")
	rsa := fs.Bool("rsa", false, "RSA-2048 instead of ECDSA P-256")
	fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	ca := pkitest.NewRoot(*name, keyType(*rsa))
	if err := write(filepath.Join(*dir, "ca.pem"), pkitest.PEM(ca.Cert.Raw), 0o644); err != nil {
		return err
	}
	return write(filepath.Join(*dir, "ca.key"), pkitest.KeyPEM(ca.Key), 0o600)
}

func loadCA(dir string) (*pkitest.CA, error) {
	cb, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(cb)
	if blk == nil {
		return nil, fmt.Errorf("ca.pem: no PEM block")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	kblk, _ := pem.Decode(kb)
	if kblk == nil {
		return nil, fmt.Errorf("ca.key: no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, err
	}
	return &pkitest.CA{Cert: cert, Key: k.(crypto.Signer)}, nil
}

func cmdIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dir := fs.String("dir", "pki", "CA directory (from init)")
	aeText := fs.String("ae", "", "AE title <AP-title OID>/<AE-qualifier>")
	name := fs.String("name", "e2e", "output file base name")
	rsa := fs.Bool("rsa", false, "RSA-2048 instead of ECDSA P-256")
	fs.Parse(args)
	ae, err := e2efile.ParseAETitle(*aeText)
	if err != nil {
		return err
	}
	ca, err := loadCA(*dir)
	if err != nil {
		return err
	}
	leaf := ca.NewE2ELeaf(ae.APTitle, ae.AEQualifier, pkitest.LeafOptions{KeyType: keyType(*rsa)})
	if err := write(filepath.Join(*dir, *name+".pem"), pkitest.PEM(leaf.DER), 0o644); err != nil {
		return err
	}
	return write(filepath.Join(*dir, *name+".key"), pkitest.KeyPEM(leaf.Key), 0o600)
}

func cmdCSR(args []string) error {
	fs := flag.NewFlagSet("csr", flag.ExitOnError)
	aeText := fs.String("ae", "", "AE title <AP-title OID>/<AE-qualifier>")
	keyPath := fs.String("key", "e2e.key", "private key output file")
	out := fs.String("out", "e2e.csr", "CSR output file")
	rsa := fs.Bool("rsa", false, "RSA-2048 instead of ECDSA P-256")
	fs.Parse(args)
	ae, err := e2efile.ParseAETitle(*aeText)
	if err != nil {
		return err
	}
	key := pkitest.NewKey(keyType(*rsa))
	// keyUsage: digitalSignature (bit 0) and keyAgreement (bit 4), critical.
	ku, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0x88}, BitLength: 5})
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		RawSubject: pki.OIDName(pki.ProvisionalAEAttributeType, ae.OID()),
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: ku},
		},
	}, key)
	if err != nil {
		return err
	}
	if err := write(*keyPath, pkitest.KeyPEM(key), 0o600); err != nil {
		return err
	}
	return write(*out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0o644)
}

func cmdShow(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("show <certificate>")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	der := b
	if blk, _ := pem.Decode(b); blk != nil {
		der = blk.Bytes
	}
	c, err := pki.ParseCertificate(der)
	if err != nil {
		return err
	}
	fmt.Printf("subject AE title OID: %v (attribute type %v)\n", c.SubjectOID, c.SubjectOIDType)
	fmt.Printf("issuer: %v\nvalid: %v .. %v\n", c.Issuer, c.NotBefore, c.NotAfter)
	if err := pki.EndEntityProfile(c); err != nil {
		fmt.Println("profile:", err)
	} else {
		fmt.Println("profile: conforms to IEC 62351-4 Annex G (as checked by this module)")
	}
	return nil
}
