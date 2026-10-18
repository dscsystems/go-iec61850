package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/iec62351"
	"github.com/dscsystems/go-iec61850/internal/tlsflags"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestKey(t *testing.T) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestCA(t *testing.T) *testCA {
	k := newTestKey(t)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, k}
}

// issue writes a leaf and its key as PEM files and returns their paths.
func (ca *testCA) issue(t *testing.T, dir, cn string, serial int64, ips ...net.IP) (string, string, tls.Certificate) {
	k := newTestKey(t)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: ips,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, k.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(k)
	cp, kp := filepath.Join(dir, cn+".pem"), filepath.Join(dir, cn+".key")
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), 0o600)
	return cp, kp, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// TestTLSFlags associates over TLS with the configuration the -tls-* flags
// build, and checks the server name and CRL checks they enable.
func TestTLSFlags(t *testing.T) {
	dir := t.TempDir()
	ca := newTestCA(t)
	caPath := filepath.Join(dir, "ca.der") // DER, as some IEDs export it
	os.WriteFile(caPath, ca.cert.Raw, 0o600)
	_, _, srvCert := ca.issue(t, dir, "server", 2, net.IPv4(127, 0, 0, 1))
	cliCert, cliKey, _ := ca.issue(t, dir, "client", 3)

	m, err := scl.LoadModel("../../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	scfg, err := iec62351.ServerConfig(iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: pool})
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := tls.NewListener(raw, scfg) // Serve takes the listener as given
	go srv.Serve(ln)
	defer srv.Close()
	addr := ln.Addr().String()

	dial := func(f tlsflags.Flags) error {
		cfg, err := f.Config(addr)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := client.Dial(ctx, addr, client.WithTLS(cfg))
		if err != nil {
			return err
		}
		defer c.Close()
		_, err = c.LogicalDevices(ctx)
		return err
	}
	ok := tlsflags.Flags{Cert: cliCert, Key: cliKey, CA: tlsflags.FileList{caPath}}

	if err := dial(ok); err != nil {
		t.Fatalf("TLS association: %v", err)
	}
	wrong := ok
	wrong.ServerName = "ied2"
	if err := dial(wrong); !errors.Is(err, iec62351.ErrServerName) {
		t.Fatalf("a server certificate not naming ied2: %v", err)
	}
	wrong.NoServerName, wrong.ServerName = true, ""
	if err := dial(wrong); err != nil {
		t.Fatalf("-tls-no-server-name: %v", err)
	}

	// A CRL revoking the server certificate (serial 2) refuses it.
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: time.Now()}}},
		ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	crlPath := filepath.Join(dir, "ca.crl")
	os.WriteFile(crlPath, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600)
	revoked := ok
	revoked.CRL = tlsflags.FileList{crlPath}
	if err := dial(revoked); !errors.Is(err, iec62351.ErrRevoked) {
		t.Fatalf("a revoked server certificate: %v", err)
	}

	for name, f := range map[string]tlsflags.Flags{
		"no key": {Cert: cliCert, CA: tlsflags.FileList{caPath}},
		"no CA":  {Cert: cliCert, Key: cliKey},
	} {
		if _, err := f.Config(addr); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
