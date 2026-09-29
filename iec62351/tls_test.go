package iec62351_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/iec62351"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

type ca struct {
	cert   *x509.Certificate
	key    crypto.Signer
	serial int64
}

func newCA(t *testing.T, name string) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert: cert, key: key, serial: 1}
}

// issue signs a leaf for cn with key (a new P-256 key when nil). sans are
// DNS names; none leaves the subject alternative name out, as IED
// certificates often do.
func (c *ca) issue(t *testing.T, cn string, key crypto.Signer, sans ...string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	c.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(c.serial),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

func (c *ca) crl(t *testing.T, next time.Time, revoked ...*x509.Certificate) *x509.RevocationList {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, r := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: r.SerialNumber, RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: next,
		RevokedCertificateEntries: entries,
	}, c.cert, c.key)
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := x509.ParseRevocationList(der)
	return crl
}

func (c *ca) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// serve starts an MMS server under the profile and returns its address
// and the events it logged.
func serve(t *testing.T, o iec62351.Options) (string, func() []iec62351.Event) {
	t.Helper()
	var mu sync.Mutex
	var events []iec62351.Event
	o.OnEvent = func(e iec62351.Event) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	cfg, err := iec62351.ServerConfig(o)
	if err != nil {
		t.Fatal(err)
	}
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m, server.WithTLS(cfg))
	go srv.Serve(tls.NewListener(ln, cfg))
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), func() []iec62351.Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]iec62351.Event(nil), events...)
	}
}

// dial associates under the profile and reads one value.
func dial(t *testing.T, addr string, o iec62351.Options) error {
	t.Helper()
	cfg, err := iec62351.ClientConfig(o)
	if err != nil {
		t.Fatal(err)
	}
	return dialWith(addr, cfg)
}

func dialWith(addr string, cfg *tls.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTLS(cfg), client.WithTimeout(2*time.Second))
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Read(ctx, "simpleIOGenericIO/GGIO1.AnIn1.mag.f", model.MX)
	return err
}

func TestMutualAuthentication(t *testing.T) {
	root := newCA(t, "root")
	srvCert, _ := root.issue(t, "ied1", nil)
	cliCert, _ := root.issue(t, "scada", nil)
	addr, events := serve(t, iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool()})

	// Both ends authenticated: the association works, and a server named
	// by its common name (no subject alternative name) is recognised.
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{cliCert}, Roots: root.pool(), ServerName: "ied1"}); err != nil {
		t.Fatalf("authenticated client: %v", err)
	}
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{cliCert}, Roots: root.pool(), ServerName: "ied2"}); err == nil {
		t.Error("the client accepted a server certificate naming another IED")
	}

	// A client without a certificate is refused.
	noCert := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	if err := dialWith(addr, noCert); err == nil {
		t.Error("a client without a certificate was served")
	}

	// A client whose certificate another authority issued is refused.
	other := newCA(t, "other")
	strangerCert, _ := other.issue(t, "stranger", nil)
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{strangerCert}, Roots: root.pool()}); err == nil {
		t.Error("a client from another authority was served")
	}
	if len(events()) == 0 {
		t.Error("the refused clients were not reported")
	}

	// A client refuses a server from another authority.
	addr2, _ := serve(t, iec62351.Options{Certificates: []tls.Certificate{strangerCert}, Roots: root.pool()})
	if err := dial(t, addr2, iec62351.Options{Certificates: []tls.Certificate{cliCert}, Roots: root.pool()}); err == nil {
		t.Error("the client accepted a server from another authority")
	}
}

func TestProtocolFloor(t *testing.T) {
	root := newCA(t, "root")
	srvCert, _ := root.issue(t, "ied1", nil)
	cliCert, _ := root.issue(t, "scada", nil)
	addr, _ := serve(t, iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool()})
	old := &tls.Config{Certificates: []tls.Certificate{cliCert}, InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	if err := dialWith(addr, old); err == nil {
		t.Error("TLS 1.1 was accepted")
	}
	weakSuite := &tls.Config{Certificates: []tls.Certificate{cliCert}, InsecureSkipVerify: true,
		MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}}
	if err := dialWith(addr, weakSuite); err == nil {
		t.Error("a CBC cipher suite was accepted")
	}
	cfg, _ := iec62351.ServerConfig(iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool(), TLS13Only: true})
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Error("TLS13Only does not raise the floor")
	}
}

func TestRevocation(t *testing.T) {
	root := newCA(t, "root")
	srvCert, _ := root.issue(t, "ied1", nil)
	cliCert, _ := root.issue(t, "scada", nil)
	revokedCert, revokedLeaf := root.issue(t, "former-employee", nil)

	fresh := root.crl(t, time.Now().Add(time.Hour), revokedLeaf)
	addr, events := serve(t, iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool(),
		CRLs: []*x509.RevocationList{fresh}})
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{cliCert}, Roots: root.pool()}); err != nil {
		t.Fatalf("unrevoked client: %v", err)
	}
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{revokedCert}, Roots: root.pool()}); err == nil {
		t.Error("a revoked client was served")
	}
	found := false
	for _, e := range events() {
		found = found || errors.Is(e.Err, iec62351.ErrRevoked)
	}
	if !found {
		t.Errorf("no revocation event: %v", events())
	}

	// A CRL past its next update fails closed, unless allowed.
	stale := root.crl(t, time.Now().Add(-time.Minute))
	addr, _ = serve(t, iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool(),
		CRLs: []*x509.RevocationList{stale}})
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{cliCert}, Roots: root.pool()}); err == nil {
		t.Error("a stale CRL did not fail the connection")
	}
	addr, _ = serve(t, iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool(),
		CRLs: []*x509.RevocationList{stale}, AllowStaleCRL: true})
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{cliCert}, Roots: root.pool()}); err != nil {
		t.Errorf("stale CRL allowed: %v", err)
	}
}

func TestKeyStrengthAndPinning(t *testing.T) {
	root := newCA(t, "root")
	srvCert, _ := root.issue(t, "ied1", nil)
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	weakCert, _ := root.issue(t, "legacy", weak)
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCert, _ := root.issue(t, "rsa-client", strong)
	pinnedCert, pinnedLeaf := root.issue(t, "pinned", nil)

	addr, _ := serve(t, iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool()})
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{weakCert}, Roots: root.pool()}); err == nil {
		t.Error("a 1024-bit RSA client was served")
	}
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{rsaCert}, Roots: root.pool()}); err != nil {
		t.Errorf("2048-bit RSA client: %v", err)
	}

	addr, _ = serve(t, iec62351.Options{Certificates: []tls.Certificate{srvCert}, Roots: root.pool(),
		AllowedPeers: []*x509.Certificate{pinnedLeaf}})
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{pinnedCert}, Roots: root.pool()}); err != nil {
		t.Errorf("pinned client: %v", err)
	}
	if err := dial(t, addr, iec62351.Options{Certificates: []tls.Certificate{rsaCert}, Roots: root.pool()}); err == nil {
		t.Error("a client outside the allowed set was served")
	}
}

func TestOptionsRequired(t *testing.T) {
	if _, err := iec62351.ServerConfig(iec62351.Options{}); err == nil {
		t.Error("a configuration without an identity")
	}
	root := newCA(t, "root")
	c, _ := root.issue(t, "x", nil)
	if _, err := iec62351.ClientConfig(iec62351.Options{Certificates: []tls.Certificate{c}}); err == nil {
		t.Error("a configuration without roots")
	}
}
