//go:build openssl && cgo

package ossltls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/iec62351"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

type pki struct {
	ca     *x509.Certificate
	caKey  crypto.Signer
	serial int64
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newPKI(t *testing.T) *pki {
	k := rsaKey(t)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ossltls CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{ca: c, caKey: k, serial: 1}
}

func (p *pki) leaf(t *testing.T, cn string, ips ...net.IP) (tls.Certificate, *x509.Certificate) {
	p.serial++
	k := rsaKey(t)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: ips,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, k.Public(), p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: c}, c
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca)
	return pool
}

// pair runs a server handshake on one end of a TCP connection and a client
// on the other, echoing what the client sends.
type endpoint func(raw net.Conn) (net.Conn, error)

func osslEnd(t *testing.T, o iec62351.Options, role Role) endpoint {
	c, err := NewContext(o, role)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return func(raw net.Conn) (net.Conn, error) { return c.Handshake(context.Background(), raw) }
}

func goEnd(t *testing.T, o iec62351.Options, role Role) endpoint {
	var cfg *tls.Config
	var err error
	if role == Server {
		cfg, err = iec62351.ServerConfig(o)
	} else {
		cfg, err = iec62351.ClientConfig(o)
	}
	if err != nil {
		t.Fatal(err)
	}
	return func(raw net.Conn) (net.Conn, error) {
		var c *tls.Conn
		if role == Server {
			c = tls.Server(raw, cfg)
		} else {
			c = tls.Client(raw, cfg)
		}
		return c, c.Handshake()
	}
}

func run(t *testing.T, srv, cli endpoint) (client net.Conn, serverErr <-chan error, err error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	errc := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		c, err := srv(raw)
		if err != nil {
			raw.Close()
			errc <- err
			return
		}
		errc <- nil
		io.Copy(c, c) // echo
		c.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := cli(raw)
	if err != nil {
		raw.Close()
		return nil, errc, err
	}
	t.Cleanup(func() { c.Close() })
	return c, errc, nil
}

func state(c net.Conn) tls.ConnectionState {
	return c.(interface{ ConnectionState() tls.ConnectionState }).ConnectionState()
}

func echo(t *testing.T, c net.Conn, size int) {
	t.Helper()
	msg := bytes.Repeat([]byte("iec62351"), size/8)
	go c.Write(msg)
	got := make([]byte, len(msg))
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("echo of %d octets: %v", len(msg), err)
	}
}

func TestNativeModeNegotiatesDHE(t *testing.T) {
	p := newPKI(t)
	sc, _ := p.leaf(t, "server", net.IPv4(127, 0, 0, 1))
	cc, _ := p.leaf(t, "client")
	srv := osslEnd(t, iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool(), NativeMode: true}, Server)
	// A client offering only the mandatory DHE suite, as devices without
	// ECDHE do.
	cctx, err := newContext(iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), NativeMode: true,
		ServerName: "127.0.0.1"}, Client, "DHE-RSA-AES128-GCM-SHA256")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cctx.Close)
	cli := func(raw net.Conn) (net.Conn, error) { return cctx.Handshake(context.Background(), raw) }
	c, errc, err := run(t, srv, cli)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
	st := state(c)
	if st.CipherSuite != 0x009E || st.Version != tls.VersionTLS12 {
		t.Fatalf("negotiated %s (%#04x), %s", SuiteName(st.CipherSuite), st.CipherSuite, tls.VersionName(st.Version))
	}
	if len(st.PeerCertificates) != 1 || st.PeerCertificates[0].Subject.CommonName != "server" {
		t.Fatalf("peer certificates %v", st.PeerCertificates)
	}
	echo(t, c, 200<<10)

	// Concurrent writers keep their writes whole.
	var wg sync.WaitGroup
	msgs := [][]byte{bytes.Repeat([]byte{'a'}, 40<<10), bytes.Repeat([]byte{'b'}, 40<<10)}
	for _, m := range msgs {
		wg.Add(1)
		go func() { defer wg.Done(); c.Write(m) }()
	}
	got := make([]byte, 80<<10)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	for i := 1; i < len(got); i++ {
		if got[i] != got[i-1] && i != 40<<10 {
			t.Fatalf("writes interleaved at %d", i)
		}
	}
}

func TestNativeModePrefersForwardSecrecy(t *testing.T) {
	p := newPKI(t)
	sc, _ := p.leaf(t, "server", net.IPv4(127, 0, 0, 1))
	cc, _ := p.leaf(t, "client")
	c, errc, err := run(t,
		osslEnd(t, iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool(), NativeMode: true}, Server),
		osslEnd(t, iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), NativeMode: true,
			ServerName: "127.0.0.1"}, Client))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if s := state(c).CipherSuite; s != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("negotiated %s", SuiteName(s))
	}
	// A client offering only RSA key exchange still gets the mandatory 0x003C.
	cctx, err := newContext(iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), NativeMode: true,
		ServerName: "127.0.0.1"}, Client, "AES128-SHA256")
	if err != nil {
		t.Fatal(err)
	}
	defer cctx.Close()
	c2, errc2, err := run(t,
		osslEnd(t, iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool(), NativeMode: true}, Server),
		func(raw net.Conn) (net.Conn, error) { return cctx.Handshake(context.Background(), raw) })
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc2; err != nil {
		t.Fatal(err)
	}
	if s := state(c2).CipherSuite; s != 0x003C {
		t.Fatalf("negotiated %s", SuiteName(s))
	}
	echo(t, c2, 20<<10)
}

func TestInteropWithCryptoTLS(t *testing.T) {
	p := newPKI(t)
	sc, _ := p.leaf(t, "server", net.IPv4(127, 0, 0, 1))
	cc, _ := p.leaf(t, "client")
	so := iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool(), NativeMode: true}
	co := iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), NativeMode: true, ServerName: "127.0.0.1"}
	for name, ends := range map[string][2]endpoint{
		"openssl client, crypto/tls server": {goEnd(t, so, Server), osslEnd(t, co, Client)},
		"crypto/tls client, openssl server": {osslEnd(t, so, Server), goEnd(t, co, Client)},
	} {
		t.Run(name, func(t *testing.T) {
			c, errc, err := run(t, ends[0], ends[1])
			if err != nil {
				t.Fatal(err)
			}
			if err := <-errc; err != nil {
				t.Fatalf("server: %v", err)
			}
			if s := state(c).CipherSuite; s != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
				t.Fatalf("negotiated %s", SuiteName(s))
			}
			echo(t, c, 50<<10)
		})
	}
}

func TestProfile3UsesTLS13(t *testing.T) {
	p := newPKI(t)
	sc, _ := p.leaf(t, "server", net.IPv4(127, 0, 0, 1))
	cc, _ := p.leaf(t, "client")
	c, errc, err := run(t,
		osslEnd(t, iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool()}, Server),
		goEnd(t, iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), ServerName: "127.0.0.1"}, Client))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server: %v", err)
	}
	want := uint16(tls.VersionTLS13)
	if Legacy() {
		want = tls.VersionTLS12 // OpenSSL 1.0.2 has no TLS 1.3
	}
	if v := state(c).Version; v != want {
		t.Fatalf("version %s", tls.VersionName(v))
	}
	echo(t, c, 10<<10)
}

func TestVerification(t *testing.T) {
	p := newPKI(t)
	sc, scert := p.leaf(t, "server", net.IPv4(127, 0, 0, 1))
	cc, _ := p.leaf(t, "client")
	stranger := newPKI(t)
	xc, _ := stranger.leaf(t, "intruder")
	srvOpts := func() iec62351.Options {
		return iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool(), NativeMode: true}
	}
	cliOpts := func() iec62351.Options {
		return iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), NativeMode: true, ServerName: "127.0.0.1"}
	}

	t.Run("wrong server name", func(t *testing.T) {
		o := cliOpts()
		o.ServerName = "ied2"
		var events int
		o.OnEvent = func(iec62351.Event) { events++ }
		_, _, err := run(t, osslEnd(t, srvOpts(), Server), osslEnd(t, o, Client))
		if !errors.Is(err, iec62351.ErrServerName) || events != 1 {
			t.Fatalf("got %v (%d events)", err, events)
		}
	})
	t.Run("untrusted server", func(t *testing.T) {
		o := cliOpts()
		o.Roots = stranger.pool()
		if _, _, err := run(t, osslEnd(t, srvOpts(), Server), osslEnd(t, o, Client)); err == nil {
			t.Fatal("accepted a server outside the trust anchors")
		}
	})
	t.Run("revoked server", func(t *testing.T) {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1),
			ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: scert.SerialNumber, RevocationTime: time.Now()}}},
			p.ca, p.caKey)
		if err != nil {
			t.Fatal(err)
		}
		crl, _ := x509.ParseRevocationList(der)
		o := cliOpts()
		o.CRLs = []*x509.RevocationList{crl}
		if _, _, err := run(t, osslEnd(t, srvOpts(), Server), osslEnd(t, o, Client)); !errors.Is(err, iec62351.ErrRevoked) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("untrusted client refused by the server", func(t *testing.T) {
		o := cliOpts()
		o.Certificates = []tls.Certificate{xc}
		_, errc, _ := run(t, osslEnd(t, srvOpts(), Server), osslEnd(t, o, Client))
		if err := <-errc; err == nil {
			t.Fatal("server accepted a client outside the trust anchors")
		}
	})
	t.Run("client without certificate refused", func(t *testing.T) {
		cfg := &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12}
		cli := func(raw net.Conn) (net.Conn, error) { c := tls.Client(raw, cfg); return c, c.Handshake() }
		_, errc, _ := run(t, osslEnd(t, srvOpts(), Server), cli)
		if err := <-errc; err == nil {
			t.Fatal("server accepted a client without a certificate")
		}
	})
}

func TestHandshakeContextCancelled(t *testing.T) {
	p := newPKI(t)
	cc, _ := p.leaf(t, "client")
	ctx, err := NewContext(iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), NativeMode: true}, Client)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); time.Sleep(2 * time.Second); c.Close() }() // never answers
	raw, _ := net.Dial("tcp", ln.Addr().String())
	cx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := ctx.Handshake(cx, raw); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("cancellation took %v", d)
	}
}

// staticDHServer is a native-mode server with an RSA identity and a
// static-DH certificate from the same CA.
func staticDHServer(t *testing.T) (srv endpoint, client tls.Certificate, roots *x509.CertPool, dh *pkitest.StaticDHLeaf) {
	ca := pkitest.NewRoot("static DH CA", pkitest.RSA2048)
	roots = x509.NewCertPool()
	roots.AddCert(ca.Cert)
	// The RSA identities come from the same CA.
	p := &pki{ca: ca.Cert, caKey: ca.Key, serial: 1}
	identity := func(cn string, ips ...net.IP) tls.Certificate { c, _ := p.leaf(t, cn, ips...); return c }
	dh = ca.NewStaticDHLeaf("server", net.IPv4(127, 0, 0, 1))
	ctx, err := NewContext(iec62351.Options{Certificates: []tls.Certificate{identity("server", net.IPv4(127, 0, 0, 1))}, Roots: roots,
		NativeMode: true}, Server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ctx.Close)
	if err := ctx.SetStaticDH([][]byte{dh.DER}, dh.Key); err != nil {
		t.Fatal(err)
	}
	srv = func(raw net.Conn) (net.Conn, error) { return ctx.Handshake(context.Background(), raw) }
	return srv, identity("client"), roots, dh
}

func TestStaticDH(t *testing.T) {
	if !Legacy() {
		t.Skip("static DH needs a build against OpenSSL 1.0.2")
	}
	for _, suite := range []struct {
		name string
		id   uint16
	}{{"DH-RSA-AES128-GCM-SHA256", 0x00A0}, {"DH-RSA-AES256-GCM-SHA384", 0x00A1}, {"DH-RSA-AES128-SHA", 0x0031}} {
		t.Run(SuiteName(suite.id), func(t *testing.T) {
			srv, cc, roots, dh := staticDHServer(t)
			cctx, err := newContext(iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: roots, NativeMode: true,
				ServerName: "127.0.0.1"}, Client, suite.name)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(cctx.Close)
			c, errc, err := run(t, srv, func(raw net.Conn) (net.Conn, error) { return cctx.Handshake(context.Background(), raw) })
			if err != nil {
				t.Fatal(err)
			}
			if err := <-errc; err != nil {
				t.Fatalf("server: %v", err)
			}
			st := state(c)
			if st.CipherSuite != suite.id {
				t.Fatalf("negotiated %s (%#04x)", SuiteName(st.CipherSuite), st.CipherSuite)
			}
			if len(st.PeerCertificates) == 0 || !bytes.Equal(st.PeerCertificates[0].Raw, dh.DER) {
				t.Fatal("the server did not present its static-DH certificate")
			}
			echo(t, c, 50<<10)
		})
	}

	// With every native-mode suite offered, the server still prefers
	// forward secrecy.
	srv, cc, roots, _ := staticDHServer(t)
	c, errc, err := run(t, srv, osslEnd(t, iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: roots,
		NativeMode: true, ServerName: "127.0.0.1"}, Client))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if s := state(c).CipherSuite; s != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("negotiated %s", SuiteName(s))
	}
}

func TestSetStaticDHChecks(t *testing.T) {
	p := newPKI(t)
	sc, _ := p.leaf(t, "server")
	ctx, err := NewContext(iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool(), NativeMode: true}, Server)
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	ca := pkitest.NewRoot("static DH CA", pkitest.RSA2048)
	dh := ca.NewStaticDHLeaf("server")
	if !Legacy() {
		if err := ctx.SetStaticDH([][]byte{dh.DER}, dh.Key); err == nil {
			t.Fatalf("OpenSSL %s accepted a static-DH certificate", Version())
		}
		return
	}
	rsaKey, _ := x509.MarshalPKCS8PrivateKey(sc.PrivateKey)
	if err := ctx.SetStaticDH([][]byte{sc.Certificate[0]}, rsaKey); err == nil {
		t.Fatal("accepted an RSA certificate as static DH")
	}
	other := ca.NewStaticDHLeaf("server")
	if err := ctx.SetStaticDH([][]byte{dh.DER}, other.Key); err == nil {
		t.Fatal("accepted a DH key that does not match the certificate")
	}
	cli, err := NewContext(iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool()}, Client)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := cli.SetStaticDH([][]byte{dh.DER}, dh.Key); err == nil {
		t.Fatal("a client context accepted a static-DH certificate")
	}
}

// OpenSSL 1.0.2 cannot switch renegotiation off; the engine drops a
// connection whose peer starts one. (OpenSSL 3 refuses it itself.)
func TestRenegotiationRefused(t *testing.T) {
	if !Legacy() {
		t.Skip("OpenSSL 3 refuses renegotiation with SSL_OP_NO_RENEGOTIATION")
	}
	p := newPKI(t)
	sc, _ := p.leaf(t, "server", net.IPv4(127, 0, 0, 1))
	cc, _ := p.leaf(t, "client")
	sctx, err := NewContext(iec62351.Options{Certificates: []tls.Certificate{sc}, Roots: p.pool(), NativeMode: true}, Server)
	if err != nil {
		t.Fatal(err)
	}
	defer sctx.Close()
	cctx, err := NewContext(iec62351.Options{Certificates: []tls.Certificate{cc}, Roots: p.pool(), NativeMode: true,
		ServerName: "127.0.0.1"}, Client)
	if err != nil {
		t.Fatal(err)
	}
	defer cctx.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		c, err := sctx.Handshake(context.Background(), raw)
		if err != nil {
			srvErr <- err
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		for {
			if _, err := c.Read(buf); err != nil {
				srvErr <- err
				return
			}
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	nc, err := cctx.Handshake(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	c := nc.(*Conn)
	if _, err := c.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if err := c.renegotiate(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-srvErr:
		if !errors.Is(err, ErrRenegotiation) {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the server did not drop the renegotiating client")
	}
}
