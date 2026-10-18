//go:build openssl && cgo

package mms

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/iec62351"
	"github.com/dscsystems/go-iec61850/iec62351/ossltls"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

// An association over the OpenSSL engine in native mode, both ends, with
// the A-profile required and no AllowWithoutTLS: the server must see the
// connection as TLS.
func TestAProfileOverOpenSSLTLS(t *testing.T) {
	f := newAPFixture(t)
	f.cli.AllowWithoutTLS, f.srv.AllowWithoutTLS = false, false

	root := pkitest.NewRoot("tls CA", pkitest.RSA2048)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	// TLS certificates carry an ordinary subject: OpenSSL does not parse the
	// AE-title subject of E2E certificates, and IEC 62351-4 G.2 keeps the two
	// credentials apart anyway.
	id := func(q int32) tls.Certificate {
		name, _ := stdasn1.Marshal(pkix.Name{CommonName: "tls-" + string(rune('0'+q))}.ToRDNSequence())
		l := root.NewE2ELeaf([]uint32{1, 3, 9999, 60}, q, pkitest.LeafOptions{KeyType: pkitest.RSA2048, Subject: name})
		return tls.Certificate{Certificate: [][]byte{l.DER}, PrivateKey: l.Key}
	}
	srvCtx, err := ossltls.NewContext(iec62351.Options{Certificates: []tls.Certificate{id(1)}, Roots: pool, NativeMode: true}, ossltls.Server)
	if err != nil {
		t.Fatal(err)
	}
	defer srvCtx.Close()
	// The A-profile, not TLS, identifies the server here (OID subject).
	cliCtx, err := ossltls.NewContext(iec62351.Options{Certificates: []tls.Certificate{id(2)}, Roots: pool, NativeMode: true,
		AnyServerName: true}, ossltls.Client)
	if err != nil {
		t.Fatal(err)
	}
	defer cliCtx.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var seen AssociationRequest
	done := serveOne(t, srvCtx.Listener(ln), AcceptOptions{AProfile: f.srv, AProfileRequired: true,
		Authenticate: func(ar AssociationRequest) error { seen = ar; return nil }})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, ln.Addr().String(), Options{TLSHandshake: cliCtx.Handshake, AProfile: f.cli})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if seen.TLS == nil || seen.TLS.Version != tls.VersionTLS12 || seen.AProfile == nil {
		t.Fatalf("server saw TLS %+v, A-profile %v", seen.TLS, seen.AProfile != nil)
	}
	if st, err := c.Status(ctx, false); err != nil || st.Physical != 1 {
		t.Fatalf("status: %+v %v", st, err)
	}
	c.Close()
	<-done
}
