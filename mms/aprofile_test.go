package mms

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/iec62351/aprofile"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
	"github.com/dscsystems/go-iec61850/internal/osi/acse"
	"github.com/dscsystems/go-iec61850/internal/osi/session"
)

type apFixture struct {
	root     *pkitest.CA
	cli, srv *aprofile.Config
}

func newAPFixture(t *testing.T) *apFixture {
	t.Helper()
	root := pkitest.NewRoot("A-profile CA", pkitest.RSA2048)
	cfg := func(q int32) *aprofile.Config {
		l := root.NewE2ELeaf([]uint32{1, 3, 9999, 50}, q, pkitest.LeafOptions{KeyType: pkitest.RSA2048})
		return &aprofile.Config{Credential: aprofile.Credential{Certificate: l.DER, Signer: l.Key},
			Verifier: &aprofile.Verifier{Trust: pki.NewTrustStore(root.Cert)}, AllowWithoutTLS: true}
	}
	return &apFixture{root: root, cli: cfg(1), srv: cfg(2)}
}

func apDial(t *testing.T, opts AcceptOptions, cli *aprofile.Config) (*Conn, <-chan error, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	done := serveOne(t, ln, opts)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, ln.Addr().String(), Options{AProfile: cli, ConnectTimeout: 3 * time.Second})
	return c, done, err
}

func TestAProfileAssociation(t *testing.T) {
	f := newAPFixture(t)
	var seen AssociationRequest
	c, done, err := apDial(t, AcceptOptions{AProfile: f.srv, AProfileRequired: true,
		Authenticate: func(ar AssociationRequest) error { seen = ar; return nil }}, f.cli)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if pc := c.PeerAProfileCertificate(); pc == nil || !bytes.Equal(pc.Raw, f.srv.Credential.Certificate) {
		t.Fatal("client did not keep the server's A-profile certificate")
	}
	if seen.AProfile == nil || !bytes.Equal(seen.AProfile.Raw, f.cli.Credential.Certificate) {
		t.Fatal("the authenticator did not see the client's certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if st, err := c.Status(ctx, false); err != nil || st.Physical != 1 {
		t.Fatalf("status over the association: %+v %v", st, err)
	}
	c.Close()
	<-done
}

func TestAProfileLegacyMechanismEchoed(t *testing.T) {
	f := newAPFixture(t)
	f.cli.Mechanism = aprofile.LegacyMechanism
	var trace [][]byte
	opts := AcceptOptions{AProfile: f.srv, Trace: func(ev string, b []byte) {
		if ev == "tx AARE" {
			trace = append(trace, b)
		}
	}}
	c, done, err := apDial(t, opts, f.cli)
	if err != nil {
		t.Fatalf("dial with the 2007 mechanism-name: %v", err)
	}
	c.Close()
	<-done
	res, err := acse.ParseAARE(trace[0])
	if err != nil || !res.Mechanism.Equal(aprofile.LegacyMechanism) || !res.ResponderAuth {
		t.Fatalf("AARE mechanism %v (responder auth %v), want the client's echoed: %v", res.Mechanism, res.ResponderAuth, err)
	}
}

func TestAProfileRefusals(t *testing.T) {
	t.Run("untrusted client is aborted", func(t *testing.T) {
		f := newAPFixture(t)
		other := newAPFixture(t)
		f.cli.Credential = other.cli.Credential
		_, done, err := apDial(t, AcceptOptions{AProfile: f.srv}, f.cli)
		if !errors.Is(err, session.ErrAborted) {
			t.Fatalf("client: %v, want a P-ABORT", err)
		}
		var ae *AProfileError
		if serr := <-done; !errors.As(serr, &ae) || !errors.Is(serr, aprofile.ErrCertificate) {
			t.Fatalf("server: %v", serr)
		}
	})
	t.Run("client clock 20 minutes ahead is aborted", func(t *testing.T) {
		f := newAPFixture(t)
		f.cli.Verifier.Now = func() time.Time { return time.Now().Add(20 * time.Minute) }
		_, done, err := apDial(t, AcceptOptions{AProfile: f.srv}, f.cli)
		if !errors.Is(err, session.ErrAborted) {
			t.Fatalf("client: %v", err)
		}
		if serr := <-done; !errors.Is(serr, aprofile.ErrTime) {
			t.Fatalf("server: %v", serr)
		}
	})
	t.Run("server without the profile is abandoned by the client", func(t *testing.T) {
		f := newAPFixture(t)
		_, _, err := apDial(t, AcceptOptions{}, f.cli)
		var ae *AProfileError
		if !errors.As(err, &ae) {
			t.Fatalf("client: %v", err)
		}
	})
	t.Run("untrusted server is abandoned by the client", func(t *testing.T) {
		f := newAPFixture(t)
		f.srv.Credential = newAPFixture(t).srv.Credential
		_, _, err := apDial(t, AcceptOptions{AProfile: f.srv}, f.cli)
		if !errors.Is(err, aprofile.ErrCertificate) {
			t.Fatalf("client: %v", err)
		}
	})
	t.Run("plain client refused when required", func(t *testing.T) {
		f := newAPFixture(t)
		_, _, err := apDial(t, AcceptOptions{AProfile: f.srv, AProfileRequired: true}, nil)
		var re *RejectedError
		// 11.2.3.2 b): no mechanism-name at all.
		if !errors.As(err, &re) || re.Diagnostic != acse.DiagAuthMechanismRequired || !errors.Is(err, ErrAuthenticationFailed) {
			t.Fatalf("client: %v", err)
		}
	})
	t.Run("plain client accepted when optional", func(t *testing.T) {
		f := newAPFixture(t)
		c, done, err := apDial(t, AcceptOptions{AProfile: f.srv}, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		<-done
	})
	t.Run("no TLS without AllowWithoutTLS", func(t *testing.T) {
		f := newAPFixture(t)
		f.cli.AllowWithoutTLS = false
		if _, _, err := apDial(t, AcceptOptions{AProfile: f.srv}, f.cli); err == nil {
			t.Fatal("the A-profile was used on plain TCP")
		}
	})
}
