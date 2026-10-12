package e2e

import (
	"testing"

	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

func TestEdition2018Association(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.RSA2048)
	f.cli.Policy.Edition, f.srv.Policy.Edition = Edition2018, Edition2018
	c, s := establish(t, f)
	transfer(t, c, s)
	transfer(t, s, c)
}

func TestEditionMismatch(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f.cli.Policy.Edition = Edition2018
	c, err := NewClient(f.cli)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(f.srv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := c.HandshakeRequest(appl)
	if err != nil {
		t.Fatal(err)
	}
	// The 2018 token puts a GeneralizedTime where 2020 expects
	// DiffieHellmanSet: a protocol error, not a security failure.
	_, err = s.ProcessHandshakeRequest(content(t, req), clientAE)
	wantHS(t, err, HDProtocolError, AlarmNone)
}

func TestDiagnosticWireMapping(t *testing.T) {
	ed18 := &Policy{Edition: Edition2018}
	amd1 := &Policy{Corrections: CorrectionsNone}
	tis := &Policy{}
	cases := []struct {
		p    *Policy
		in   int
		want int
	}{
		{ed18, HDAltSigMismatch, HDProtocolError},
		{ed18, HDInvalidAttributeCertificate, HDInvalidAttributeCertificate},
		{amd1, HDAltSigMismatch, 19},
		{amd1, HDSingleICVAlgoRequired, 26},
		{tis, HDAEIsRequired, 18},
		{tis, HDAltSigMismatch, HDProtocolError},
		{tis, HDAEASelectButEncrypNotSupp, 19},
		{tis, HDSingleICVAlgoRequired, 25},
		{tis, -1, -1},
	}
	for _, c := range cases {
		if got := c.p.hdToWire(c.in); got != c.want {
			t.Errorf("%+v: %s → %d, want %d", *c.p, HandshakeDiagName(c.in), got, c.want)
		}
	}
	for w := 0; w <= 25; w++ {
		if d := tis.hdFromWire(w); tis.hdToWire(d) != w {
			t.Errorf("TISSUE 94 numbering does not round-trip at %d", w)
		}
	}
}
