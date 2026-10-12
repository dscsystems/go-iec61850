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

func TestEdition2018DiagnosticMapping(t *testing.T) {
	if d := Edition2018.diagFor(PhaseHandshake, HDAltSigMismatch); d != HDProtocolError {
		t.Fatalf("altSig-mismatch under 2018 = %d", d)
	}
	if d := Edition2018.diagFor(PhaseHandshake, HDInvalidAttributeCertificate); d != HDInvalidAttributeCertificate {
		t.Fatalf("value 16 under 2018 = %d", d)
	}
	if d := Edition2020.diagFor(PhaseHandshake, HDAltSigMismatch); d != HDAltSigMismatch {
		t.Fatal("2020 must keep AMD1 values")
	}
	if d := Edition2018.diagFor(PhaseData, DDUnexpectedChangedKey); d != DDUnexpectedChangedKey {
		t.Fatal("data diagnostics are the same in both editions")
	}
}
