package aprofile

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	stdasn1 "encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

func setup(t *testing.T) (*pkitest.CA, Credential, *Verifier, time.Time) {
	t.Helper()
	root := pkitest.NewRoot("aprofile CA", pkitest.ECDSAP256)
	leaf := root.NewE2ELeaf([]uint32{1, 3, 9999, 1}, 1, pkitest.LeafOptions{KeyType: pkitest.RSA2048})
	now := time.Date(2026, 10, 12, 21, 30, 0, 0, time.UTC)
	return root, Credential{Certificate: leaf.DER, Signer: leaf.Key},
		&Verifier{Trust: pki.NewTrustStore(root.Cert), Now: func() time.Time { return now }}, now
}

// The encoding checked against encoding/asn1 from the Annex A module
// (DEFINITIONS IMPLICIT TAGS).
func TestEncodingOracle(t *testing.T) {
	_, cred, _, now := setup(t)
	v, err := cred.Sign(now)
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Time) != "20261012213000Z" {
		t.Fatalf("time %q", v.Time)
	}
	type certBased struct {
		Cert []byte `asn1:"tag:0"`
		Time []byte `asn1:"tag:1"`
		Sig  []byte `asn1:"tag:2"`
	}
	inner, _ := stdasn1.MarshalWithParams(certBased{v.Certificate, v.Time, v.Signature}, "tag:0")    // certificate-based [0]
	single, _ := stdasn1.Marshal(stdasn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: inner}) // single-ASN1-type [0]
	want, _ := stdasn1.Marshal(stdasn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: single})  // external [2]
	if got := v.Encode(); !bytes.Equal(got, want) {
		t.Fatalf("encoding\n got % x\nwant % x", got, want)
	}

	v.IndirectReference, v.HasIndirectReference = 7, true
	back, err := Parse(v.Encode())
	if err != nil || back.IndirectReference != 7 || !bytes.Equal(back.Signature, v.Signature) {
		t.Fatalf("round trip with indirect-reference: %+v %v", back, err)
	}
	// Tolerated: no single-ASN1-type wrapper.
	bare, _ := stdasn1.Marshal(stdasn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: inner})
	if _, err := Parse(bare); err != nil {
		t.Fatalf("value without the single-ASN1-type wrapper: %v", err)
	}
	if IsValue([]byte{0x80, 0x01, 'x'}) {
		t.Fatal("a password reads as an A-profile value")
	}
}

func TestVerify(t *testing.T) {
	root, cred, ver, now := setup(t)
	v, _ := cred.Sign(now.Add(-time.Minute))
	if c, err := ver.Verify(v); err != nil || !bytes.Equal(c.Raw, cred.Certificate) {
		t.Fatalf("verify: %v", err)
	}
	if _, err := ver.Verify(v); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	// The same time from another certificate is not a replay.
	other := root.NewE2ELeaf([]uint32{1, 3, 9999, 2}, 1, pkitest.LeafOptions{KeyType: pkitest.RSA2048})
	v2, _ := Credential{Certificate: other.DER, Signer: other.Key}.Sign(now.Add(-time.Minute))
	if _, err := ver.Verify(v2); err != nil {
		t.Fatalf("same time, other certificate: %v", err)
	}

	cases := map[string]struct {
		val  func() *Value
		want error
	}{
		"time ahead":  {func() *Value { v, _ := cred.Sign(now.Add(11 * time.Minute)); return v }, ErrTime},
		"time behind": {func() *Value { v, _ := cred.Sign(now.Add(-11 * time.Minute)); return v }, ErrTime},
		"bad signature": {func() *Value {
			v, _ := cred.Sign(now.Add(-2 * time.Minute))
			v.Signature[0] ^= 1
			return v
		}, ErrSignature},
		"signature over another time": {func() *Value {
			v, _ := cred.Sign(now.Add(-3 * time.Minute))
			w, _ := cred.Sign(now.Add(-4 * time.Minute))
			v.Signature = w.Signature
			return v
		}, ErrSignature},
		"untrusted": {func() *Value {
			stranger := pkitest.NewRoot("other", pkitest.ECDSAP256).NewE2ELeaf([]uint32{1, 3, 9999, 3}, 1,
				pkitest.LeafOptions{KeyType: pkitest.RSA2048})
			v, _ := Credential{Certificate: stranger.DER, Signer: stranger.Key}.Sign(now)
			return v
		}, ErrCertificate},
		"EC key": {func() *Value {
			ec := root.NewE2ELeaf([]uint32{1, 3, 9999, 4}, 1, pkitest.LeafOptions{})
			v, _ := Credential{Certificate: cred.Certificate, Signer: cred.Signer}.Sign(now.Add(-5 * time.Minute))
			v.Certificate = ec.DER
			return v
		}, ErrCertificate},
	}
	for name, c := range cases {
		if _, err := ver.Verify(c.val()); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}

	// A revoked certificate.
	ver.Revocation = pki.NewRevocationChecker(pki.Warn, root.CRL(now.Add(time.Hour), mustParse(t, cred.Certificate)))
	v3, _ := cred.Sign(now.Add(-6 * time.Minute))
	if _, err := ver.Verify(v3); !errors.Is(err, ErrCertificate) {
		t.Errorf("revoked: %v", err)
	}
}

func TestReplayCacheExpires(t *testing.T) {
	_, cred, ver, now := setup(t)
	v, _ := cred.Sign(now)
	if _, err := ver.Verify(v); err != nil {
		t.Fatal(err)
	}
	clock := now.Add(MaxClockSkew + time.Second)
	ver.Now = func() time.Time { return clock }
	if _, err := ver.Verify(v); !errors.Is(err, ErrTime) {
		t.Fatalf("an old value past the window: %v", err)
	}
	fresh, _ := cred.Sign(clock)
	if _, err := ver.Verify(fresh); err != nil {
		t.Fatal(err)
	}
	if n := len(ver.seen[sha256.Sum256(cred.Certificate)]); n != 1 {
		t.Fatalf("cache holds %d time values, want only the fresh one", n)
	}
}

func TestSignRefusesECKeys(t *testing.T) {
	leaf := pkitest.NewRoot("ec", pkitest.ECDSAP256).NewE2ELeaf([]uint32{1, 3}, 1, pkitest.LeafOptions{})
	if _, err := (Credential{Certificate: leaf.DER, Signer: leaf.Key}).Sign(time.Now()); err == nil {
		t.Fatal("signed with an EC key")
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := pki.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c.Certificate
}
