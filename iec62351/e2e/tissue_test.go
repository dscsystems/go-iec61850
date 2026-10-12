package e2e

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

// TISSUE 52: a corrected peer offers id-aesNNN-GMAC; an uncorrected one
// knows only aesNNN-GCM. The server echoes the client's identifier and both
// ends keep using it, so mixed pairs interoperate.
func TestTissue52GMACIdentifiers(t *testing.T) {
	for _, c := range []struct {
		name     string
		cli, srv Corrections
		want     asn1.OID
	}{
		{"corrected pair", CorrectionsInForce, CorrectionsInForce, oidAES256GMAC},
		{"corrected client, AMD1 server", CorrectionsInForce, CorrectionsNone, oidAES256GMAC},
		{"AMD1 client, corrected server", CorrectionsNone, CorrectionsInForce, oidAES256GCM},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
			f.cli.Policy.ICVAlgs = []ICVAlg{ICVGMACAES256}
			f.srv.Policy.ICVAlgs = []ICVAlg{ICVGMACAES256}
			f.cli.Policy.Corrections, f.srv.Policy.Corrections = c.cli, c.srv
			cl, sv := establish(t, f)
			for _, a := range []*Association{cl, sv} {
				if !a.icvID.Algorithm.Equal(c.want) {
					t.Fatalf("%v uses %v, want %v", a.role, a.icvID.Algorithm, c.want)
				}
			}
			transfer(t, cl, sv)
			transfer(t, sv, cl)
		})
	}
}

// TISSUE 97: without authorization configured, an attribute certificate is
// ignored, not refused.
func TestTissue97AttCertIgnored(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	cl, _ := NewClient(f.cli)
	sv, _ := NewServer(f.srv)
	req, _ := cl.HandshakeRequest(appl)
	s, err := ParseSigned(KindHandshakeReq, content(t, req))
	if err != nil {
		t.Fatal(err)
	}
	s.Token1.AttCert = []byte{0x30, 0x00}
	req, err = encodeSigned(s, cl.signFn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sv.ProcessHandshakeRequest(content(t, req), clientAE); err != nil {
		t.Fatalf("attribute certificate refused: %v", err)
	}
	f.eventMu.Lock()
	defer f.eventMu.Unlock()
	for _, e := range f.events {
		if e.Code == EventAttCertIgnored {
			return
		}
	}
	t.Fatal("no attribute-certificate-ignored event")
}

// TISSUE 53/55: InitializationVector is SIZE (12 | 16).
func TestTissue55IVSizes(t *testing.T) {
	for n, ok := range map[int]bool{12: true, 16: true, 8: false} {
		tk := &ClearToken2{AssoID: "1:1", TimeRaw: []byte("20261012083015.000Z"), IV: make([]byte, n)}
		_, err := parseToken2(asn1.Span{Content: content(t, tk.element().Encode())})
		if (err == nil) != ok {
			t.Errorf("iv of %d octets: %v", n, err)
		}
	}
}
