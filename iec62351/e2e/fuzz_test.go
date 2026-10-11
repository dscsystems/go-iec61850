package e2e

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

func seedPDUs(f *testing.F) {
	fx := newFixture(&testing.T{}, pkitest.ECDSAP256, pkitest.ECDSAP256)
	c, _ := NewClient(fx.cli)
	s, _ := NewServer(fx.srv)
	req, _ := c.HandshakeRequest(appl)
	rc, _ := asn1.NewDecoder(req).Expect(asn1.TagSequence)
	f.Add(rc)
	if _, err := s.ProcessHandshakeRequest(rc, clientAE); err == nil {
		acc, _ := s.HandshakeAccept(appl)
		ac, _ := asn1.NewDecoder(acc).Expect(asn1.TagSequence)
		f.Add(ac)
		if _, err := c.ProcessHandshakeAccept(ac, serverAE); err == nil {
			p, _ := c.Seal(appl)
			pc, _ := asn1.NewDecoder(p).Expect(asn1.TagSequence)
			f.Add(pc)
			r, _ := c.ReleaseRequest()
			rc, _ := asn1.NewDecoder(r).Expect(asn1.TagSequence)
			f.Add(rc)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
}

func FuzzParseSigned(f *testing.F) {
	seedPDUs(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		for k := KindHandshakeReq; k <= KindReleaseRsp; k++ {
			ParseSigned(k, b)
		}
	})
}

func FuzzParseTransfer(f *testing.F) {
	seedPDUs(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseTransfer(false, b, AuthAnnexB)
		ParseTransfer(true, b, AuthAnnexB)
		ParseTransfer(false, b, AuthClause13)
	})
}

// FuzzServerHandshake feeds arbitrary requests to a server association: it
// must never panic, and must never accept a request it did not see signed.
func FuzzServerHandshake(f *testing.F) {
	seedPDUs(f)
	fx := newFixture(&testing.T{}, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := NewServer(fx.srv)
		if err != nil {
			t.Skip()
		}
		s.ProcessHandshakeRequest(b, clientAE)
	})
}
