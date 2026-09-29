package acse

import (
	"sync"
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// aareFields decodes the application-context-name of an AARE and the
// indirect-reference of its user information's EXTERNAL.
func aareFields(t *testing.T, apdu []byte) (asn1.OID, int64) {
	t.Helper()
	content, err := asn1.NewDecoder(apdu).Expect(tagAARE)
	if err != nil {
		t.Fatal(err)
	}
	var ctx asn1.OID
	ref := int64(-1)
	d := asn1.NewDecoder(content)
	for d.More() {
		tag, c, err := d.ReadTLV()
		if err != nil {
			t.Fatal(err)
		}
		switch tag {
		case asn1.ContextConstructed(1):
			b, err := asn1.NewDecoder(c).Expect(asn1.TagOID)
			if err != nil {
				t.Fatal(err)
			}
			if ctx, err = asn1.DecodeOID(b); err != nil {
				t.Fatal(err)
			}
		case asn1.ContextConstructed(30):
			ext, err := asn1.NewDecoder(c).Expect(asn1.Tag{Class: asn1.ClassUniversal, Constructed: true, Number: 8})
			if err != nil {
				t.Fatal(err)
			}
			b, err := asn1.NewDecoder(ext).Expect(asn1.TagInteger)
			if err != nil {
				t.Fatal(err)
			}
			if ref, err = asn1.DecodeInt(b); err != nil {
				t.Fatal(err)
			}
		}
	}
	return ctx, ref
}

// The EXTERNAL carrying the InitiateResponse names the MMS presentation
// context by the identifier the peer chose. A constant 3 tells a peer that
// numbered MMS otherwise that the response is in some other syntax.
func TestAAREUsesNegotiatedMMSContext(t *testing.T) {
	_, ref := aareFields(t, AAREFor([]byte{0xa9, 0x00}, Identity{}, nil, 5))
	if ref != 5 {
		t.Errorf("indirect-reference = %d, want the peer's 5", ref)
	}
	_, ref = aareFields(t, AAREFor([]byte{0xa9, 0x00}, Identity{}, nil, 0))
	if ref != PresentationContextMMS {
		t.Errorf("indirect-reference = %d, want the conventional %d", ref, PresentationContextMMS)
	}
}

// The AARE answers with the application context the peer proposed, when it
// is one this library serves, whatever the process-wide setting says.
func TestAAREEchoesProposedApplicationContext(t *testing.T) {
	for _, tc := range []struct {
		name     string
		proposed asn1.OID
		want     asn1.OID
	}{
		{"ACSI", oidACSIContext, oidACSIContext},
		{"MMS", oidMMSContext, oidMMSContext},
		{"none", nil, oidMMSContext},
		{"unknown", asn1.OID{1, 2, 3}, oidMMSContext},
	} {
		got, _ := aareFields(t, AAREFor([]byte{0xa9, 0x00}, Identity{}, tc.proposed, 3))
		if !got.Equal(tc.want) {
			t.Errorf("%s: AARE context = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The context an AARQ proposes is what the responder reads back.
func TestAARQApplicationContextRoundTrips(t *testing.T) {
	t.Cleanup(func() { SetApplicationContext(MMSContext) })
	for _, c := range []ApplicationContext{ACSIContext, MMSContext} {
		SetApplicationContext(c)
		req, err := ParseAARQFull(AARQ([]byte{0xa8, 0x00}, ""))
		if err != nil {
			t.Fatal(err)
		}
		if !req.ApplicationContext.Equal(ApplicationContextOID()) {
			t.Errorf("parsed context %v, want %v", req.ApplicationContext, ApplicationContextOID())
		}
	}
}

// SetApplicationContext may run while another goroutine dials; under -race
// this fails if the setting is an unsynchronised global.
func TestSetApplicationContextConcurrent(t *testing.T) {
	t.Cleanup(func() { SetApplicationContext(MMSContext) })
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 200 {
			SetApplicationContext(ApplicationContext(i % 2))
		}
	}()
	go func() {
		defer wg.Done()
		for range 200 {
			AARQ([]byte{0xa8, 0x00}, "")
		}
	}()
	wg.Wait()
}
