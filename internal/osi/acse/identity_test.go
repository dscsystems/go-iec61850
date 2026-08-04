package acse

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// A proxy standing in for a device has to reproduce its identity exactly, so
// what goes into the AARE must come back out of the parser unchanged.
func TestAARERespondingIdentityRoundTrips(t *testing.T) {
	want := Identity{
		APTitle:     asn1.OID{1, 1, 999, 1},
		AEQualifier: 12,
		HasAEQual:   true,
	}
	res, err := ParseAARE(AAREWithIdentity([]byte{0xa9, 0x00}, want))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted {
		t.Fatal("identity fields made the AARE unparseable as an acceptance")
	}
	got := res.Responding
	if got.APTitle.String() != want.APTitle.String() {
		t.Errorf("AP-title = %v, want %v", got.APTitle, want.APTitle)
	}
	if !got.HasAEQual || got.AEQualifier != want.AEQualifier {
		t.Errorf("AE-qualifier = %d (present %v), want %d", got.AEQualifier, got.HasAEQual, want.AEQualifier)
	}
}

// An empty identity must leave the APDU byte-identical to the bare
// acceptance: servers with no identity of their own must not start emitting
// half-filled ACSE fields.
func TestEmptyIdentityLeavesAAREUnchanged(t *testing.T) {
	user := []byte{0xa9, 0x00}
	if string(AAREWithIdentity(user, Identity{})) != string(AARE(user)) {
		t.Fatal("an empty identity changed the AARE encoding")
	}
	if string(AARQWithIdentity(user, "", Identity{}, Identity{})) != string(AARQ(user, "")) {
		t.Fatal("an empty identity changed the AARQ encoding")
	}
}

// The client's AARQ says who it addressed; a replica needs that to know the
// client is checking identity at all.
func TestAARQIdentitiesRoundTrip(t *testing.T) {
	called := Identity{APTitle: asn1.OID{1, 1, 999, 1}, AEQualifier: 12, HasAEQual: true}
	calling := Identity{APTitle: asn1.OID{1, 1, 999, 2}, AEQualifier: 7, HasAEQual: true}
	req, err := ParseAARQFull(AARQWithIdentity([]byte{0xa8, 0x00}, "secret", called, calling))
	if err != nil {
		t.Fatal(err)
	}
	if req.Called.APTitle.String() != called.APTitle.String() {
		t.Errorf("called AP-title = %v, want %v", req.Called.APTitle, called.APTitle)
	}
	if req.Calling.APTitle.String() != calling.APTitle.String() {
		t.Errorf("calling AP-title = %v, want %v", req.Calling.APTitle, calling.APTitle)
	}
	if req.Called.AEQualifier != 12 || req.Calling.AEQualifier != 7 {
		t.Errorf("AE-qualifiers = %d/%d, want 12/7", req.Called.AEQualifier, req.Calling.AEQualifier)
	}
	if req.Password != "secret" {
		t.Errorf("password = %q, want secret", req.Password)
	}
}
