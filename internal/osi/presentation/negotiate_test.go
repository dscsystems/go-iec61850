package presentation

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// The presentation-context-identifier is the proposer's choice, so a
// responder that assumes the conventional 3 and a peer that chose something
// else agree on nothing. Every data PDU after the association is then
// mis-tagged, which the peer sees as silence rather than as an error.
func TestNegotiatedContextIsTheProposersChoice(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contexts []Context
		wantACSE int
		wantMMS  int
	}{
		{"the conventional pair", defaultContexts(), ContextACSE, ContextMMS},
		{"sequential from one", []Context{
			{ID: 1, AbstractSyntax: oidACSE, TransferSyntax: oidBER},
			{ID: 2, AbstractSyntax: oidMMS, TransferSyntax: oidBER},
		}, 1, 2},
		{"reversed order", []Context{
			{ID: 2, AbstractSyntax: oidMMS, TransferSyntax: oidBER},
			{ID: 1, AbstractSyntax: oidACSE, TransferSyntax: oidBER},
		}, 1, 2},
		{"MMS first, high numbers", []Context{
			{ID: 9, AbstractSyntax: oidMMS, TransferSyntax: oidBER},
			{ID: 4, AbstractSyntax: oidACSE, TransferSyntax: oidBER},
		}, 4, 9},
	} {
		neg, _ := BuildCPA(nil, tc.contexts, []byte{0x61, 0x00})
		if neg.ACSE != tc.wantACSE {
			t.Errorf("%s: ACSE context = %d, want %d", tc.name, neg.ACSE, tc.wantACSE)
		}
		if neg.MMS != tc.wantMMS {
			t.Errorf("%s: MMS context = %d, want %d", tc.name, neg.MMS, tc.wantMMS)
		}
		if !neg.HasACSE() || !neg.HasMMS() {
			t.Errorf("%s: negotiation = %+v, want both contexts", tc.name, neg)
		}
	}
}

// A context this library cannot serve is rejected rather than accepted:
// accepting a transfer syntax it does not implement would produce PDUs the
// peer cannot decode.
func TestUnacceptableContextIsRejected(t *testing.T) {
	contexts := []Context{
		{ID: 1, AbstractSyntax: oidACSE, TransferSyntax: oidBER},
		// An abstract syntax this library does not implement.
		{ID: 2, AbstractSyntax: asn1.OID{1, 2, 3}, TransferSyntax: oidBER},
		// The right syntax, a transfer syntax it does not implement.
		{ID: 3, AbstractSyntax: oidMMS, TransferSyntax: asn1.OID{2, 1, 2}},
		{ID: 4, AbstractSyntax: oidMMS, TransferSyntax: oidBER},
	}
	neg, cpa := BuildCPA(nil, contexts, []byte{0x61, 0x00})
	if neg.MMS != 4 {
		t.Errorf("MMS context = %d, want 4, the only one this library can serve", neg.MMS)
	}
	results := resultList(t, cpa)
	if len(results) != len(contexts) {
		t.Fatalf("%d results for %d proposals", len(results), len(contexts))
	}
	for i, want := range []Result{ResultAcceptance, ResultProviderRejection,
		ResultProviderRejection, ResultAcceptance} {
		if results[i].Result != want {
			t.Errorf("result %d = %d, want %d", i, results[i].Result, want)
		}
	}
	// A rejected context names no transfer syntax: none was agreed.
	for i, r := range results {
		if r.Result == ResultAcceptance && !r.HasTransferSyntax {
			t.Errorf("accepted result %d names no transfer syntax", i)
		}
		if r.Result != ResultAcceptance && r.HasTransferSyntax {
			t.Errorf("rejected result %d names a transfer syntax", i)
		}
	}
}

// A peer that proposes no MMS context gets an answer that says so, and the
// caller is expected to refuse the association rather than go silent.
func TestNoMMSContext(t *testing.T) {
	neg, _ := BuildCPA(nil, []Context{
		{ID: 1, AbstractSyntax: oidACSE, TransferSyntax: oidBER},
	}, []byte{0x61, 0x00})
	if neg.HasMMS() {
		t.Errorf("MMS context = %d, want none", neg.MMS)
	}
	if !neg.HasACSE() {
		t.Error("the ACSE context should still be accepted")
	}
}

// The CPA carries the AARE in the ACSE context the peer proposed, not in
// the conventional one.
func TestCPAUserDataUsesNegotiatedACSEContext(t *testing.T) {
	for _, acseID := range []int{1, 2, 5, 17} {
		contexts := []Context{
			{ID: acseID, AbstractSyntax: oidACSE, TransferSyntax: oidBER},
			{ID: acseID + 1, AbstractSyntax: oidMMS, TransferSyntax: oidBER},
		}
		_, cpa := BuildCPA(nil, contexts, []byte{0x61, 0x2a})
		id, data, err := parsePDVList(setUserData(t, cpa))
		if err != nil {
			t.Fatal(err)
		}
		if id != acseID {
			t.Errorf("AARE wrapped in context %d, want the proposed %d", id, acseID)
		}
		if len(data) == 0 || data[0] != 0x61 {
			t.Errorf("user data = %x, want the AARE", data)
		}
	}
}

// Data PDUs go into the negotiated MMS context, not the conventional one.
func TestWrapDataUsesNegotiatedContext(t *testing.T) {
	for _, id := range []int{0, ContextMMS, 2, 9} {
		pdu := WrapData(id, []byte{0xa0, 0x01, 0x02})
		got, data, err := parseUserData(pdu)
		if err != nil {
			t.Fatal(err)
		}
		want := id
		if want == 0 {
			want = ContextMMS
		}
		if got != want {
			t.Errorf("WrapData(%d) tagged the PDU with context %d", id, got)
		}
		if len(data) != 3 || data[0] != 0xa0 {
			t.Errorf("payload = %x, want the MMS PDU", data)
		}
	}
}

// A CP round-trips through ParseCP and back into a CPA that agrees with it.
func TestCPRoundTrip(t *testing.T) {
	aarq := []byte{0x60, 0x03, 0x02, 0x01, 0x00}
	cp := BuildCP([]byte{0, 0, 0, 1}, []byte{0, 0, 0, 2}, aarq)
	parsed, err := ParseCP(cp)
	if err != nil {
		t.Fatal(err)
	}
	neg, cpa := BuildCPA(parsed.CalledPSel, parsed.Contexts, aarq)
	if neg.ACSE != ContextACSE || neg.MMS != ContextMMS {
		t.Errorf("negotiation = %+v, want the conventional pair", neg)
	}
	// The answering selector is the one the peer addressed.
	normal := normalModeParams(t, cpa)
	if !bytesContainsSub(normal, []byte{0, 0, 0, 2}) {
		t.Error("the CPA does not carry the called selector as its responding selector")
	}
}

// resultEntry is one decoded entry of a CPA result list.
type resultEntry struct {
	Result            Result
	HasTransferSyntax bool
}

// resultList decodes a CPA's presentation-context-definition-result-list.
func resultList(t *testing.T, cpa []byte) []resultEntry {
	t.Helper()
	dec := asn1.NewDecoder(normalModeParams(t, cpa))
	for dec.More() {
		tag, content, err := dec.ReadTLV()
		if err != nil {
			t.Fatal(err)
		}
		if tag != asn1.ContextConstructed(5) {
			continue
		}
		entries := asn1.NewDecoder(content)
		var out []resultEntry
		for entries.More() {
			t2, body, err := entries.ReadTLV()
			if err != nil || t2 != asn1.TagSequence {
				break
			}
			inner := asn1.NewDecoder(body)
			var e resultEntry
			for inner.More() {
				rt, rc, err := inner.ReadTLV()
				if err != nil {
					break
				}
				switch rt {
				case asn1.ContextPrimitive(0):
					if n, err := asn1.DecodeInt(rc); err == nil {
						e.Result = Result(n)
					}
				case asn1.ContextPrimitive(1):
					e.HasTransferSyntax = true
				}
			}
			out = append(out, e)
		}
		return out
	}
	t.Fatal("no result list in the CPA")
	return nil
}

// setUserData extracts the fully-encoded-data element from a CPA.
func setUserData(t *testing.T, cpa []byte) []byte {
	t.Helper()
	dec := asn1.NewDecoder(normalModeParams(t, cpa))
	for dec.More() {
		tag, content, err := dec.ReadTLV()
		if err != nil {
			t.Fatal(err)
		}
		if tag == asn1.ApplicationConstructed(1) {
			return content
		}
	}
	t.Fatal("no user data in the CPA")
	return nil
}

func bytesContainsSub(hay, needle []byte) bool {
	if len(needle) > len(hay) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
