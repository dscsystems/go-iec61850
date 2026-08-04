package presentation

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// The CPA has its own parameter tags. A responder that answers with the CP's
// calling [1] and called [2] selectors emits a CPA that no conforming decoder
// accepts, and peers that validate it drop the connection before any user
// data is exchanged. Real devices answer with responding [3] alone.
func TestCPAUsesRespondingSelectorOnly(t *testing.T) {
	cpa := BuildCPA([]byte{0x00, 0x00, 0x00, 0x01}, 2, []byte{0x61, 0x00})

	normal := normalModeParams(t, cpa)
	dec := asn1.NewDecoder(normal)
	var tags []asn1.Tag
	for dec.More() {
		tag, _, err := dec.ReadTLV()
		if err != nil {
			t.Fatal(err)
		}
		tags = append(tags, tag)
	}
	for _, tag := range tags {
		switch tag {
		case asn1.ContextPrimitive(1):
			t.Error("CPA carries a calling-presentation-selector, which exists only in a CP")
		case asn1.ContextPrimitive(2):
			t.Error("CPA carries a called-presentation-selector, which exists only in a CP")
		}
	}
	if !hasTag(tags, asn1.ContextPrimitive(3)) {
		t.Error("CPA has no responding-presentation-selector [3]")
	}
	if !hasTag(tags, asn1.ContextConstructed(5)) {
		t.Error("CPA has no presentation-context-definition-result-list [5]")
	}
}

// The result list is matched to the proposal by position, so its length has
// to follow what the peer actually proposed.
func TestCPAResultsMatchTheProposedContexts(t *testing.T) {
	for _, contexts := range []int{1, 2, 3} {
		cpa := BuildCPA(nil, contexts, []byte{0x61, 0x00})
		dec := asn1.NewDecoder(normalModeParams(t, cpa))
		found := -1
		for dec.More() {
			tag, c, err := dec.ReadTLV()
			if err != nil {
				t.Fatal(err)
			}
			if tag == asn1.ContextConstructed(5) {
				found = countSequences(c)
			}
		}
		if found != contexts {
			t.Errorf("%d proposed contexts produced %d results", contexts, found)
		}
	}
}

// The CP a real client sends must yield the selector it addressed and the
// number of contexts it proposed. This is the CP from a live 61850 client.
func TestParseCPFromARealClient(t *testing.T) {
	raw, err := hex.DecodeString(strings.Join([]string{
		"31819da003800101a28195810400000001820400000001a423300f020101060452",
		"0100013004060251013010020103060528ca2202013004060251016162306002",
		"0101a05b6059a107060528ca220203a20706052987670101a30302010ca6060604",
		"29018767a70302010cbe33283106025101020103a028a826800300fde881010a82",
		"010a830105a416800101810305f100820c03ee1c00000408000079ef18",
	}, ""))
	if err != nil {
		t.Fatal(err)
	}
	cp, err := ParseCP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cp.CalledPSel) != "00000001" {
		t.Errorf("called PSel = %x, want 00000001", cp.CalledPSel)
	}
	if cp.Contexts != 2 {
		t.Errorf("contexts = %d, want 2 (ACSE and MMS)", cp.Contexts)
	}
	if len(cp.UserData) == 0 || cp.UserData[0] != 0x60 {
		t.Errorf("user data is not an AARQ: %x", cp.UserData)
	}
}

func normalModeParams(t *testing.T, pdu []byte) []byte {
	t.Helper()
	dec := asn1.NewDecoder(pdu)
	set, err := dec.Expect(asn1.TagSet)
	if err != nil {
		t.Fatal(err)
	}
	inner := asn1.NewDecoder(set)
	for inner.More() {
		tag, c, err := inner.ReadTLV()
		if err != nil {
			t.Fatal(err)
		}
		if tag == asn1.ContextConstructed(2) {
			return c
		}
	}
	t.Fatal("no normal-mode-parameters")
	return nil
}

func hasTag(tags []asn1.Tag, want asn1.Tag) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
