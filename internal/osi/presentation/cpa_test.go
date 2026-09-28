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
	_, cpa := BuildCPA([]byte{0x00, 0x00, 0x00, 0x01}, defaultContexts(), []byte{0x61, 0x00})

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
	for _, n := range []int{1, 2, 3} {
		// One more context than the conventional pair, to show the
		// result list follows the proposal rather than a fixed length.
		contexts := append(defaultContexts(), Context{
			ID: 7, AbstractSyntax: asn1.OID{1, 2, 3, 4}, TransferSyntax: oidBER,
		})
		contexts = contexts[:n]
		_, cpa := BuildCPA(nil, contexts, []byte{0x61, 0x00})
		dec := asn1.NewDecoder(normalModeParams(t, cpa))
		found := -1
		for dec.More() {
			tag, c, err := dec.ReadTLV()
			if err != nil {
				t.Fatal(err)
			}
			if tag == asn1.ContextConstructed(5) {
				found = countEntries(c)
			}
		}
		if found != n {
			t.Errorf("%d proposed contexts produced %d results", n, found)
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
	if len(cp.Contexts) != 2 {
		t.Fatalf("%d contexts, want 2 (ACSE and MMS)", len(cp.Contexts))
	}
	var sawACSE, sawMMS bool
	for _, c := range cp.Contexts {
		if c.IsACSE() {
			sawACSE = true
		}
		if c.IsMMS() {
			sawMMS = true
		}
		if !c.BER() {
			t.Errorf("context %d proposes transfer syntax %v, want BER", c.ID, c.TransferSyntax)
		}
	}
	if !sawACSE || !sawMMS {
		t.Errorf("contexts = %+v, want one ACSE and one MMS", cp.Contexts)
	}
	if len(cp.UserData) == 0 || cp.UserData[0] != 0x60 {
		t.Errorf("user data is not an AARQ: %x", cp.UserData)
	}
}

// defaultContexts is the ACSE and MMS pair every MMS peer proposes,
// under the identifiers convention gives them.
func defaultContexts() []Context {
	return []Context{
		{ID: ContextACSE, AbstractSyntax: oidACSE, TransferSyntax: oidBER},
		{ID: ContextMMS, AbstractSyntax: oidMMS, TransferSyntax: oidBER},
	}
}

// countEntries counts the SEQUENCE entries in a list.
func countEntries(content []byte) int {
	dec := asn1.NewDecoder(content)
	n := 0
	for dec.More() {
		tag, _, err := dec.ReadTLV()
		if err != nil {
			return n
		}
		if tag == asn1.TagSequence {
			n++
		}
	}
	return n
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
