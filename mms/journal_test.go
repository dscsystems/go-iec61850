package mms

import (
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

// buildJournalResponse encodes a readJournal response the way a server
// would, so the client decoder can be tested without a live log.
func buildJournalResponse(entryID []byte, occ time.Time, tag string, val *Value) []byte {
	entry := asn1.Cons(asn1.TagSequence,
		asn1.Prim(asn1.ContextPrimitive(0), entryID), // entryID [0]
		asn1.Cons(asn1.ContextConstructed(2), // entryContent [2]
			asn1.Prim(asn1.ContextPrimitive(0), NewBinaryTime(occ).Bytes()), // occurenceTime [0]
			asn1.Cons(asn1.ContextConstructed(2), // journalVariables container [2]
				asn1.Cons(asn1.TagSequence, // JournalVariable
					asn1.Prim(asn1.TagGraphicString, []byte(tag)),
					asn1.Cons(asn1.ContextConstructed(1), DataElement(val)), // valueSpecification [1]
				),
			),
		),
	)
	resp := asn1.Cons(asn1.ContextConstructed(svcReadJournal),
		asn1.Cons(asn1.ContextConstructed(0), entry), // listOfJournalEntry [0]
	)
	return resp.Encode()
}

func TestJournalResponseDecode(t *testing.T) {
	occ := time.Date(2026, 7, 18, 10, 30, 0, 0, time.UTC)
	resp := buildJournalResponse([]byte{0, 0, 0, 5}, occ, "GGIO1$ST$Ind1$stVal", NewBool(true))

	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcReadJournal))
	if err != nil {
		t.Fatal(err)
	}
	inner := asn1.NewDecoder(content)
	listContent, _ := inner.Expect(asn1.ContextConstructed(0))
	ld := asn1.NewDecoder(listContent)
	entryContent, _ := ld.Expect(asn1.TagSequence)
	e, err := parseJournalEntry(entryContent)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.EntryID) != 4 || e.EntryID[3] != 5 {
		t.Fatalf("entryID = %x", e.EntryID)
	}
	if d := e.OccurrenceTime.Sub(occ); d > time.Second || d < -time.Second {
		t.Fatalf("occurrence time drift %v (got %v)", d, e.OccurrenceTime)
	}
	if len(e.Variables) != 1 {
		t.Fatalf("expected 1 variable, got %d", len(e.Variables))
	}
	if e.Variables[0].Tag != "GGIO1$ST$Ind1$stVal" || !e.Variables[0].Value.Bool() {
		t.Fatalf("variable = %+v", e.Variables[0])
	}
}

func TestJournalRequestEncoding(t *testing.T) {
	// The request must use the readJournal application tag [65] = 0xbf 0x41
	// and a domain-specific journalName. We assert on the leading framing.
	req := asn1.Cons(asn1.ContextConstructed(svcReadJournal),
		journalName("IED1LD0", "LLN0$LG$EventLog"),
	).Encode()
	if req[0] != 0xbf || req[1] != 0x41 {
		t.Fatalf("readJournal tag = %x %x, want bf 41", req[0], req[1])
	}
}
