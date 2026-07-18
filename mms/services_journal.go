package mms

import (
	"context"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

// svcReadJournal is the MMS readJournal confirmed service (ISO 9506-2).
const svcReadJournal = 65

// JournalEntry is one entry returned by a readJournal query.
type JournalEntry struct {
	EntryID        []byte
	OccurrenceTime time.Time
	Variables      []JournalVariable
}

// JournalVariable is one logged variable within a journal entry.
type JournalVariable struct {
	Tag   string
	Value *Value
}

// ReadJournalByTime queries a journal (log) for entries in the inclusive
// time range [start, end].
func (c *Conn) ReadJournalByTime(ctx context.Context, domain, item string, start, end time.Time) ([]JournalEntry, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcReadJournal),
		journalName(domain, item),
		asn1.Cons(asn1.ContextConstructed(1), // rangeStartSpecification [1]
			asn1.Prim(asn1.ContextPrimitive(0), binaryTimeBytes(start))),
		asn1.Cons(asn1.ContextConstructed(2), // rangeStopSpecification [2]
			asn1.Prim(asn1.ContextPrimitive(0), binaryTimeBytes(end))),
	)
	return c.readJournal(ctx, req)
}

// ReadJournalAfter queries a journal for entries after the given time and
// entry id (gap-free continuation).
func (c *Conn) ReadJournalAfter(ctx context.Context, domain, item string, after time.Time, entryID []byte) ([]JournalEntry, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcReadJournal),
		journalName(domain, item),
		asn1.Cons(asn1.ContextConstructed(3), // entryToStartAfter [3]
			asn1.Prim(asn1.ContextPrimitive(0), binaryTimeBytes(after)),
			asn1.Prim(asn1.ContextPrimitive(1), entryID),
		),
	)
	return c.readJournal(ctx, req)
}

func journalName(domain, item string) *asn1.Element {
	return asn1.Cons(asn1.ContextConstructed(0), // journalName [0]
		asn1.Cons(asn1.ContextConstructed(1), // objectId [1] domain-specific
			asn1.Prim(asn1.TagVisibleString, []byte(domain)),
			asn1.Prim(asn1.TagVisibleString, []byte(item)),
		),
	)
}

func binaryTimeBytes(t time.Time) []byte {
	return NewBinaryTime(t).Bytes()
}

func (c *Conn) readJournal(ctx context.Context, req *asn1.Element) ([]JournalEntry, error) {
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcReadJournal))
	if err != nil {
		return nil, err
	}
	inner := asn1.NewDecoder(content)
	listContent, err := inner.Expect(asn1.ContextConstructed(0)) // listOfJournalEntry [0]
	if err != nil {
		return nil, err
	}
	var entries []JournalEntry
	ld := asn1.NewDecoder(listContent)
	for ld.More() {
		entryContent, err := ld.Expect(asn1.TagSequence) // JournalEntry SEQUENCE
		if err != nil {
			return nil, err
		}
		e, err := parseJournalEntry(entryContent)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func parseJournalEntry(content []byte) (JournalEntry, error) {
	dec := asn1.NewDecoder(content)
	var e JournalEntry
	for dec.More() {
		tag, c, err := dec.ReadTLV()
		if err != nil {
			return e, err
		}
		switch tag {
		case asn1.ContextPrimitive(0): // entryID
			e.EntryID = append([]byte(nil), c...)
		case asn1.ContextConstructed(2): // entryContent
			parseEntryContent(c, &e)
		}
	}
	return e, nil
}

func parseEntryContent(content []byte, e *JournalEntry) {
	dec := asn1.NewDecoder(content)
	for dec.More() {
		tag, c, err := dec.ReadTLV()
		if err != nil {
			return
		}
		switch tag {
		case asn1.ContextPrimitive(0): // occurenceTime
			if len(c) >= 4 {
				v := &Value{typ: TypeBinaryTime, bytes: append([]byte(nil), c...)}
				e.OccurrenceTime = v.Time()
			}
		case asn1.ContextConstructed(2): // data / journal variables
			parseJournalVariables(c, e)
		}
	}
}

func parseJournalVariables(content []byte, e *JournalEntry) {
	// Each journal variable is a SEQUENCE { variableTag GraphicString,
	// valueSpecification [1] Data }.
	dec := asn1.NewDecoder(content)
	for dec.More() {
		tag, c, err := dec.ReadTLV()
		if err != nil {
			return
		}
		if tag != asn1.TagSequence && tag != asn1.ContextConstructed(1) {
			continue
		}
		var jv JournalVariable
		vd := asn1.NewDecoder(c)
		for vd.More() {
			t, vc, err := vd.ReadTLV()
			if err != nil {
				break
			}
			switch t {
			case asn1.TagGraphicString, asn1.TagVisibleString, asn1.ContextPrimitive(0):
				jv.Tag = string(vc)
			case asn1.ContextConstructed(1): // valueSpecification wraps a Data
				if v, err := DecodeData(asn1.NewDecoder(vc)); err == nil {
					jv.Value = v
				}
			}
		}
		if jv.Tag != "" || jv.Value != nil {
			e.Variables = append(e.Variables, jv)
		}
	}
}
