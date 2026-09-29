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
// time range [start, end], following the server's continuation until the
// range is complete.
func (c *Conn) ReadJournalByTime(ctx context.Context, domain, item string, start, end time.Time) ([]JournalEntry, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcReadJournal),
		journalName(domain, item),
		asn1.Cons(asn1.ContextConstructed(1), // rangeStartSpecification [1]
			asn1.Prim(asn1.ContextPrimitive(0), binaryTimeBytes(start))),
		rangeStop(end),
	)
	return c.readJournalAll(ctx, domain, item, req, &end)
}

// ReadJournalAfter queries a journal for entries after the given time and
// entry id (gap-free continuation), following the server's continuation.
func (c *Conn) ReadJournalAfter(ctx context.Context, domain, item string, after time.Time, entryID []byte) ([]JournalEntry, error) {
	return c.readJournalAll(ctx, domain, item, afterRequest(domain, item, after, entryID, nil), nil)
}

// afterRequest is a ReadJournal continuing after one entry, up to end when
// it is not nil. entryToStartAfter is [5] in ISO 9506-2; earlier versions
// of this library sent [3], which no other server understands.
func afterRequest(domain, item string, after time.Time, entryID []byte, end *time.Time) *asn1.Element {
	req := asn1.Cons(asn1.ContextConstructed(svcReadJournal), journalName(domain, item))
	if end != nil {
		req.Add(rangeStop(*end))
	}
	req.Add(asn1.Cons(asn1.ContextConstructed(5), // entryToStartAfter [5]
		asn1.Prim(asn1.ContextPrimitive(0), binaryTimeBytes(after)),
		asn1.Prim(asn1.ContextPrimitive(1), entryID),
	))
	return req
}

// rangeStop is rangeStopSpecification [2] { endingTime [0] }.
func rangeStop(end time.Time) *asn1.Element {
	return asn1.Cons(asn1.ContextConstructed(2),
		asn1.Prim(asn1.ContextPrimitive(0), binaryTimeBytes(end)))
}

// readJournalAll issues req and, while the server says more follow,
// continues after the last entry received.
func (c *Conn) readJournalAll(ctx context.Context, domain, item string, req *asn1.Element, end *time.Time) ([]JournalEntry, error) {
	var all []JournalEntry
	for {
		entries, more, err := c.readJournal(ctx, req)
		if err != nil {
			return nil, err
		}
		all = append(all, entries...)
		if !more || len(entries) == 0 {
			return all, nil
		}
		last := entries[len(entries)-1]
		req = afterRequest(domain, item, last.OccurrenceTime, last.EntryID, end)
	}
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

// readJournal issues one ReadJournal and returns its entries and whether
// the server has more.
func (c *Conn) readJournal(ctx context.Context, req *asn1.Element) ([]JournalEntry, bool, error) {
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, false, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcReadJournal))
	if err != nil {
		return nil, false, err
	}
	inner := asn1.NewDecoder(content)
	listContent, err := inner.Expect(asn1.ContextConstructed(0)) // listOfJournalEntry [0]
	if err != nil {
		return nil, false, err
	}
	var entries []JournalEntry
	ld := asn1.NewDecoder(listContent)
	for ld.More() {
		entryContent, err := ld.Expect(asn1.TagSequence) // JournalEntry SEQUENCE
		if err != nil {
			return nil, false, err
		}
		e, err := parseJournalEntry(entryContent)
		if err != nil {
			return nil, false, err
		}
		entries = append(entries, e)
	}
	more := false
	if b, ok, _ := inner.Optional(asn1.ContextPrimitive(1)); ok && len(b) > 0 { // moreFollows [1]
		more = b[0] != 0
	}
	return entries, more, nil
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

// parseJournalVariables reads the data [2] of an entry. ISO 9506-2 puts the
// variables in listOfVariables [1], each a SEQUENCE { variableTag [0],
// valueSpecification [1] Data }; the variables are also accepted directly
// in data, a shape some servers send.
func parseJournalVariables(content []byte, e *JournalEntry) {
	dec := asn1.NewDecoder(content)
	for dec.More() {
		tag, c, err := dec.ReadTLV()
		if err != nil {
			return
		}
		if tag == asn1.ContextConstructed(1) { // listOfVariables [1]
			parseJournalVariables(c, e)
			continue
		}
		if tag != asn1.TagSequence {
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
