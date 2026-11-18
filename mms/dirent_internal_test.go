package mms

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

// A FileName of several GraphicStrings is one name: listing it must not
// truncate it to the first part, which FileDirectory would then send back
// as its continuation cursor.
func TestParseDirEntryMultipartName(t *testing.T) {
	entry := asn1.Cons(asn1.TagSequence,
		asn1.Cons(asn1.ContextConstructed(0),
			asn1.Prim(asn1.TagGraphicString, []byte("COMTRADE/")),
			asn1.Prim(asn1.TagGraphicString, []byte("rec_001.cfg"))),
		asn1.Cons(asn1.ContextConstructed(1),
			asn1.IntElem(asn1.ContextPrimitive(0), 42)),
	)
	content, err := asn1.NewDecoder(entry.Encode()).Expect(asn1.TagSequence)
	if err != nil {
		t.Fatal(err)
	}
	e, err := parseDirEntry(content)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "COMTRADE/rec_001.cfg" || e.Size != 42 {
		t.Errorf("entry = %+v", e)
	}

	bad := asn1.Cons(asn1.ContextConstructed(0), asn1.IntElem(asn1.TagInteger, 1)).Encode()
	if _, err := parseDirEntry(bad); err == nil {
		t.Error("a non-string name part should be an error")
	}
}
