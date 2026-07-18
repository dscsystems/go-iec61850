package asn1

// Element is a build-time representation of a BER element. Constructed
// elements carry Children; primitive elements carry Value; a raw element
// (from RawContent) carries pre-encoded content octets. It exists for the
// control-plane codecs (MMS, ACSE, presentation) where clarity beats
// allocation counts; the GOOSE/SV hot paths use the Append* helpers
// directly instead.
type Element struct {
	Tag        Tag
	Value      []byte
	Children   []*Element
	raw        []byte // pre-encoded content octets (RawContent)
	isRaw      bool
	verbatim   []byte // pre-encoded complete TLV(s) (RawTLV)
	isVerbatim bool
}

// RawContent returns a constructed element with tag t whose content is the
// already-encoded octets in content (one or more complete TLVs). This
// embeds a nested PDU encoded elsewhere without re-parsing it, e.g. an
// ACSE APDU inside a presentation single-ASN1-type.
func RawContent(t Tag, content []byte) *Element {
	t.Constructed = true
	return &Element{Tag: t, raw: content, isRaw: true}
}

// RawTLV returns an element that appends the pre-encoded complete TLV(s)
// in tlv verbatim, with no tag or length of its own. Use it to place an
// element encoded elsewhere as a child of a constructed element.
func RawTLV(tlv []byte) *Element {
	return &Element{verbatim: tlv, isVerbatim: true}
}

// Prim returns a primitive element.
func Prim(t Tag, value []byte) *Element { return &Element{Tag: t, Value: value} }

// Cons returns a constructed element. Nil children are skipped, which lets
// callers express optional fields inline.
func Cons(t Tag, children ...*Element) *Element {
	el := &Element{Tag: t}
	el.Tag.Constructed = true
	for _, c := range children {
		if c != nil {
			el.Children = append(el.Children, c)
		}
	}
	return el
}

// Add appends children (nil children skipped) and returns el.
func (el *Element) Add(children ...*Element) *Element {
	for _, c := range children {
		if c != nil {
			el.Children = append(el.Children, c)
		}
	}
	return el
}

// ContentSize returns the encoded size of the element's content octets.
func (el *Element) ContentSize() int {
	if el.isRaw {
		return len(el.raw)
	}
	if el.Tag.Constructed {
		n := 0
		for _, c := range el.Children {
			n += c.Size()
		}
		return n
	}
	return len(el.Value)
}

// Size returns the total encoded size of the element.
func (el *Element) Size() int {
	if el.isVerbatim {
		return len(el.verbatim)
	}
	n := el.ContentSize()
	return TagSize(el.Tag) + LengthSize(n) + n
}

// Append encodes the element to dst.
func (el *Element) Append(dst []byte) []byte {
	if el.isVerbatim {
		return append(dst, el.verbatim...)
	}
	n := el.ContentSize()
	dst = AppendTag(dst, el.Tag)
	dst = AppendLength(dst, n)
	if el.isRaw {
		return append(dst, el.raw...)
	}
	if el.Tag.Constructed {
		for _, c := range el.Children {
			dst = c.Append(dst)
		}
		return dst
	}
	return append(dst, el.Value...)
}

// Encode returns the encoded element as a fresh slice.
func (el *Element) Encode() []byte {
	return el.Append(make([]byte, 0, el.Size()))
}
