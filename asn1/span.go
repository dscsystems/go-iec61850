package asn1

// Span is one element as it appears on the wire. Security protocols sign
// or MAC the exact octets they received, so a decoder that hands back only
// the content of an indefinite-length element (without its end-of-contents
// octets) or that re-encodes before verifying cannot be used for them.
//
// All slices alias the decoder's input.
type Span struct {
	Tag Tag
	// Full is the complete TLV: identifier, length and content octets,
	// including the end-of-contents octets of an indefinite-length element.
	Full []byte
	// Content is the content octets, excluding end-of-contents octets.
	Content []byte
	// ContentEOC is the content octets including, for an indefinite-length
	// element, the trailing 00 00 (IEC 62351-4 13.1.3 c): "if indefinite
	// length encoding is used, trailing zeros shall be included"). For a
	// definite-length element it equals Content.
	ContentEOC []byte
	// Indefinite reports the indefinite length form.
	Indefinite bool
}

// ReadSpan consumes the next element and returns it with its raw octets.
func (d *Decoder) ReadSpan() (Span, error) {
	start := d.off
	t, err := d.readTag()
	if err != nil {
		return Span{}, err
	}
	n, indefinite, err := d.readLength()
	if err != nil {
		return Span{}, err
	}
	hdrEnd := d.off
	if !indefinite {
		if n > len(d.data)-d.off {
			return Span{}, d.errAt(ErrTruncated, "reading content")
		}
		d.off += n
		c := d.data[hdrEnd:d.off]
		return Span{Tag: t, Full: d.data[start:d.off], Content: c, ContentEOC: c}, nil
	}
	// Reuse the indefinite scanner of readTLV by rewinding.
	d.off = start
	_, content, err := d.readTLV(0)
	if err != nil {
		return Span{}, err
	}
	return Span{
		Tag:        t,
		Full:       d.data[start:d.off],
		Content:    content,
		ContentEOC: d.data[hdrEnd:d.off],
		Indefinite: true,
	}, nil
}

// PeekTag returns the tag of the next element, or false when none remains
// or it is malformed.
func (d *Decoder) PeekTag() (Tag, bool) {
	if !d.More() {
		return Tag{}, false
	}
	t, err := d.Peek()
	return t, err == nil
}
