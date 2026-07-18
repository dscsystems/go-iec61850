package asn1

import (
	"fmt"
)

// Decoder is a bounds-checked cursor over BER-encoded bytes. The content
// slices it returns alias the input buffer; callers that retain them past
// the lifetime of the buffer must copy.
//
// Indefinite lengths are accepted (the matching end-of-contents octets are
// located by structural scanning) since BER permits them, although all
// known 61850 stacks emit definite lengths.
type Decoder struct {
	data []byte
	off  int
}

// NewDecoder returns a decoder over data.
func NewDecoder(data []byte) *Decoder { return &Decoder{data: data} }

// More reports whether unread bytes remain.
func (d *Decoder) More() bool { return d.off < len(d.data) }

// Offset returns the current byte offset, for error reporting.
func (d *Decoder) Offset() int { return d.off }

// Rest returns the unread remainder without consuming it.
func (d *Decoder) Rest() []byte { return d.data[d.off:] }

func (d *Decoder) errAt(err error, what string) error {
	return fmt.Errorf("%s at offset %d: %w", what, d.off, err)
}

// readTag consumes and returns the identifier octets.
func (d *Decoder) readTag() (Tag, error) {
	if d.off >= len(d.data) {
		return Tag{}, d.errAt(ErrTruncated, "reading tag")
	}
	b := d.data[d.off]
	d.off++
	t := Tag{
		Class:       Class(b >> 6),
		Constructed: b&0x20 != 0,
		Number:      uint32(b & 0x1f),
	}
	if t.Number != 0x1f {
		return t, nil
	}
	// High tag number form.
	t.Number = 0
	for i := 0; ; i++ {
		if d.off >= len(d.data) {
			return Tag{}, d.errAt(ErrTruncated, "reading tag")
		}
		if i >= 5 {
			return Tag{}, d.errAt(ErrBadTag, "tag number too large")
		}
		c := d.data[d.off]
		d.off++
		t.Number = t.Number<<7 | uint32(c&0x7f)
		if c&0x80 == 0 {
			break
		}
	}
	return t, nil
}

// readLength consumes the length octets. indefinite is true for the
// indefinite form (0x80).
func (d *Decoder) readLength() (n int, indefinite bool, err error) {
	if d.off >= len(d.data) {
		return 0, false, d.errAt(ErrTruncated, "reading length")
	}
	b := d.data[d.off]
	d.off++
	if b < 0x80 {
		return int(b), false, nil
	}
	if b == 0x80 {
		return 0, true, nil
	}
	numOctets := int(b & 0x7f)
	if numOctets > 4 {
		return 0, false, d.errAt(errLenOverflow, "reading length")
	}
	if d.off+numOctets > len(d.data) {
		return 0, false, d.errAt(ErrTruncated, "reading length")
	}
	for i := 0; i < numOctets; i++ {
		n = n<<8 | int(d.data[d.off])
		d.off++
	}
	if n < 0 {
		return 0, false, d.errAt(errLenOverflow, "reading length")
	}
	return n, false, nil
}

// Peek returns the tag of the next element without consuming anything.
func (d *Decoder) Peek() (Tag, error) {
	save := d.off
	t, err := d.readTag()
	d.off = save
	return t, err
}

// PeekIs reports whether the next element has tag t. False when no
// element remains or the tag is malformed.
func (d *Decoder) PeekIs(t Tag) bool {
	got, err := d.Peek()
	return err == nil && got == t
}

// ReadTLV consumes the next element and returns its tag and content
// octets. For indefinite-length elements the content excludes the
// end-of-contents octets.
func (d *Decoder) ReadTLV() (Tag, []byte, error) {
	return d.readTLV(0)
}

func (d *Decoder) readTLV(depth int) (Tag, []byte, error) {
	if depth > MaxDepth {
		return Tag{}, nil, d.errAt(ErrTooDeep, "reading element")
	}
	t, err := d.readTag()
	if err != nil {
		return Tag{}, nil, err
	}
	n, indefinite, err := d.readLength()
	if err != nil {
		return Tag{}, nil, err
	}
	if !indefinite {
		if n > len(d.data)-d.off {
			return Tag{}, nil, d.errAt(ErrTruncated, "reading content")
		}
		content := d.data[d.off : d.off+n]
		d.off += n
		return t, content, nil
	}
	if !t.Constructed {
		return Tag{}, nil, d.errAt(ErrBadLength, "indefinite length on primitive")
	}
	// Indefinite: scan children until end-of-contents (00 00).
	start := d.off
	for {
		if d.off+2 <= len(d.data) && d.data[d.off] == 0 && d.data[d.off+1] == 0 {
			content := d.data[start:d.off]
			d.off += 2
			return t, content, nil
		}
		if _, _, err := d.readTLV(depth + 1); err != nil {
			return Tag{}, nil, err
		}
	}
}

// Expect consumes the next element, requiring tag t, and returns its content.
func (d *Decoder) Expect(t Tag) ([]byte, error) {
	got, content, err := d.ReadTLV()
	if err != nil {
		return nil, err
	}
	if got != t {
		return nil, fmt.Errorf("expected %v, got %v: %w", t, got, ErrUnexpected)
	}
	return content, nil
}

// Optional consumes the next element only if it has tag t, returning its
// content and true, or nil and false without consuming otherwise.
func (d *Decoder) Optional(t Tag) ([]byte, bool, error) {
	if !d.More() {
		return nil, false, nil
	}
	got, err := d.Peek()
	if err != nil {
		return nil, false, err
	}
	if got != t {
		return nil, false, nil
	}
	_, content, err := d.ReadTLV()
	return content, true, err
}

// Skip consumes and discards the next element.
func (d *Decoder) Skip() error {
	_, _, err := d.ReadTLV()
	return err
}
