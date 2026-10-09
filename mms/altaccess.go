package mms

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dscsystems/go-iec61850/asn1"
)

// ListMember is one member of a named variable list: the variable, and the
// part of it the list selects. IEC 61850 datasets name array elements and
// their components this way — "MHAI1.HA.phsAHar(9).cVal" is the variable
// MHAI1$MX$HA$phsAHar with alternate access "element 9, component cVal".
type ListMember struct {
	VarRef
	// AlternateAccess is the content octets of the member's
	// alternateAccess [5] (ISO 9506-2), exactly as the server sent them,
	// or nil when the member is the whole variable. Kept raw so it can be
	// replayed verbatim; ParseAlternateAccess interprets it.
	AlternateAccess []byte
}

// GetNamedVariableListMembers reads a named variable list's definition,
// keeping each member's alternate access (MMS getNamedVariableListAttributes,
// service 12).
func (c *Conn) GetNamedVariableListMembers(ctx context.Context, domain, listName string) ([]ListMember, bool, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcGetNamedVarListAttr),
		objectName(domain, listName),
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, false, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcGetNamedVarListAttr))
	if err != nil {
		return nil, false, err
	}
	return parseListMembers(content)
}

// parseListMembers decodes a GetNamedVariableListAttributes-Response:
//
//	SEQUENCE { mmsDeletable [0] BOOLEAN,
//	           listOfVariable [1] SEQUENCE OF SEQUENCE {
//	             variableSpecification VariableSpecification,   -- name [0]
//	             alternateAccess [5] IMPLICIT AlternateAccess OPTIONAL } }
func parseListMembers(content []byte) ([]ListMember, bool, error) {
	inner := asn1.NewDecoder(content)
	deletable := false
	if b, ok, err := inner.Optional(asn1.ContextPrimitive(0)); err != nil {
		return nil, false, err
	} else if ok {
		deletable, _ = asn1.DecodeBool(b)
	}
	listContent, err := inner.Expect(asn1.ContextConstructed(1))
	if err != nil {
		return nil, false, err
	}
	var out []ListMember
	ld := asn1.NewDecoder(listContent)
	for ld.More() {
		entry, err := ld.Expect(asn1.TagSequence)
		if err != nil {
			return nil, false, err
		}
		ed := asn1.NewDecoder(entry)
		specContent, err := ed.Expect(asn1.ContextConstructed(0)) // variableSpecification name [0]
		if err != nil {
			return nil, false, err
		}
		ref, err := parseObjectName(specContent)
		if err != nil {
			return nil, false, err
		}
		m := ListMember{VarRef: ref}
		if alt, ok, err := ed.Optional(asn1.ContextConstructed(5)); err != nil {
			return nil, false, err
		} else if ok {
			m.AlternateAccess = append([]byte(nil), alt...)
		}
		out = append(out, m)
	}
	return out, deletable, nil
}

// AccessStep is one step of an alternate access: a structure component by
// name, or an array element by index.
type AccessStep struct {
	Component string // set for a component selection
	Index     int    // array index, when Component is empty
}

func (s AccessStep) String() string {
	if s.Component != "" {
		return "." + s.Component
	}
	return fmt.Sprintf("(%d)", s.Index)
}

// ErrAlternateAccessUnsupported reports an alternate access that does not
// select a single element: an index range, all elements, or a named access.
// IEC 61850-8-1 datasets only ever select one element, so these are refused
// rather than half-supported.
var ErrAlternateAccessUnsupported = errors.New("mms: alternate access selects more than one element")

// ParseAlternateAccess decodes the content of an alternateAccess [5] into a
// chain of steps:
//
//	AlternateAccess ::= SEQUENCE OF CHOICE {
//	  unnamed AlternateAccessSelection, named [5] ... }
//	AlternateAccessSelection ::= CHOICE {
//	  selectAlternateAccess [0] IMPLICIT SEQUENCE {
//	    accessSelection CHOICE { component [0], index [1], indexRange [2], allElements [3] },
//	    alternateAccess AlternateAccess },
//	  selectAccess CHOICE { component [1], index [2], indexRange [3], allElements [4] } }
//
// libiec61850 encodes "phsAHar(10).cVal.mag" as selectAlternateAccess(index
// 10, selectAlternateAccess(component cVal, selectAccess(component mag))).
func ParseAlternateAccess(content []byte) ([]AccessStep, error) {
	dec := asn1.NewDecoder(content)
	var steps []AccessStep
	n := 0
	for dec.More() {
		tag, c, err := dec.ReadTLV()
		if err != nil {
			return nil, err
		}
		if n++; n > 1 {
			return nil, ErrAlternateAccessUnsupported
		}
		switch {
		case tag == asn1.ContextConstructed(0): // selectAlternateAccess
			sd := asn1.NewDecoder(c)
			stag, sc, err := sd.ReadTLV()
			if err != nil {
				return nil, err
			}
			step, err := selection(stag.Number, stag.Constructed, sc, 0)
			if err != nil {
				return nil, err
			}
			steps = append(steps, step...)
			rest, err := sd.Expect(asn1.TagSequence)
			if err != nil {
				return nil, err
			}
			more, err := ParseAlternateAccess(rest)
			if err != nil {
				return nil, err
			}
			steps = append(steps, more...)
		case tag.Class == asn1.ClassContextSpecific && tag.Number >= 1 && tag.Number <= 4: // selectAccess
			step, err := selection(tag.Number, tag.Constructed, c, 1)
			if err != nil {
				return nil, err
			}
			steps = append(steps, step...)
		default:
			return nil, ErrAlternateAccessUnsupported
		}
	}
	return steps, nil
}

// selection decodes one accessSelection. Its CHOICE numbers sit one higher
// in selectAccess than in selectAlternateAccess, which offset absorbs.
func selection(num uint32, constructed bool, c []byte, offset uint32) ([]AccessStep, error) {
	switch num - offset {
	case 0: // component Identifier
		if constructed {
			return nil, fmt.Errorf("mms: constructed component name: %w", asn1.ErrUnexpected)
		}
		// A component path may be written whole, "cVal$mag".
		var out []AccessStep
		for _, p := range strings.Split(string(c), "$") {
			out = append(out, AccessStep{Component: p})
		}
		return out, nil
	case 1: // index Unsigned32
		n, err := asn1.DecodeUint(c)
		if err != nil {
			return nil, err
		}
		return []AccessStep{{Index: int(n)}}, nil
	}
	return nil, ErrAlternateAccessUnsupported
}

// AccessPath resolves alternate-access steps against the variable's type,
// returning the child-index path to the selected element and its type.
func AccessPath(spec *TypeSpec, steps []AccessStep) ([]int, *TypeSpec, error) {
	cur := spec
	path := make([]int, 0, len(steps))
	for _, s := range steps {
		if cur == nil {
			return nil, nil, fmt.Errorf("mms: alternate access %s past a leaf", s)
		}
		if s.Component != "" {
			if cur.Kind != TypeStructure {
				return nil, nil, fmt.Errorf("mms: component %q of a non-structure", s.Component)
			}
			found := -1
			for i, c := range cur.Components {
				if c.Name == s.Component {
					found = i
					break
				}
			}
			if found < 0 {
				return nil, nil, fmt.Errorf("mms: no component %q", s.Component)
			}
			path = append(path, found)
			cur = cur.Components[found].Spec
			continue
		}
		if cur.Kind != TypeArray {
			return nil, nil, fmt.Errorf("mms: index %d of a non-array", s.Index)
		}
		if s.Index < 0 || (cur.Elements > 0 && s.Index >= cur.Elements) {
			return nil, nil, fmt.Errorf("mms: index %d out of range %d", s.Index, cur.Elements)
		}
		path = append(path, s.Index)
		cur = cur.Element
	}
	return path, cur, nil
}

// AlternateAccessElement encodes steps as an alternateAccess [5] element's
// content, the form libiec61850 produces: every step but the last a
// selectAlternateAccess, the last a selectAccess.
func AlternateAccessElement(steps []AccessStep) []byte {
	if len(steps) == 0 {
		return nil
	}
	var build func(i int) *asn1.Element
	build = func(i int) *asn1.Element {
		s := steps[i]
		if i == len(steps)-1 {
			if s.Component != "" {
				return asn1.Prim(asn1.ContextPrimitive(1), []byte(s.Component))
			}
			return asn1.UintElem(asn1.ContextPrimitive(2), uint64(s.Index))
		}
		var sel *asn1.Element
		if s.Component != "" {
			sel = asn1.Prim(asn1.ContextPrimitive(0), []byte(s.Component))
		} else {
			sel = asn1.UintElem(asn1.ContextPrimitive(1), uint64(s.Index))
		}
		return asn1.Cons(asn1.ContextConstructed(0), sel, asn1.Cons(asn1.TagSequence, build(i+1)))
	}
	return build(0).Encode()
}
