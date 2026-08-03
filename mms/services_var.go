package mms

import (
	"context"
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// GetVariableAccessAttributes retrieves the TypeSpec of a domain variable
// (getVariableAccessAttributes with a name access specification). Clients
// use it to reconstruct a server's data model.
func (c *Conn) GetVariableAccessAttributes(ctx context.Context, domain, item string) (*TypeSpec, error) {
	// GetVariableAccessAttributes-Request ::= CHOICE {
	//   name [0] ObjectName, address [1] Address }
	req := asn1.Cons(asn1.ContextConstructed(svcGetVariableAccess),
		asn1.Cons(asn1.ContextConstructed(0), objectName(domain, item)),
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcGetVariableAccess))
	if err != nil {
		return nil, err
	}
	// GetVariableAccessAttributes-Response ::= SEQUENCE {
	//   mmsDeletable [0] IMPLICIT BOOLEAN,
	//   address [1] EXPLICIT Address OPTIONAL,
	//   typeSpecification [2] EXPLICIT TypeSpecification }
	inner := asn1.NewDecoder(content)
	if _, _, err := inner.Optional(asn1.ContextPrimitive(0)); err != nil {
		return nil, err
	}
	if _, _, err := inner.Optional(asn1.ContextConstructed(1)); err != nil {
		return nil, err
	}
	tsContent, err := inner.Expect(asn1.ContextConstructed(2))
	if err != nil {
		return nil, err
	}
	return DecodeTypeSpec(asn1.NewDecoder(tsContent))
}

// ReadNamedVariableList reads all members of a named variable list (a
// dataset) and returns their values in order.
func (c *Conn) ReadNamedVariableList(ctx context.Context, domain, listName string) ([]*Value, error) {
	// Read-Request with variableAccessSpecification = variableListName [1].
	vas := asn1.Cons(asn1.ContextConstructed(1), // variableAccessSpecification [1] EXPLICIT
		asn1.Cons(asn1.ContextConstructed(1), objectName(domain, listName)), // variableListName [1]
	)
	req := asn1.Cons(asn1.ContextConstructed(svcRead), vas)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	return parseReadResponse(resp)
}

// GetVariableAccessAttributesRaw retrieves a variable's TypeSpecification as
// the raw BER octets the server sent, alongside the decoded form.
//
// A proxy standing in for the server replays these octets verbatim. Decoding
// and re-encoding is close to lossless but not exactly so — a server may use a
// non-minimal integer length, or a form this package normalises — and "close"
// is not good enough when a client validates the type against its own
// configuration.
func (c *Conn) GetVariableAccessAttributesRaw(ctx context.Context, domain, item string) (*TypeSpec, []byte, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcGetVariableAccess),
		asn1.Cons(asn1.ContextConstructed(0), objectName(domain, item)),
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcGetVariableAccess))
	if err != nil {
		return nil, nil, err
	}
	inner := asn1.NewDecoder(content)
	if _, _, err := inner.Optional(asn1.ContextPrimitive(0)); err != nil {
		return nil, nil, err
	}
	if _, _, err := inner.Optional(asn1.ContextConstructed(1)); err != nil {
		return nil, nil, err
	}
	tsContent, err := inner.Expect(asn1.ContextConstructed(2))
	if err != nil {
		return nil, nil, err
	}
	// tsContent is the content of the [2] EXPLICIT wrapper, i.e. the
	// TypeSpecification CHOICE element itself.
	raw := append([]byte(nil), tsContent...)
	ts, err := DecodeTypeSpec(asn1.NewDecoder(tsContent))
	if err != nil {
		return nil, raw, err
	}
	return ts, raw, nil
}

// ReadNamedVariableListWithSpec reads a named variable list and asks the
// server to echo the access specification, so the caller learns which members
// the values correspond to without a separate
// GetNamedVariableListAttributes round trip. Servers may omit the
// specification even when asked; the returned refs are then nil.
func (c *Conn) ReadNamedVariableListWithSpec(ctx context.Context, domain, listName string) ([]VarRef, []*Value, error) {
	vas := asn1.Cons(asn1.ContextConstructed(1),
		asn1.Cons(asn1.ContextConstructed(1), objectName(domain, listName)),
	)
	req := asn1.Cons(asn1.ContextConstructed(svcRead),
		asn1.BoolElem(asn1.ContextPrimitive(0), true), // specificationWithResult
		vas,
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	return parseReadResponseWithSpec(resp)
}

// parseReadResponseWithSpec decodes a Read-Response, returning the echoed
// access specification's variable references when present.
func parseReadResponseWithSpec(resp []byte) ([]VarRef, []*Value, error) {
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcRead))
	if err != nil {
		return nil, nil, err
	}
	inner := asn1.NewDecoder(content)

	var refs []VarRef
	if specContent, ok, err := inner.Optional(asn1.ContextConstructed(0)); err != nil {
		return nil, nil, err
	} else if ok {
		sd := asn1.NewDecoder(specContent)
		// variableAccessSpecification CHOICE: only listOfVariable [0] names
		// the members individually.
		if listContent, ok, _ := sd.Optional(asn1.ContextConstructed(0)); ok {
			ld := asn1.NewDecoder(listContent)
			for ld.More() {
				entry, err := ld.Expect(asn1.TagSequence)
				if err != nil {
					break
				}
				ed := asn1.NewDecoder(entry)
				nameContent, err := ed.Expect(asn1.ContextConstructed(0))
				if err != nil {
					break
				}
				ref, err := parseObjectName(nameContent)
				if err != nil {
					break
				}
				refs = append(refs, ref)
			}
		}
	}

	arContent, err := inner.Expect(asn1.ContextConstructed(1))
	if err != nil {
		return nil, nil, err
	}
	var values []*Value
	ar := asn1.NewDecoder(arContent)
	for ar.More() {
		v, err := DecodeAccessResult(ar)
		if err != nil {
			return nil, nil, err
		}
		values = append(values, v)
	}
	return refs, values, nil
}

// DefineNamedVariableList creates a named variable list (dataset) from the
// given domain variable item IDs.
func (c *Conn) DefineNamedVariableList(ctx context.Context, domain, listName string, members []VarRef) error {
	list := asn1.Cons(asn1.ContextConstructed(1)) // listOfVariable [1]
	for _, m := range members {
		list.Add(asn1.Cons(asn1.TagSequence,
			asn1.Cons(asn1.ContextConstructed(0), objectName(m.Domain, m.Item)),
		))
	}
	// DefineNamedVariableList-Request ::= SEQUENCE {
	//   variableListName ObjectName, listOfVariable [1] SEQUENCE OF ... }
	req := asn1.Cons(asn1.ContextConstructed(svcDefineNamedVarList),
		objectName(domain, listName),
		list,
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return err
	}
	dec := asn1.NewDecoder(resp)
	if _, err := dec.Expect(asn1.ContextConstructed(svcDefineNamedVarList)); err != nil {
		// Some servers reply with an empty (NULL) response element.
		if !asn1.NewDecoder(resp).PeekIs(asn1.ContextPrimitive(svcDefineNamedVarList)) {
			return err
		}
	}
	return nil
}

// DeleteNamedVariableList deletes a named variable list (dataset).
func (c *Conn) DeleteNamedVariableList(ctx context.Context, domain, listName string) error {
	// DeleteNamedVariableList-Request ::= SEQUENCE {
	//   scopeOfDelete [0] INTEGER DEFAULT specific,
	//   listOfVariableListName [1] SEQUENCE OF ObjectName OPTIONAL, ... }
	req := asn1.Cons(asn1.ContextConstructed(svcDeleteNamedVarList),
		asn1.Cons(asn1.ContextConstructed(1), objectName(domain, listName)),
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return err
	}
	_ = resp
	return nil
}

// GetNamedVariableListAttributes returns the member references of a named
// variable list (dataset).
func (c *Conn) GetNamedVariableListAttributes(ctx context.Context, domain, listName string) ([]VarRef, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcGetNamedVarListAttr),
		objectName(domain, listName),
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcGetNamedVarListAttr))
	if err != nil {
		return nil, err
	}
	inner := asn1.NewDecoder(content)
	// GetNamedVariableListAttributes-Response ::= SEQUENCE {
	//   mmsDeletable [0] BOOLEAN, listOfVariable [1] SEQUENCE OF ... }
	if _, _, err := inner.Optional(asn1.ContextPrimitive(0)); err != nil {
		return nil, err
	}
	listContent, err := inner.Expect(asn1.ContextConstructed(1))
	if err != nil {
		return nil, err
	}
	var refs []VarRef
	ld := asn1.NewDecoder(listContent)
	for ld.More() {
		entry, err := ld.Expect(asn1.TagSequence)
		if err != nil {
			return nil, err
		}
		ed := asn1.NewDecoder(entry)
		specContent, err := ed.Expect(asn1.ContextConstructed(0)) // variableSpecification name [0]
		if err != nil {
			return nil, err
		}
		ref, err := parseObjectName(specContent)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}

// VarRef names a domain variable (domain + MMS itemID).
type VarRef struct {
	Domain string
	Item   string
}

func (v VarRef) String() string { return v.Domain + "/" + v.Item }

// parseObjectName decodes an ObjectName element content into a VarRef.
func parseObjectName(content []byte) (VarRef, error) {
	dec := asn1.NewDecoder(content)
	tag, c, err := dec.ReadTLV()
	if err != nil {
		return VarRef{}, err
	}
	switch tag {
	case asn1.ContextPrimitive(0): // vmd-specific
		return VarRef{Item: string(c)}, nil
	case asn1.ContextConstructed(1): // domain-specific
		dd := asn1.NewDecoder(c)
		domain, err := dd.Expect(asn1.TagVisibleString)
		if err != nil {
			return VarRef{}, err
		}
		item, err := dd.Expect(asn1.TagVisibleString)
		if err != nil {
			return VarRef{}, err
		}
		return VarRef{Domain: string(domain), Item: string(item)}, nil
	default:
		return VarRef{}, fmt.Errorf("mms: unexpected ObjectName tag %v", tag)
	}
}
