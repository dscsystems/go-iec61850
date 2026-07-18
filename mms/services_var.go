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
