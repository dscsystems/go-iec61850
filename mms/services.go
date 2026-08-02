package mms

import (
	"context"
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// ObjectClass identifies the object class for getNameList.
type ObjectClass int

// ISO 9506-2 basic object classes. Servers commonly implement only a subset;
// getNameList for an unsupported class answers with an access error.
const (
	ClassNamedVariable     ObjectClass = 0
	ClassScatteredAccess   ObjectClass = 1
	ClassNamedVariableList ObjectClass = 2
	ClassNamedType         ObjectClass = 3
	ClassSemaphore         ObjectClass = 4
	ClassEventCondition    ObjectClass = 5
	ClassEventAction       ObjectClass = 6
	ClassEventEnrollment   ObjectClass = 7
	ClassJournal           ObjectClass = 8
	ClassDomain            ObjectClass = 9
	ClassProgramInvocation ObjectClass = 10
	ClassOperatorStation   ObjectClass = 11
)

// objectName builds an MMS ObjectName. When domain is empty the name is
// vmd-specific; otherwise it is domain-specific with the given itemID.
func objectName(domain, item string) *asn1.Element {
	if domain == "" {
		return asn1.Prim(asn1.ContextPrimitive(0), []byte(item)) // vmd-specific
	}
	return asn1.Cons(asn1.ContextConstructed(1), // domain-specific
		asn1.Prim(asn1.TagVisibleString, []byte(domain)),
		asn1.Prim(asn1.TagVisibleString, []byte(item)),
	)
}

// variableEntry builds one ListOfVariable entry naming a domain variable.
func variableEntry(domain, item string) *asn1.Element {
	return asn1.Cons(asn1.TagSequence,
		asn1.Cons(asn1.ContextConstructed(0), objectName(domain, item)), // variableSpecification: name [0]
	)
}

// Call issues a confirmed request carrying the given service element and
// returns the response's service element content. It is the escape hatch for
// services this package does not wrap: a thorough census wants to try
// GetCapabilityList, Status and vendor services, and a proxy may need to
// forward whatever a client sends.
func (c *Conn) Call(ctx context.Context, service *asn1.Element) ([]byte, error) {
	return c.call(ctx, service)
}

// Identify issues the Identify service and returns vendor/model/revision.
func (c *Conn) Identify(ctx context.Context) (vendor, model, revision string, err error) {
	// identify [2] IMPLICIT Identify-Request ::= NULL (primitive, empty).
	resp, err := c.call(ctx, asn1.Prim(asn1.ContextPrimitive(svcIdentify), nil))
	if err != nil {
		return "", "", "", err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcIdentify))
	if err != nil {
		return "", "", "", err
	}
	inner := asn1.NewDecoder(content)
	if v, ok, _ := inner.Optional(asn1.ContextPrimitive(0)); ok {
		vendor = string(v)
	}
	if v, ok, _ := inner.Optional(asn1.ContextPrimitive(1)); ok {
		model = string(v)
	}
	if v, ok, _ := inner.Optional(asn1.ContextPrimitive(2)); ok {
		revision = string(v)
	}
	return vendor, model, revision, nil
}

// GetNameList retrieves the names of the given object class, optionally
// scoped to a domain, following continuation until the list is complete.
func (c *Conn) GetNameList(ctx context.Context, class ObjectClass, domain string) ([]string, error) {
	var names []string
	after := ""
	for {
		batch, more, err := c.getNameListPage(ctx, class, domain, after)
		if err != nil {
			return nil, err
		}
		names = append(names, batch...)
		if !more || len(batch) == 0 {
			return names, nil
		}
		after = batch[len(batch)-1]
	}
}

func (c *Conn) getNameListPage(ctx context.Context, class ObjectClass, domain, after string) ([]string, bool, error) {
	// GetNameList-Request ::= SEQUENCE {
	//   objectClass [0] ObjectClass,
	//   objectScope [1] CHOICE { vmdSpecific [0] NULL, domainSpecific [1] Identifier, aaSpecific [2] NULL },
	//   continueAfter [2] Identifier OPTIONAL }
	req := asn1.Cons(asn1.ContextConstructed(svcGetNameList),
		asn1.Cons(asn1.ContextConstructed(0), asn1.IntElem(asn1.ContextPrimitive(0), int64(class))),
	)
	if domain == "" {
		req.Add(asn1.Cons(asn1.ContextConstructed(1), asn1.Prim(asn1.ContextPrimitive(0), nil)))
	} else {
		req.Add(asn1.Cons(asn1.ContextConstructed(1), asn1.Prim(asn1.ContextPrimitive(1), []byte(domain))))
	}
	if after != "" {
		req.Add(asn1.Prim(asn1.ContextPrimitive(2), []byte(after)))
	}
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, false, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcGetNameList))
	if err != nil {
		return nil, false, err
	}
	inner := asn1.NewDecoder(content)
	// GetNameList-Response ::= SEQUENCE {
	//   listOfIdentifier [0] SEQUENCE OF Identifier,
	//   moreFollows [1] BOOLEAN DEFAULT TRUE }
	listContent, err := inner.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, false, err
	}
	var names []string
	ld := asn1.NewDecoder(listContent)
	for ld.More() {
		id, err := ld.Expect(asn1.TagVisibleString)
		if err != nil {
			return nil, false, err
		}
		names = append(names, string(id))
	}
	more := true
	if mf, ok, _ := inner.Optional(asn1.ContextPrimitive(1)); ok {
		more, _ = asn1.DecodeBool(mf)
	}
	return names, more, nil
}

// Read reads one or more domain variables and returns their values in
// order. Per-element failures are returned as DataAccessError values.
func (c *Conn) Read(ctx context.Context, domain string, items ...string) ([]*Value, error) {
	if len(items) == 0 {
		return nil, fmt.Errorf("mms: Read requires at least one item")
	}
	list := asn1.Cons(asn1.ContextConstructed(0)) // listOfVariable [0]
	for _, item := range items {
		list.Add(variableEntry(domain, item))
	}
	// ReadRequest.variableAccessSpecification is [1] EXPLICIT in the MMS
	// module used by 61850 (unlike WriteRequest, where it is untagged).
	vas := asn1.Cons(asn1.ContextConstructed(1), list)
	req := asn1.Cons(asn1.ContextConstructed(svcRead), vas)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	return parseReadResponse(resp)
}

// ReadRefs reads variables that may span several domains and VMD scope in one
// request. Conn.Read applies a single domain to every item, which cannot
// express a dataset whose members mix scopes — a real ICCP dataset does
// exactly that. Per-element failures come back as DataAccessError values.
func (c *Conn) ReadRefs(ctx context.Context, refs []VarRef) ([]*Value, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("mms: ReadRefs requires at least one reference")
	}
	list := asn1.Cons(asn1.ContextConstructed(0)) // listOfVariable [0]
	for _, r := range refs {
		list.Add(variableEntry(r.Domain, r.Item))
	}
	vas := asn1.Cons(asn1.ContextConstructed(1), list)
	req := asn1.Cons(asn1.ContextConstructed(svcRead), vas)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	return parseReadResponse(resp)
}

func parseReadResponse(resp []byte) ([]*Value, error) {
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcRead))
	if err != nil {
		return nil, err
	}
	inner := asn1.NewDecoder(content)
	// Optional variableAccessSpecification [0], then listOfAccessResult [1].
	if _, ok, err := inner.Optional(asn1.ContextConstructed(0)); err != nil {
		return nil, err
	} else {
		_ = ok
	}
	arContent, err := inner.Expect(asn1.ContextConstructed(1))
	if err != nil {
		return nil, err
	}
	var values []*Value
	ar := asn1.NewDecoder(arContent)
	for ar.More() {
		v, err := DecodeAccessResult(ar)
		if err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, nil
}

// Write writes values to the named domain variables and returns a
// per-item DataAccessError (nil on success) for each.
func (c *Conn) Write(ctx context.Context, domain string, items []string, values []*Value) ([]error, error) {
	if len(items) != len(values) {
		return nil, fmt.Errorf("mms: Write items/values length mismatch")
	}
	list := asn1.Cons(asn1.ContextConstructed(0))
	for _, item := range items {
		list.Add(variableEntry(domain, item))
	}
	data := asn1.Cons(asn1.ContextConstructed(0)) // listOfData [0]
	for _, v := range values {
		data.Add(DataElement(v))
	}
	// Write-Request ::= SEQUENCE { variableAccessSpecification, listOfData [0] }
	req := asn1.Cons(asn1.ContextConstructed(svcWrite), list, data)
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcWrite))
	if err != nil {
		return nil, err
	}
	// Write-Response ::= SEQUENCE OF CHOICE { failure [0] DataAccessError, success [1] NULL }
	var results []error
	inner := asn1.NewDecoder(content)
	for inner.More() {
		tag, c, err := inner.ReadTLV()
		if err != nil {
			return nil, err
		}
		switch tag {
		case asn1.ContextPrimitive(0): // failure
			code, _ := asn1.DecodeUint(c)
			results = append(results, DataAccessError(code))
		default: // success [1] NULL
			results = append(results, nil)
		}
	}
	return results, nil
}
