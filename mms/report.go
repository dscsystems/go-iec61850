package mms

import "github.com/dscsystems/go-iec61850/asn1"

// InformationReport is an unconfirmed MMS InformationReport PDU, the
// transport for IEC 61850 buffered and unbuffered reports. VariableList
// holds the variable specifications (named-variable itemIDs, or empty for
// a VMD-specific/named-variable-list report) and Values holds the decoded
// AccessResults in the same order.
type InformationReport struct {
	// ListName is set when the report references a named variable list
	// (RCB reports use "RPT" as the conventional first name). It holds only
	// the item ID; ListRef carries the domain as well.
	ListName string
	// VarNames holds the item IDs of the listOfVariable form's entries, in the
	// same order as Values. VarRefs carries the same entries with their scope.
	VarNames []string
	Values   []*Value
	// IsVMDNamed reports that the access specification was a variableListName
	// rather than a listOfVariable.
	IsVMDNamed bool

	// ListRef is the fully scoped name of the referenced variable list. A
	// proxy needs the domain as well as the item to attribute a report.
	ListRef VarRef
	// VarRefs holds the fully scoped names of the listOfVariable entries, in
	// the same order as Values. An entry is zero when the specification used
	// an alternative other than name [0].
	VarRefs []VarRef
}

func (c *Conn) handleUnconfirmed(content []byte) {
	// The raw handlers run first and see every unconfirmed PDU, including
	// services this package does not decode. A proxy that must reproduce what
	// arrived needs the octets, not an interpretation of them.
	c.mu.Lock()
	raw := c.rawUnconfHandlers
	c.mu.Unlock()
	for _, e := range raw {
		e.fn(content)
	}

	dec := asn1.NewDecoder(content)
	tag, body, err := dec.ReadTLV()
	if err != nil {
		return
	}
	if tag != asn1.ContextConstructed(unconfInformationReport) {
		return
	}
	rep := parseInformationReport(body)
	if rep == nil {
		return
	}
	c.mu.Lock()
	handlers := c.reportHandlers
	c.mu.Unlock()
	for _, e := range handlers {
		e.fn(rep)
	}
}

// parseInformationReport decodes an InformationReport: variableAccessSpec
// CHOICE followed by listOfAccessResult SEQUENCE OF AccessResult.
func parseInformationReport(body []byte) *InformationReport {
	dec := asn1.NewDecoder(body)
	rep := &InformationReport{}

	spec, err := dec.Peek()
	if err != nil {
		return nil
	}
	// VariableAccessSpecification ::= CHOICE {
	//   listOfVariable   [0] IMPLICIT SEQUENCE OF ...,
	//   variableListName [1] ObjectName }
	//
	// These two were previously transposed, so a report naming a variable list
	// — which is what every IEC 61850 RCB report does — was decoded as a list
	// of variable specifications and its name was lost.
	switch spec {
	case asn1.ContextConstructed(0): // listOfVariable
		_, c, _ := dec.ReadTLV()
		parseVarSpecList(c, rep)
	case asn1.ContextConstructed(1): // variableListName
		_, c, _ := dec.ReadTLV()
		rep.IsVMDNamed = true
		if ref, err := parseObjectName(c); err == nil {
			rep.ListRef = ref
			rep.ListName = ref.Item
		}
	default:
		// Unknown spec; skip one element.
		dec.Skip()
	}

	// listOfAccessResult [0] IMPLICIT SEQUENCE OF AccessResult
	if arContent, ok, _ := dec.Optional(asn1.ContextConstructed(0)); ok {
		ar := asn1.NewDecoder(arContent)
		for ar.More() {
			v, err := DecodeAccessResult(ar)
			if err != nil {
				break
			}
			rep.Values = append(rep.Values, v)
		}
	}
	return rep
}

// parseVarSpecList decodes the listOfVariable form's VariableSpecifications.
// Each entry is a CHOICE whose name [0] alternative carries an ObjectName;
// other alternatives (address, variableDescription, scatteredAccess) leave an
// empty entry so the positions still line up with listOfAccessResult.
func parseVarSpecList(content []byte, rep *InformationReport) {
	dec := asn1.NewDecoder(content)
	for dec.More() {
		tag, vs, err := dec.ReadTLV()
		if err != nil {
			return
		}
		var ref VarRef
		if tag == asn1.ContextConstructed(0) { // name [0] ObjectName
			if r, err := parseObjectName(vs); err == nil {
				ref = r
			}
		}
		rep.VarRefs = append(rep.VarRefs, ref)
		rep.VarNames = append(rep.VarNames, ref.Item)
	}
}
