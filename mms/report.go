package mms

import "github.com/dscsystems/go-iec61850/asn1"

// InformationReport is an unconfirmed MMS InformationReport PDU, the
// transport for IEC 61850 buffered and unbuffered reports. VariableList
// holds the variable specifications (named-variable itemIDs, or empty for
// a VMD-specific/named-variable-list report) and Values holds the decoded
// AccessResults in the same order.
type InformationReport struct {
	// ListName is set when the report references a named variable list
	// (RCB reports use "RPT" as the conventional first name).
	ListName   string
	VarNames   []string
	Values     []*Value
	IsVMDNamed bool
}

func (c *Conn) handleUnconfirmed(content []byte) {
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
	h := c.reportHandler
	c.mu.Unlock()
	if h != nil {
		h(rep)
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
	switch spec {
	case asn1.ContextConstructed(0): // variableListName
		c, _, _ := dec.ReadTLV()
		_ = c
		rep.IsVMDNamed = true
	case asn1.ContextConstructed(1): // listOfVariable
		_, c, _ := dec.ReadTLV()
		parseVarSpecList(c, rep)
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

func parseVarSpecList(content []byte, rep *InformationReport) {
	dec := asn1.NewDecoder(content)
	for dec.More() {
		// VariableSpecification CHOICE; name [0] -> ObjectName.
		vs, _, err := dec.ReadTLV()
		if err != nil {
			return
		}
		_ = vs
		rep.VarNames = append(rep.VarNames, "")
	}
}
