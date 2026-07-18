package client

import (
	"context"
	"sort"
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// RetrieveModel reconstructs the server's data model by enumerating its
// domains and logical nodes and reading the type specification of each
// functionally-constrained top-level data object. The returned model is
// suitable for browsing (the TUI uses it); leaf values are not read here,
// use Read for live values.
func (c *Client) RetrieveModel(ctx context.Context) (*model.Model, error) {
	domains, err := c.LogicalDevices(ctx)
	if err != nil {
		return nil, err
	}
	m := &model.Model{}
	for _, domain := range domains {
		ld, err := c.retrieveDevice(ctx, domain)
		if err != nil {
			return nil, err
		}
		m.Devices = append(m.Devices, ld)
	}
	if len(m.Devices) > 0 {
		// IED name is the common prefix up to the LD instance; best effort.
		m.Name = m.Devices[0].Name
	}
	return m, nil
}

func (c *Client) retrieveDevice(ctx context.Context, domain string) (*model.LogicalDevice, error) {
	names, err := c.mc.GetNameList(ctx, mms.ClassNamedVariable, domain)
	if err != nil {
		return nil, err
	}
	ld := &model.LogicalDevice{Name: domain}

	// Group variable names by (LN, FC, topDO). We fetch the type spec of
	// each LN$FC$DO once and expand it into the model tree.
	type key struct{ ln, fc, do string }
	seen := map[key]bool{}
	lnOrder := []string{}
	lnSeen := map[string]bool{}

	for _, name := range names {
		parts := strings.Split(name, "$")
		if len(parts) < 3 {
			if len(parts) == 1 && !lnSeen[parts[0]] {
				lnSeen[parts[0]] = true
				lnOrder = append(lnOrder, parts[0])
			}
			continue
		}
		ln, fcStr, do := parts[0], parts[1], parts[2]
		fc, err := model.ParseFC(fcStr)
		if err != nil {
			continue
		}
		if !lnSeen[ln] {
			lnSeen[ln] = true
			lnOrder = append(lnOrder, ln)
		}
		k := key{ln, fcStr, do}
		if seen[k] {
			continue
		}
		seen[k] = true

		ts, err := c.mc.GetVariableAccessAttributes(ctx, domain, ln+"$"+fcStr+"$"+do)
		if err != nil {
			continue // skip objects we cannot introspect
		}
		lnNode := ensureLN(ld, ln)
		doNode := ensureDO(lnNode, do)
		expandTypeSpec(doNode, ts, fc)
	}

	// Ensure logical nodes with no readable DOs still appear.
	for _, ln := range lnOrder {
		ensureLN(ld, ln)
	}
	sort.SliceStable(ld.Nodes, func(i, j int) bool { return ld.Nodes[i].Name < ld.Nodes[j].Name })
	return ld, nil
}

func ensureLN(ld *model.LogicalDevice, name string) *model.LogicalNode {
	if ln := ld.Node(name); ln != nil {
		return ln
	}
	ln := &model.LogicalNode{Name: name, Class: lnClass(name)}
	ld.Nodes = append(ld.Nodes, ln)
	return ln
}

func ensureDO(ln *model.LogicalNode, name string) *model.DataObject {
	if do := ln.Object(name); do != nil {
		return do
	}
	do := &model.DataObject{Name: name}
	ln.Objects = append(ln.Objects, do)
	return do
}

// lnClass extracts the LN class from an instance name (e.g. "Q0XCBR1" ->
// "XCBR", "LLN0" -> "LLN0").
func lnClass(name string) string {
	if name == "LLN0" {
		return "LLN0"
	}
	// Strip a trailing instance number and a leading prefix: the class is
	// the four-letter core. Best effort without SCL.
	end := len(name)
	for end > 0 && name[end-1] >= '0' && name[end-1] <= '9' {
		end--
	}
	core := name[:end]
	if len(core) >= 4 {
		return core[len(core)-4:]
	}
	return core
}

// expandTypeSpec grafts an MMS structure type spec onto a data object as
// data attributes under the given functional constraint.
func expandTypeSpec(do *model.DataObject, ts *mms.TypeSpec, fc model.FC) {
	if ts.Kind != mms.TypeStructure {
		// A DO whose FC view is a single value: represent as one attribute.
		do.Attributes = append(do.Attributes, &model.DataAttribute{
			Name: do.Name, FC: fc, Kind: ts.Kind, Value: ts.DefaultValue(),
		})
		return
	}
	for _, comp := range ts.Components {
		do.Attributes = append(do.Attributes, attrFromSpec(comp.Name, comp.Spec, fc))
	}
}

func attrFromSpec(name string, ts *mms.TypeSpec, fc model.FC) *model.DataAttribute {
	da := &model.DataAttribute{Name: name, FC: fc, Kind: ts.Kind}
	switch ts.Kind {
	case mms.TypeStructure:
		for _, comp := range ts.Components {
			da.Children = append(da.Children, attrFromSpec(comp.Name, comp.Spec, fc))
		}
	case mms.TypeArray:
		da.Count = ts.Elements
		da.Value = ts.DefaultValue()
	default:
		da.Value = ts.DefaultValue()
	}
	return da
}
