package server

import (
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// namesForDomain enumerates the MMS variable item IDs a client sees via
// getNameList for one logical device: for each logical node, the bare LN
// name, then LN$FC and the DO/DA paths under each functional constraint,
// in a stable order.
func namesForDomain(ld *model.LogicalDevice) []string {
	var names []string
	for _, ln := range ld.Nodes {
		names = append(names, ln.Name)
		// Collect the FCs present, in canonical order.
		fcs := map[model.FC][]*model.DataObject{}
		var order []model.FC
		// fcText maps a constraint to the mnemonic to compose item IDs
		// with: the verbatim spelling when the object is under a
		// constraint this library does not know.
		fcText := map[model.FC]string{}
		for _, do := range ln.Objects {
			for _, fc := range do.FCs() {
				if _, ok := fcs[fc]; !ok {
					order = append(order, fc)
					fcText[fc] = do.FCText(fc)
				}
				fcs[fc] = append(fcs[fc], do)
			}
		}
		sortFCs(order)
		for _, fc := range order {
			prefix := ln.Name + "$" + fcText[fc]
			names = append(names, prefix)
			for _, do := range ln.Objects {
				if !hasFC(do, fc) {
					continue
				}
				names = append(names, prefix+"$"+do.Name)
				for _, a := range do.Attributes {
					appendAttrNames(&names, prefix+"$"+do.Name, a, fc)
				}
				for _, sub := range do.Objects {
					appendSubDONames(&names, prefix+"$"+do.Name, sub, fc)
				}
			}
		}
	}
	return names
}

func appendSubDONames(names *[]string, prefix string, do *model.DataObject, fc model.FC) {
	if !hasFC(do, fc) {
		return
	}
	p := prefix + "$" + do.Name
	*names = append(*names, p)
	for _, a := range do.Attributes {
		appendAttrNames(names, p, a, fc)
	}
	for _, sub := range do.Objects {
		appendSubDONames(names, p, sub, fc)
	}
}

func appendAttrNames(names *[]string, prefix string, a *model.DataAttribute, fc model.FC) {
	if a.FC != fc {
		return
	}
	p := prefix + "$" + a.Name
	*names = append(*names, p)
	for _, c := range a.Children {
		appendAttrNames(names, p, c, fc)
	}
}

func hasFC(do *model.DataObject, fc model.FC) bool {
	for _, f := range do.FCs() {
		if f == fc {
			return true
		}
	}
	return false
}

func sortFCs(fcs []model.FC) {
	for i := 1; i < len(fcs); i++ {
		for j := i; j > 0 && fcs[j] < fcs[j-1]; j-- {
			fcs[j], fcs[j-1] = fcs[j-1], fcs[j]
		}
	}
}

// resolveRead returns the MMS value for an item ID "LN$FC$DO[$DA...]"
// within a logical node, composing structures for DO- and structured-DA
// level reads. A false ok means the item does not resolve, or its leaf has a
// basic type this library does not know: readErr says which.
func resolveRead(ln *model.LogicalNode, item string) (*mms.Value, bool) {
	v, _, ok := resolveReadErr(ln, item)
	return v, ok
}

// resolveReadErr is resolveRead with the access error that explains a
// failure, so a caller can answer with a reason rather than the generic
// object-non-existent.
func resolveReadErr(ln *model.LogicalNode, item string) (*mms.Value, byte, bool) {
	notFound := byte(mms.AccessObjectNonExistent)
	parts := strings.Split(item, "$")
	if len(parts) < 2 {
		return nil, notFound, false
	}
	// readOK is the reason a successful read reports. It is not a
	// DataAccessError — ISO 9506-2 defines 0..11 — so it must never be
	// returned on a failure path, where it would reach the peer as an
	// undefined error code.
	const readOK = byte(0xff)
	fc := model.ParseFCLenient(parts[1])
	if len(parts) == 2 {
		// LN$FC: structure of all DOs with that FC.
		var members []*mms.Value
		for _, do := range ln.Objects {
			if v, ok := doValue(do, fc); ok {
				members = append(members, v)
			}
		}
		return mms.NewStructure(members...), readOK, true
	}
	do := ln.Object(parts[2])
	if do == nil {
		return nil, notFound, false
	}
	rest := parts[3:]
	// Descend sub-objects.
	for len(rest) > 0 {
		if sub := do.Child(rest[0]); sub != nil {
			do, rest = sub, rest[1:]
			continue
		}
		break
	}
	if len(rest) == 0 {
		// The data object is not exposed under this functional
		// constraint, so the item "LN$FC$DO" does not exist on the
		// device. That is a missing item rather than a type problem, and
		// saying so matters: a client told type-inconsistent would look
		// for a type it cannot find.
		v, ok := doValue(do, fc)
		if !ok {
			return nil, notFound, false
		}
		return v, readOK, true
	}
	// Descend attributes.
	var da *model.DataAttribute
	for _, a := range do.Attributes {
		if a.Name == rest[0] && a.FC == fc {
			da = a
			break
		}
	}
	if da == nil {
		return nil, notFound, false
	}
	for _, name := range rest[1:] {
		da = da.Child(name)
		if da == nil {
			return nil, notFound, false
		}
	}
	v := daValue(da)
	if v == nil {
		// A leaf whose basic type this library does not know has no value
		// this library could encode, and no type to describe it in a
		// GetVariableAccessAttributes reply. Returning a zero of some
		// other type would be a lie the client cannot detect, so the read
		// reports that the type is inconsistent rather than the object
		// being absent — the object is there, and the client should be
		// able to tell the two cases apart.
		return nil, byte(mms.AccessTypeInconsistent), false
	}
	return v, readOK, true
}

// doValue composes the value of a data object under one FC as a structure
// of its matching attributes and sub-objects.
func doValue(do *model.DataObject, fc model.FC) (*mms.Value, bool) {
	var members []*mms.Value
	for _, a := range do.Attributes {
		if a.FC != fc {
			continue
		}
		v := daValue(a)
		if v == nil {
			// One member of the structure cannot be produced. Returning
			// the rest would encode a structure with fewer components
			// than the type specification declares, and the client would
			// read them against the wrong member names — silent
			// misalignment, which is worse than an error.
			return nil, false
		}
		members = append(members, v)
	}
	for _, sub := range do.Objects {
		if v, ok := doValue(sub, fc); ok && v.Len() > 0 {
			members = append(members, v)
		}
	}
	if len(members) == 0 {
		return nil, false
	}
	return mms.NewStructure(members...), true
}

// daValue returns the value of a data attribute: its leaf value or a
// structure of its children.
func daValue(da *model.DataAttribute) *mms.Value {
	if len(da.Children) == 0 {
		if da.Value != nil {
			return da.Value.Clone()
		}
		if da.Kind == mms.TypeNone {
			// The basic type is one this library does not know, so there
			// is no value it could encode and no way to describe it. A
			// zero of some other type would be a lie the client cannot
			// detect, so this reports the access error instead.
			return nil
		}
		return mms.NewBool(false)
	}
	members := make([]*mms.Value, 0, len(da.Children))
	for _, c := range da.Children {
		v := daValue(c)
		if v == nil {
			return nil
		}
		members = append(members, v)
	}
	return mms.NewStructure(members...)
}

// resolveWrite finds the leaf data attribute for an item ID and sets its
// value. Only leaf (non-structured) attributes are writable here.
func resolveWrite(ln *model.LogicalNode, item string, v *mms.Value) (*model.DataAttribute, bool) {
	parts := strings.Split(item, "$")
	if len(parts) < 4 {
		return nil, false
	}
	fc := model.ParseFCLenient(parts[1])
	do := ln.Object(parts[2])
	if do == nil {
		return nil, false
	}
	rest := parts[3:]
	for len(rest) > 1 {
		if sub := do.Child(rest[0]); sub != nil {
			do, rest = sub, rest[1:]
			continue
		}
		break
	}
	var da *model.DataAttribute
	for _, a := range do.Attributes {
		if a.Name == rest[0] && a.FC == fc {
			da = a
			break
		}
	}
	if da == nil {
		return nil, false
	}
	for _, name := range rest[1:] {
		da = da.Child(name)
		if da == nil {
			return nil, false
		}
	}
	if len(da.Children) != 0 {
		return nil, false // cannot write a structured attribute directly
	}
	return da, true
}

// typeSpecFor returns the MMS TypeSpec for an item ID at logical-node,
// functional-constraint, data-object or data-attribute level, mirroring
// what conformant servers report for getVariableAccessAttributes.
func typeSpecFor(ln *model.LogicalNode, item string) (*mms.TypeSpec, bool) {
	parts := strings.Split(item, "$")
	switch len(parts) {
	case 1:
		return lnTypeSpec(ln), true // "LN": a structure with one member per FC
	case 2:
		// "LN$FC": one member per data object exposing that FC. An
		// unknown FC yields an empty structure rather than an error, so a
		// newer constraint does not make the node un-introspectable.
		return fcTypeSpec(ln, model.ParseFCLenient(parts[1])), true
	}
	fc := model.ParseFCLenient(parts[1])
	do := ln.Object(parts[2])
	if do == nil {
		return nil, false
	}
	rest := parts[3:]
	for len(rest) > 0 {
		if sub := do.Child(rest[0]); sub != nil {
			do, rest = sub, rest[1:]
			continue
		}
		break
	}
	if len(rest) == 0 {
		return doTypeSpec(do, fc), true
	}
	var da *model.DataAttribute
	for _, a := range do.Attributes {
		if a.Name == rest[0] && a.FC == fc {
			da = a
			break
		}
	}
	if da == nil {
		return nil, false
	}
	for _, name := range rest[1:] {
		da = da.Child(name)
		if da == nil {
			return nil, false
		}
	}
	return daTypeSpec(da), true
}

// lnTypeSpec builds the logical-node type: a structure with one member per
// functional constraint present, named by the FC.
func lnTypeSpec(ln *model.LogicalNode) *mms.TypeSpec {
	seen := map[model.FC]bool{}
	var order []model.FC
	for _, do := range ln.Objects {
		for _, fc := range do.FCs() {
			if !seen[fc] {
				seen[fc] = true
				order = append(order, fc)
			}
		}
	}
	sortFCs(order)
	ts := &mms.TypeSpec{Kind: mms.TypeStructure}
	for _, fc := range order {
		ts.Components = append(ts.Components, mms.Component{
			Name: fcNameFor(ln, fc), Spec: fcTypeSpec(ln, fc),
		})
	}
	return ts
}

// fcNameFor is the component name a node-level type specification uses for a
// functional constraint: the verbatim mnemonic for one this library does not
// know.
func fcNameFor(ln *model.LogicalNode, fc model.FC) string {
	for _, do := range ln.Objects {
		if hasFC(do, fc) {
			return do.FCText(fc)
		}
	}
	return fc.String()
}

// fcTypeSpec builds the functional-constraint type: a structure with one
// member per data object that exposes that FC.
func fcTypeSpec(ln *model.LogicalNode, fc model.FC) *mms.TypeSpec {
	ts := &mms.TypeSpec{Kind: mms.TypeStructure}
	for _, do := range ln.Objects {
		if hasFC(do, fc) {
			ts.Components = append(ts.Components, mms.Component{Name: do.Name, Spec: doTypeSpec(do, fc)})
		}
	}
	return ts
}

func doTypeSpec(do *model.DataObject, fc model.FC) *mms.TypeSpec {
	ts := &mms.TypeSpec{Kind: mms.TypeStructure}
	for _, a := range do.Attributes {
		if a.FC == fc {
			ts.Components = append(ts.Components, mms.Component{Name: a.Name, Spec: daTypeSpec(a)})
		}
	}
	for _, sub := range do.Objects {
		if hasFC(sub, fc) {
			ts.Components = append(ts.Components, mms.Component{Name: sub.Name, Spec: doTypeSpec(sub, fc)})
		}
	}
	return ts
}

func daTypeSpec(da *model.DataAttribute) *mms.TypeSpec {
	if len(da.Children) > 0 {
		ts := &mms.TypeSpec{Kind: mms.TypeStructure}
		for _, c := range da.Children {
			ts.Components = append(ts.Components, mms.Component{Name: c.Name, Spec: daTypeSpec(c)})
		}
		return ts
	}
	return valueTypeSpec(da.Value)
}

func valueTypeSpec(v *mms.Value) *mms.TypeSpec {
	if v == nil {
		return &mms.TypeSpec{Kind: mms.TypeBoolean}
	}
	switch v.Type() {
	case mms.TypeBitString:
		return &mms.TypeSpec{Kind: mms.TypeBitString, Size: -v.BitLen()}
	case mms.TypeInteger:
		return &mms.TypeSpec{Kind: mms.TypeInteger, Size: 32}
	case mms.TypeUnsigned:
		return &mms.TypeSpec{Kind: mms.TypeUnsigned, Size: 32}
	case mms.TypeVisibleString:
		return &mms.TypeSpec{Kind: mms.TypeVisibleString, Size: 129}
	case mms.TypeOctetString:
		return &mms.TypeSpec{Kind: mms.TypeOctetString, Size: 64}
	default:
		return &mms.TypeSpec{Kind: v.Type()}
	}
}
