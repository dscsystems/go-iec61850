package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// ACSIClass names a class of ACSI objects that can live inside a logical
// node. It selects what LogicalNodeDirectory browses for.
type ACSIClass uint8

const (
	// ACSIDataObject is a data object (IEC 61850-7-2 DATA), the default
	// content of a logical node.
	ACSIDataObject ACSIClass = iota
	// ACSIDataSet is a data set (DATA-SET).
	ACSIDataSet
	// ACSIBRCB is a buffered report control block.
	ACSIBRCB
	// ACSIURCB is an unbuffered report control block.
	ACSIURCB
	// ACSILCB is a log control block.
	ACSILCB
	// ACSILog is a log.
	ACSILog
	// ACSISGCB is the setting group control block.
	ACSISGCB
	// ACSIGoCB is a GOOSE control block.
	ACSIGoCB
	// ACSIGsCB is a GSSE control block (legacy).
	ACSIGsCB
	// ACSIMSVCB is a multicast sampled value control block.
	ACSIMSVCB
	// ACSIUSVCB is a unicast sampled value control block.
	ACSIUSVCB
)

var acsiClassNames = [...]string{
	ACSIDataObject: "DATA", ACSIDataSet: "DATA-SET", ACSIBRCB: "BRCB",
	ACSIURCB: "URCB", ACSILCB: "LCB", ACSILog: "LOG", ACSISGCB: "SGCB",
	ACSIGoCB: "GoCB", ACSIGsCB: "GsCB", ACSIMSVCB: "MSVCB", ACSIUSVCB: "USVCB",
}

func (a ACSIClass) String() string {
	if int(a) < len(acsiClassNames) {
		return acsiClassNames[a]
	}
	return fmt.Sprintf("ACSIClass(%d)", uint8(a))
}

// acsiClassFC is the functional constraint that carries each control-block
// class in its MMS name (IEC 61850-8-1). The classes that are not named
// variables at all — data sets and logs — are absent, as is ACSIDataObject,
// which is defined by exclusion.
var acsiClassFC = map[ACSIClass]model.FC{
	ACSIBRCB:  model.BR,
	ACSIURCB:  model.RP,
	ACSILCB:   model.LG,
	ACSISGCB:  model.SP, // as "LN$SP$SGCB"; other SP names are set points
	ACSIGoCB:  model.GO,
	ACSIGsCB:  model.GS,
	ACSIMSVCB: model.MS,
	ACSIUSVCB: model.US,
}

// LogicalNodeDirectory returns the names of the objects of one ACSI class
// inside a logical node, addressed as "LD/LN". It is the ACSI
// GetLogicalNodeDirectory, derived from the MMS name lists: the names an
// IED reports are flat MMS item IDs, and the class of each is carried by
// its functional constraint, so the browse is a filter over GetNameList
// rather than a service of its own.
//
// The names are the bare object names ("Pos", "urcb01", "Events"); build a
// reference with ln.Child(name). Order follows the server's, deduplicated;
// an empty result is not an error, a logical node need not hold any object
// of a given class.
//
// The server and logical device levels of the browse are LogicalDevices
// and LogicalNodes.
func (c *Client) LogicalNodeDirectory(ctx context.Context, ln model.ObjectReference, class ACSIClass) ([]string, error) {
	domain, lnName := ln.LD(), ln.LN()
	if domain == "" || lnName == "" {
		return nil, fmt.Errorf("client: logical node reference %q must be LD/LN", ln)
	}

	// Data sets are MMS named variable lists and logs are MMS journals;
	// everything else is a named variable distinguished by its FC.
	switch class {
	case ACSIDataSet:
		names, err := c.mc.GetNameList(ctx, mms.ClassNamedVariableList, domain)
		if err != nil {
			return nil, err
		}
		return namesUnder(names, lnName), nil
	case ACSILog:
		names, err := c.mc.GetNameList(ctx, mms.ClassJournal, domain)
		if err != nil {
			return nil, err
		}
		return namesUnder(names, lnName), nil
	}

	names, err := c.mc.GetNameList(ctx, mms.ClassNamedVariable, domain)
	if err != nil {
		return nil, err
	}
	return objectsOfClass(names, lnName, class), nil
}

// objectsOfClass picks the objects of one class out of a domain's variable
// name list.
func objectsOfClass(names []string, ln string, class ACSIClass) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		parts := strings.Split(n, "$")
		// "LN" and "LN$FC" are the bare node and FC entries; objects start
		// at "LN$FC$Name", and members ("LN$RP$urcb01$RptID") name the same
		// object again.
		if len(parts) < 3 || parts[0] != ln {
			continue
		}
		fc, err := model.ParseFC(parts[1])
		if err != nil {
			continue
		}
		name := parts[2]
		if name == "" || !classHolds(class, fc, name) || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// classHolds reports whether an object named under fc belongs to class.
func classHolds(class ACSIClass, fc model.FC, name string) bool {
	switch class {
	case ACSIDataObject:
		// Everything that is not a control block. The SGCB shares FC SP
		// with ordinary set points and is told apart by its name.
		if _, isCB := controlBlockFCs[fc]; isCB {
			return false
		}
		return !(fc == model.SP && name == sgcbName)
	case ACSISGCB:
		return fc == model.SP && name == sgcbName
	}
	want, ok := acsiClassFC[class]
	return ok && fc == want
}

// sgcbName is the fixed MMS name of the setting group control block.
const sgcbName = "SGCB"

// controlBlockFCs are the functional constraints that carry control blocks
// rather than data.
var controlBlockFCs = map[model.FC]bool{
	model.BR: true, model.RP: true, model.LG: true, model.GO: true,
	model.GS: true, model.MS: true, model.US: true,
}

// namesUnder returns the entries of a "LN$Name" list that belong to ln,
// stripped of the logical node prefix.
func namesUnder(names []string, ln string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		node, name, ok := strings.Cut(n, "$")
		if !ok || node != ln || name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// DirectoryEntry is one object found by Browse.
type DirectoryEntry struct {
	// Ref addresses the object, ready for GetRCB, ReadDataSet,
	// SettingGroups, QueryLogByTime or Read: it is the MMS item ID with
	// "$" written as ".", so a control block keeps its functional
	// constraint ("LD/LLN0.RP.urcb01") and a data object does not
	// ("LD/GGIO1.SPCSO1"), the FC being a separate argument there.
	Ref model.ObjectReference
	// Class is the ACSI class the object was matched as.
	Class ACSIClass
}

// allACSIClasses is what Browse looks for when the caller names no class.
var allACSIClasses = []ACSIClass{
	ACSIDataObject, ACSIDataSet, ACSIBRCB, ACSIURCB, ACSILCB, ACSILog,
	ACSISGCB, ACSIGoCB, ACSIGsCB, ACSIMSVCB, ACSIUSVCB,
}

// Browse returns every object of the given ACSI classes in a logical
// device, as references. It is the logical-device-wide form of
// LogicalNodeDirectory: one pass over the device's name list covers all
// the logical nodes and all the classes asked for, so browsing several
// classes costs no more round trips than browsing one.
//
// With no class named, it looks for every class. Entries come grouped by
// the name list they were found in (variables, then data sets, then logs),
// in the server's order. An error from a name list is returned, including
// the journal list that backs ACSILog, which servers without logging
// support may refuse — ask for the classes you need.
func (c *Client) Browse(ctx context.Context, ld string, classes ...ACSIClass) ([]DirectoryEntry, error) {
	if ld == "" {
		return nil, fmt.Errorf("client: browse needs a logical device name")
	}
	if len(classes) == 0 {
		classes = allACSIClasses
	}
	var wantVars, wantSets, wantLogs bool
	for _, class := range classes {
		switch class {
		case ACSIDataSet:
			wantSets = true
		case ACSILog:
			wantLogs = true
		default:
			wantVars = true
		}
	}

	var out []DirectoryEntry
	seen := map[model.ObjectReference]bool{}
	add := func(ref model.ObjectReference, class ACSIClass) {
		if seen[ref] {
			return
		}
		seen[ref] = true
		out = append(out, DirectoryEntry{Ref: ref, Class: class})
	}

	if wantVars {
		names, err := c.mc.GetNameList(ctx, mms.ClassNamedVariable, ld)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			parts := strings.Split(n, "$")
			if len(parts) < 3 || parts[0] == "" || parts[2] == "" {
				continue
			}
			fc, err := model.ParseFC(parts[1])
			if err != nil {
				continue
			}
			ln, name := parts[0], parts[2]
			for _, class := range classes {
				// The classes are disjoint, so the first match is the only
				// one.
				if class == ACSIDataSet || class == ACSILog || !classHolds(class, fc, name) {
					continue
				}
				if class == ACSIDataObject {
					add(model.ObjectReference(ld+"/"+ln+"."+name), class)
				} else {
					add(model.ObjectReference(ld+"/"+ln+"."+fc.String()+"."+name), class)
				}
				break
			}
		}
	}
	if wantSets {
		names, err := c.mc.GetNameList(ctx, mms.ClassNamedVariableList, ld)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if ln, name, ok := strings.Cut(n, "$"); ok && ln != "" && name != "" {
				add(model.ObjectReference(ld+"/"+ln+"."+name), ACSIDataSet)
			}
		}
	}
	if wantLogs {
		names, err := c.mc.GetNameList(ctx, mms.ClassJournal, ld)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			if ln, name, ok := strings.Cut(n, "$"); ok && ln != "" && name != "" {
				add(model.ObjectReference(ld+"/"+ln+"."+name), ACSILog)
			}
		}
	}
	return out, nil
}

// DataDirectory returns the names of the immediate children of a data
// object or data attribute, addressed as "LD/LN.DO[.DA...]". It is the
// ACSI GetDataDirectory, derived from the same name list: an IED lists
// every leaf under its functionally-constrained objects, so one level of
// the tree is the set of distinct next components.
//
// fc restricts the browse to one functional constraint; model.ALL (or
// model.FCNone) unions the children seen under every FC, which is how a
// data object exposes both its status attributes and its control ones.
func (c *Client) DataDirectory(ctx context.Context, ref model.ObjectReference, fc model.FC) ([]string, error) {
	domain, path := ref.LD(), ref.Path()
	if domain == "" || len(path) < 2 {
		return nil, fmt.Errorf("client: data reference %q must be LD/LN.DO[.DA...]", ref)
	}
	names, err := c.mc.GetNameList(ctx, mms.ClassNamedVariable, domain)
	if err != nil {
		return nil, err
	}
	lnName, want := path[0], path[1:]

	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		parts := strings.Split(n, "$")
		if len(parts) < 3 || parts[0] != lnName {
			continue
		}
		efc, err := model.ParseFC(parts[1])
		if err != nil {
			continue
		}
		if fc != model.ALL && fc != model.FCNone && efc != fc {
			continue
		}
		// The entry has to be exactly one component deeper than the
		// reference, below the same path.
		rest := parts[2:]
		if len(rest) != len(want)+1 || !hasPrefixPath(rest, want) {
			continue
		}
		child := rest[len(rest)-1]
		if seen[child] {
			continue
		}
		seen[child] = true
		out = append(out, child)
	}
	return out, nil
}

func hasPrefixPath(path, prefix []string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i, p := range prefix {
		if path[i] != p {
			return false
		}
	}
	return true
}
