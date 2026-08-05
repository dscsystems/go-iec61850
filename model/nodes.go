package model

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
)

// Model is the root of an IED data model: the server's view when built
// from SCL or by hand, and the client's view when retrieved online.
type Model struct {
	Name    string // IED name
	Devices []*LogicalDevice
}

// LogicalDevice is one MMS domain.
type LogicalDevice struct {
	Name  string // full domain name: IED name + LD inst
	Inst  string
	Nodes []*LogicalNode
}

// LogicalNode holds data objects and the control blocks configured on it.
type LogicalNode struct {
	Name    string // e.g. "LLN0", "Q0XCBR1"
	Class   string // LN class, e.g. "XCBR" (empty on retrieved models)
	Objects []*DataObject

	DataSets       []*DataSet
	ReportControls []*ReportControl
	GSEControls    []*GSEControl
	SVControls     []*SVControl
	LogControls    []*LogControl
	SettingControl *SettingControl
}

// DataObject is a DO or SDO.
type DataObject struct {
	Name       string
	CDC        string // common data class, e.g. "MV" (empty when unknown)
	Objects    []*DataObject
	Attributes []*DataAttribute
}

// DataAttribute is a DA (possibly structured). Leaf attributes carry a
// current value; structured attributes carry children.
type DataAttribute struct {
	Name     string
	FC       FC
	Kind     mms.Type // leaf basic type, or TypeStructure/TypeArray
	BType    string   // SCL bType (e.g. "Quality", "Timestamp", "INT32"), informational
	Count    int      // array element count when Kind == TypeArray
	Children []*DataAttribute
	Value    *mms.Value // leaf value; nil on structured attributes

	TrgOps TrgOps // dchg/qchg/dupd flags from SCL, drives reporting
}

// DataSet is a named set of functionally-constrained data references.
type DataSet struct {
	Name    string
	Entries []FCDA
}

// FCDA is one dataset member.
type FCDA struct {
	Ref ObjectReference // LD/LN.DO[.DA]
	FC  FC
}

// ReportControl is the SCL-side configuration of a report control block.
type ReportControl struct {
	Name       string
	RptID      string
	DataSet    string // dataset name within the same LN
	ConfRev    uint32
	Buffered   bool
	BufTime    uint32 // ms
	TrgOps     TrgOps
	OptFlds    OptFlds
	IntgPd     uint32 // ms
	RptEnabled int    // max enabled instances (indexed RCBs)
	// MaxQueueSize is how many reports a buffered control block retains
	// while no subscriber is enabled. Zero leaves it to the server's own
	// default. It has no meaning for an unbuffered control block.
	MaxQueueSize int
}

// GSEControl is the SCL-side configuration of a GOOSE control block.
type GSEControl struct {
	Name    string
	GoID    string
	DataSet string
	ConfRev uint32
	// Communication parameters resolved from the SCL Communication
	// section (zero when absent).
	DstMAC  [6]byte
	AppID   uint16
	VLANID  uint16
	VLANPri uint8
	MinTime uint32 // ms
	MaxTime uint32 // ms
}

// SVControl is the SCL-side configuration of a sampled-value control block.
type SVControl struct {
	Name      string
	SvID      string
	DataSet   string
	ConfRev   uint32
	SmpRate   uint32
	NoASDU    uint32
	Multicast bool
	DstMAC    [6]byte
	AppID     uint16
	VLANID    uint16
	VLANPri   uint8
}

// LogControl is the SCL-side configuration of a log control block.
type LogControl struct {
	Name    string
	DataSet string
	LogName string
	TrgOps  TrgOps
	IntgPd  uint32
	LogEna  bool
}

// SettingControl describes the setting groups of a logical device.
type SettingControl struct {
	NumOfSGs uint8
	ActSG    uint8
}

// Device returns the logical device with the given (domain) name.
func (m *Model) Device(name string) *LogicalDevice {
	for _, ld := range m.Devices {
		if ld.Name == name {
			return ld
		}
	}
	return nil
}

// Node returns the named logical node.
func (ld *LogicalDevice) Node(name string) *LogicalNode {
	for _, ln := range ld.Nodes {
		if ln.Name == name {
			return ln
		}
	}
	return nil
}

// Object returns the named top-level data object.
func (ln *LogicalNode) Object(name string) *DataObject {
	for _, do := range ln.Objects {
		if do.Name == name {
			return do
		}
	}
	return nil
}

// DataSet returns the named dataset.
func (ln *LogicalNode) DataSet(name string) *DataSet {
	for _, ds := range ln.DataSets {
		if ds.Name == name {
			return ds
		}
	}
	return nil
}

// Child returns the named sub-object or attribute path start.
func (do *DataObject) Child(name string) *DataObject {
	for _, s := range do.Objects {
		if s.Name == name {
			return s
		}
	}
	return nil
}

// Attribute returns the named direct attribute.
func (do *DataObject) Attribute(name string) *DataAttribute {
	for _, a := range do.Attributes {
		if a.Name == name {
			return a
		}
	}
	return nil
}

// Child returns the named child of a structured attribute.
func (da *DataAttribute) Child(name string) *DataAttribute {
	for _, c := range da.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Lookup resolves a reference to the node it designates. It returns one
// of *LogicalDevice, *LogicalNode, *DataObject or *DataAttribute, or nil.
// When fc is not ALL, attribute traversal is restricted to that FC.
func (m *Model) Lookup(ref ObjectReference, fc FC) any {
	ld := m.Device(ref.LD())
	if ld == nil {
		return nil
	}
	path := ref.Path()
	if len(path) == 0 {
		return ld
	}
	ln := ld.Node(path[0])
	if ln == nil {
		return nil
	}
	if len(path) == 1 {
		return ln
	}
	do := ln.Object(path[1])
	if do == nil {
		return nil
	}
	rest := path[2:]
	// Descend through sub-objects while they match.
	for len(rest) > 0 {
		if sub := do.Child(rest[0]); sub != nil {
			do, rest = sub, rest[1:]
			continue
		}
		break
	}
	if len(rest) == 0 {
		return do
	}
	// Then through attributes.
	var da *DataAttribute
	for _, a := range do.Attributes {
		if a.Name == rest[0] && (fc == ALL || fc == FCNone || a.FC == fc) {
			da = a
			break
		}
	}
	if da == nil {
		return nil
	}
	for _, name := range rest[1:] {
		da = da.Child(name)
		if da == nil {
			return nil
		}
	}
	return da
}

// Attribute resolves a reference to a data attribute under the given FC.
func (m *Model) Attribute(ref ObjectReference, fc FC) *DataAttribute {
	da, _ := m.Lookup(ref, fc).(*DataAttribute)
	return da
}

// FCs returns the sorted set of functional constraints present on the
// object (including nested attributes).
func (do *DataObject) FCs() []FC {
	seen := map[FC]bool{}
	var walk func(*DataObject)
	walk = func(o *DataObject) {
		for _, a := range o.Attributes {
			seen[a.FC] = true
		}
		for _, s := range o.Objects {
			walk(s)
		}
	}
	walk(do)
	fcs := make([]FC, 0, len(seen))
	for fc := range seen {
		fcs = append(fcs, fc)
	}
	sort.Slice(fcs, func(i, j int) bool { return fcs[i] < fcs[j] })
	return fcs
}

// String renders the model tree for diagnostics.
func (m *Model) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "IED %s\n", m.Name)
	for _, ld := range m.Devices {
		fmt.Fprintf(&sb, "  LD %s\n", ld.Name)
		for _, ln := range ld.Nodes {
			fmt.Fprintf(&sb, "    LN %s\n", ln.Name)
			for _, do := range ln.Objects {
				dumpDO(&sb, do, "      ")
			}
		}
	}
	return sb.String()
}

func dumpDO(sb *strings.Builder, do *DataObject, indent string) {
	fmt.Fprintf(sb, "%sDO %s", indent, do.Name)
	if do.CDC != "" {
		fmt.Fprintf(sb, " (%s)", do.CDC)
	}
	sb.WriteByte('\n')
	for _, a := range do.Attributes {
		dumpDA(sb, a, indent+"  ")
	}
	for _, s := range do.Objects {
		dumpDO(sb, s, indent+"  ")
	}
}

func dumpDA(sb *strings.Builder, da *DataAttribute, indent string) {
	fmt.Fprintf(sb, "%s%s [%s] %s", indent, da.Name, da.FC, da.Kind)
	if da.Value != nil {
		fmt.Fprintf(sb, " = %s", da.Value)
	}
	sb.WriteByte('\n')
	for _, c := range da.Children {
		dumpDA(sb, c, indent+"  ")
	}
}
