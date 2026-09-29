package model

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
)

// Model is the root of an IED data model: the server's view when built
// from SCL or by hand, and the client's view when retrieved online.
type Model struct {
	Name    string // IED name
	Devices []*LogicalDevice

	// Diagnostics holds non-fatal problems found while interpreting the
	// source of this model (SCL build, or online retrieval): unknown basic
	// types, unknown functional constraints, unresolvable dataset members.
	// The model is still usable. See Diagnostic.
	Diagnostics []Diagnostic

	// SettingGroups holds the per-group initial values of FC SG and SE
	// attributes, when the source configuration defines them (SCL Val
	// elements carrying an sGroup). The first entry is the active group.
	SettingGroups []SettingGroup
}

// SettingGroup is one named setting group of a logical device: the value
// each setting-group attribute takes in it.
type SettingGroup struct {
	// Number is the setting-group number; 0 is the active group.
	Number int
	// LD is the logical device (MMS domain) the group applies to.
	LD string
	// Values maps an attribute reference, e.g.
	// "SIMPLEIOLD0/GGIO1.AnIn1.setVal", to its value in this group.
	Values map[string]*mms.Value
}

// Diagnosticf records a non-fatal problem on the model.
func (m *Model) Diagnosticf(path, format string, args ...any) {
	m.Diagnostics = append(m.Diagnostics, Diagnostic{
		Path:    path,
		Message: fmt.Sprintf(format, args...),
	})
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
	// Logs names the logs this node holds (SCL Log elements), which a
	// server serves as MMS journals named "LN$Name". A log a LogControl
	// writes to is served whether or not it is declared here.
	Logs []string
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
	FCName   string   // mnemonic verbatim from the source; used when FC is FCUnknown
	Kind     mms.Type // leaf basic type, or TypeStructure/TypeArray
	BType    string   // SCL bType (e.g. "Quality", "Timestamp", "INT32"), informational
	Count    int      // array element count when Kind == TypeArray
	Children []*DataAttribute
	Value    *mms.Value // leaf value; nil on structured attributes

	TrgOps TrgOps // dchg/qchg/dupd flags from SCL, drives reporting
}

// Attr returns the named member of a structured attribute, or of an array
// attribute, by its element name.
func (da *DataAttribute) Attr(name string) *DataAttribute { return da.Child(name) }

// Elem returns the i-th element of an array attribute.
func (da *DataAttribute) Elem(i int) *mms.Value {
	v, _ := da.ElemOK(i)
	return v
}

// ElemOK returns the i-th element of an array attribute, false when the
// attribute is not an array or the index is out of range.
func (da *DataAttribute) ElemOK(i int) (*mms.Value, bool) {
	if da == nil || da.Kind != mms.TypeArray || da.Value == nil {
		return nil, false
	}
	if i < 0 || i >= da.Value.Len() {
		return nil, false
	}
	return da.Value.Index(i), true
}

// DataSet is a named set of functionally-constrained data references.
type DataSet struct {
	Name    string
	Entries []FCDA
}

// FCDA is one dataset member.
type FCDA struct {
	Ref    ObjectReference // LD/LN.DO[.DA]
	FC     FC
	FCName string // mnemonic verbatim from the source; used when FC is FCUnknown
}

// FCText renders the functional constraint of the member.
func (f FCDA) FCText() string { return FCText(f.FC, f.FCName) }

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
	// NotIndexed is SCL indexed="false": the block has exactly one
	// instance, named Name with no "01".."99" suffix. The zero value is
	// the schema default, indexed.
	NotIndexed bool
	// MaxQueueSize is how many reports a buffered control block retains
	// while no subscriber is enabled. Zero leaves it to the server's own
	// default. It has no meaning for an unbuffered control block.
	MaxQueueSize int
	// Reservations are the clients the configuration reserves instances
	// for (SCL RptEnabled/ClientLN), in instance order: Reservations[i]
	// holds instance i+1. Only that client may use the instance, and a
	// BRCB reports ResvTms -1 for it (IEC 61850-7-2). A nil entry leaves
	// its instance free.
	Reservations []*ClientReservation
}

// ClientReservation identifies the client a report control block instance
// is reserved for. The server knows a client by its transport address
// before anything else, so the IP address is what the reservation is
// checked against; IEDName is informational.
type ClientReservation struct {
	IEDName string
	IP      net.IP
}

// GSType is the variant of a GOOSE control block: plain GOOSE or the
// legacy GSSE.
type GSType uint8

const (
	GOOSE GSType = iota
	GSSE
)

func (t GSType) String() string {
	if t == GSSE {
		return "GSSE"
	}
	return "GOOSE"
}

// GSEControl is the SCL-side configuration of a GOOSE control block.
type GSEControl struct {
	Name    string
	GoID    string
	DataSet string
	ConfRev uint32
	Type    GSType
	// Protocol names the transmission profile, e.g. "R-GOOSE". The
	// routable profiles of IEC 61850-90-5 are reported here but are not
	// implemented by this library.
	Protocol string
	// Communication parameters resolved from the SCL Communication
	// section (zero when absent).
	DstMAC  [6]byte
	AppID   uint16
	VLANID  uint16
	VLANPri uint8
	MinTime uint32 // ms
	MaxTime uint32 // ms
	// FixedOffs is GSEControl@fixedOffs: the block asks for the
	// fixed-offset encoding of IEC 61850-8-1, in which every dataset member
	// has a fixed position and length in the frame. It is served as
	// GoCB.FixedOffs. This library encodes GOOSE only with variable
	// lengths, so the loader reports a block that sets it.
	FixedOffs bool
}

// SmpMod is the sample mode of a sampled-value control block: the rate is
// samples per measurement period, per second, or seconds per sample
// (IEC 61850-9-2).
type SmpMod uint8

const (
	SmpPerPeriod SmpMod = iota
	SmpPerSec
	SecPerSmp
)

func (m SmpMod) String() string {
	switch m {
	case SmpPerSec:
		return "SmpPerSec"
	case SecPerSmp:
		return "SecPerSmp"
	}
	return "SmpPerPeriod"
}

// SVOpts is the set of optional fields a sampled-value control block
// includes in its ASDU (IEC 61850-6 SmvOpts). A field is present only when
// its option is set.
type SVOpts struct {
	RefreshTime        bool
	SampleSynchronized bool
	SampleRate         bool
	DataSet            bool
	Security           bool
	Timestamp          bool
	SynchSourceID      bool
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
	SmpMod    SmpMod
	Opts      SVOpts
	// Protocol names the transmission profile, e.g. "R-SV".
	Protocol string
	DstMAC   [6]byte
	AppID    uint16
	VLANID   uint16
	VLANPri  uint8
}

// LogControl is the SCL-side configuration of a log control block.
type LogControl struct {
	Name    string
	DataSet string
	LogName string
	TrgOps  TrgOps
	IntgPd  uint32
	LogEna  bool
	// BufTime is the buffer period, and ReasonCode whether the log is
	// reported with a reason for each entry.
	BufTime    uint32
	ReasonCode bool
	// LogLDInst and LogLN locate the logical node holding the log
	// (LogControl@ldInst, and prefix+lnClass+lnInst). Empty means the
	// defaults of IEC 61850-6: the block's own device, and LLN0.
	LogLDInst string
	LogLN     string
}

// SettingControl describes the setting groups of a logical device.
type SettingControl struct {
	NumOfSGs int
	ActSG    int
	// ResvTms is how long a setting-group reservation lasts, in
	// milliseconds (IEC 61850-8-1, Ed 2.1). Zero leaves it to the server.
	ResvTms int
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

// FCText returns the mnemonic to use in an item ID for the constraint the
// object exposes. An FCUnknown attribute carries the verbatim mnemonic, so
// an object under a constraint this library does not know still composes the
// name the peer uses.
func (do *DataObject) FCText(fc FC) string {
	var walk func(*DataObject) string
	walk = func(o *DataObject) string {
		for _, a := range o.Attributes {
			if a.FC == fc {
				return FCText(a.FC, a.FCName)
			}
		}
		for _, s := range o.Objects {
			if t := walk(s); t != "" {
				return t
			}
		}
		return ""
	}
	if t := walk(do); t != "" {
		return t
	}
	return fc.String()
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
