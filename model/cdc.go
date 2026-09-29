package model

import (
	"fmt"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
)

// CDC is a common data class name (IEC 61850-7-3). It selects the
// attribute table a data object is built from.
type CDC string

// The common data classes this package can build.
const (
	// Status information.
	CDCSPS CDC = "SPS" // single point status
	CDCDPS CDC = "DPS" // double point status
	CDCINS CDC = "INS" // integer status
	CDCENS CDC = "ENS" // enumerated status
	CDCVSS CDC = "VSS" // visible string status
	CDCACT CDC = "ACT" // protection activation information
	CDCACD CDC = "ACD" // directional protection activation information
	CDCBCR CDC = "BCR" // binary counter reading

	// Measurand information.
	CDCMV  CDC = "MV"  // measured value
	CDCCMV CDC = "CMV" // complex measured value
	CDCSAV CDC = "SAV" // sampled value
	CDCWYE CDC = "WYE" // phase-to-ground related measurands
	CDCDEL CDC = "DEL" // phase-to-phase related measurands

	// Controllable information.
	CDCSPC CDC = "SPC" // controllable single point
	CDCDPC CDC = "DPC" // controllable double point
	CDCINC CDC = "INC" // controllable integer status
	CDCENC CDC = "ENC" // controllable enumerated status
	CDCBSC CDC = "BSC" // binary controlled step position
	CDCAPC CDC = "APC" // controllable analogue process value

	// Settings.
	CDCSPG CDC = "SPG" // single point setting
	CDCING CDC = "ING" // integer status setting
	CDCENG CDC = "ENG" // enumerated status setting
	CDCASG CDC = "ASG" // analogue setting

	// Description.
	CDCLPL CDC = "LPL" // logical node name plate
	CDCDPL CDC = "DPL" // device name plate

	// Classes added by Edition 2 and 2.1.
	CDCSEC   CDC = "SEC"   // security violation counting
	CDCHST   CDC = "HST"   // histogram
	CDCORS   CDC = "ORS"   // object reference status
	CDCTCS   CDC = "TCS"   // time status
	CDCSEQ   CDC = "SEQ"   // sequence
	CDCHMV   CDC = "HMV"   // harmonic value
	CDCHWYE  CDC = "HWYE"  // harmonic value for WYE
	CDCHDEL  CDC = "HDEL"  // harmonic value for DEL
	CDCISC   CDC = "ISC"   // integer controlled step position
	CDCBAC   CDC = "BAC"   // binary controlled analogue process value
	CDCORG   CDC = "ORG"   // object reference setting
	CDCTSG   CDC = "TSG"   // time setting
	CDCCUG   CDC = "CUG"   // currency setting
	CDCVSG   CDC = "VSG"   // visible string setting
	CDCCURVE CDC = "CURVE" // setting curve
	CDCCSG   CDC = "CSG"   // curve shape setting
	CDCCSD   CDC = "CSD"   // curve shape description
	CDCVSD   CDC = "VSD"   // visible string description

	// Service tracking (IEC 61850-7-2 Edition 2), served under FC SR.
	CDCCST CDC = "CST" // common service tracking
	CDCBTS CDC = "BTS" // buffered report tracking
	CDCUTS CDC = "UTS" // unbuffered report tracking
	CDCLTS CDC = "LTS" // log control tracking
	CDCGTS CDC = "GTS" // GOOSE control tracking
	CDCMTS CDC = "MTS" // multicast sampled value control tracking
	CDCNTS CDC = "NTS" // unicast sampled value control tracking
	CDCSTS CDC = "STS" // setting group control tracking
	CDCCTS CDC = "CTS" // control service tracking
)

// CDCAttribute describes one attribute of a common data class: what it is
// called, the functional constraint it is served under, and its type.
// Structured attributes (AnalogueValue, Vector, the control structures)
// carry their members in Children.
type CDCAttribute struct {
	Name     string
	FC       FC
	Kind     mms.Type
	Size     int  // bit-string width; 0 for other types
	Optional bool // omitted unless asked for with WithOptional
	// Array marks an attribute that is an array of Kind (or, for a
	// structure, of Children), as long as the class's maxPts: see
	// WithMaxPts.
	Array    bool
	Children []CDCAttribute

	// trg overrides the trigger options cdcTrgOps derives from the name,
	// for the attributes whose 7-3 options the rule does not produce.
	trg    TrgOps
	trgSet bool
	// oneOf names a group of optional attributes of which at least one is
	// present (7-3 AtLeastOne): the first is built unless another member
	// is asked for.
	oneOf string
	// allOrNone names a group of optional attributes that are present
	// together (7-3 AllOrNonePerGroup): asking for one builds them all.
	allOrNone string
	// ctlValSlot marks the ctlVal of a control tracking class, whose type
	// is that of the control it tracks: see WithTrackedControl.
	ctlValSlot bool
}

// CDCSubObject describes a data object nested inside another, as the phase
// measurands of a WYE are.
type CDCSubObject struct {
	Name     string
	CDC      CDC
	Optional bool
	// Array marks a sub-object repeated maxPts times, as the harmonics of
	// HMV are. The instances are named Name(1)..Name(maxPts), as the SCL
	// loader names the instances of an SDO with a count.
	Array bool
}

// CDCAttributes returns the attribute table of a common data class, or nil
// if the class is not known. The result is a copy; editing it changes
// nothing.
func CDCAttributes(cdc CDC) []CDCAttribute {
	spec, ok := cdcTable[cdc]
	if !ok {
		return nil
	}
	return cloneAttrs(spec.attrs)
}

// CDCSubObjects returns the nested data objects of a common data class,
// nil for the classes that have none.
func CDCSubObjects(cdc CDC) []CDCSubObject {
	spec, ok := cdcTable[cdc]
	if !ok {
		return nil
	}
	return append([]CDCSubObject(nil), spec.subObjects...)
}

// CDCControlValue returns the type of the class's ctlVal, and false when
// the class is not controllable.
func CDCControlValue(cdc CDC) (CDCAttribute, bool) {
	spec, ok := cdcTable[cdc]
	if !ok || spec.ctlVal == nil {
		return CDCAttribute{}, false
	}
	return cloneAttrs([]CDCAttribute{*spec.ctlVal})[0], true
}

// KnownCDCs returns the classes this package can build, unordered.
func KnownCDCs() []CDC {
	out := make([]CDC, 0, len(cdcTable))
	for cdc := range cdcTable {
		out = append(out, cdc)
	}
	return out
}

// CDCOption adjusts how a data object is built.
type CDCOption func(*cdcBuild)

type cdcBuild struct {
	ctlModel     CtlModel
	hasCtlModel  bool
	withCancel   bool
	integerAnalg bool
	optional     map[string]bool
	settingFC    FC
	maxPts       int
	tracked      CDC
}

// WithControlModel builds the control attributes for a controllable class:
// Oper and Cancel for the direct models, plus SBO or SBOw for the
// select-before-operate ones, and ctlModel carrying m. Without it a
// controllable class is built status-only, with no control attributes.
func WithControlModel(m CtlModel) CDCOption {
	return func(b *cdcBuild) { b.ctlModel = m; b.hasCtlModel = true }
}

// WithoutCancel leaves the (optional) Cancel structure out of a
// controllable object.
func WithoutCancel() CDCOption { return func(b *cdcBuild) { b.withCancel = false } }

// WithIntegerAnalogue represents every AnalogueValue as an integer "i"
// instead of the default float "f".
func WithIntegerAnalogue() CDCOption { return func(b *cdcBuild) { b.integerAnalg = true } }

// WithOptional includes optional attributes of the class by name, for
// example "instMag", "units" or "subVal". Names the class does not define
// are ignored.
func WithOptional(names ...string) CDCOption {
	return func(b *cdcBuild) {
		for _, n := range names {
			b.optional[n] = true
		}
	}
}

// WithSettingFC serves a setting class's values under fc instead of SP —
// pass SG for values that belong to a setting group.
func WithSettingFC(fc FC) CDCOption { return func(b *cdcBuild) { b.settingFC = fc } }

// WithMaxPts sets the length of the array attributes and sub-objects of
// the classes that have them (HST, CSG, CSD, HMV, HWYE, HDEL), and the
// value of their maxPts attribute. Without it the arrays have one element,
// which is valid but rarely what a device has.
func WithMaxPts(n int) CDCOption {
	return func(b *cdcBuild) {
		if n > 0 {
			b.maxPts = n
		}
	}
}

// WithTrackedControl gives the ctlVal of a control tracking object (CTS)
// the type of the controllable class it tracks: CDCSPC or CDCDPC for a
// boolean, CDCINC for an integer, CDCAPC for an analogue value, and so on.
// Without it ctlVal is a boolean, as for the single point control tracked
// by LTRK.SpcTrk.
func WithTrackedControl(cdc CDC) CDCOption { return func(b *cdcBuild) { b.tracked = cdc } }

// NewDataObjectOr is NewDataObject that says when the class is one it does
// not know: it returns a diagnostic and the named data object with no
// attributes. NewDataObjectOrNil returns nil in that case instead.
// This matters for a model built from a file of a newer edition than this
// library, where the class is real and simply has no template here yet —
// panicking would make such a file unloadable, which is a worse outcome
// than serving an object with no attributes.
func NewDataObjectOr(name string, cdc CDC, opts ...CDCOption) (*DataObject, Diagnostic) {
	if !KnownCDC(string(cdc)) {
		return &DataObject{Name: name, CDC: string(cdc)}, Addf(name,
			"common data class %q has no attribute template in this library; "+
				"the object is present but has no attributes", cdc)
	}
	return NewDataObject(name, cdc, opts...), Diagnostic{}
}

// NewDataObjectOrNil is NewDataObject without the fallback object: an
// unknown class yields nil and a diagnostic.
func NewDataObjectOrNil(name string, cdc CDC, opts ...CDCOption) (*DataObject, Diagnostic) {
	if !KnownCDC(string(cdc)) {
		return nil, Addf(name,
			"common data class %q has no attribute template in this library", cdc)
	}
	return NewDataObject(name, cdc, opts...), Diagnostic{}
}

// KnownCDC reports whether this library has an attribute template for the
// named common data class. The comparison is case-insensitive, as the SCL
// cdc attribute is.
func KnownCDC(name string) bool {
	_, ok := cdcTable[CDC(strings.ToUpper(strings.TrimSpace(name)))]
	return ok
}

// CDCName is a hook for a build that adds classes to cdcTable. It reports
// whether a class has a template; the SCL loader uses it to warn about a
// class it cannot expand, and defaults to the table's contents.
var CDCName = func(name string) bool { return KnownCDC(name) }

// NewDataObject builds a data object of the given common data class: its
// mandatory attributes, any optional ones asked for, and any nested data
// objects the class defines, each with a zero value of its type.
//
//	spc := model.NewDataObject("SPCSO1", model.CDCSPC,
//		model.WithControlModel(model.CtlSBOEnhanced))
//	mv := model.NewDataObject("AnIn1", model.CDCMV,
//		model.WithOptional("units", "db"))
//
// A class it does not know yields a data object with the name and class
// and no attributes, as NewDataObjectOr does, without the diagnostic. It
// used to panic, which made a class name that arrives at run time (from a
// file of a newer edition, say) a crash rather than an empty object; use
// NewDataObjectOr to be told.
func NewDataObject(name string, cdc CDC, opts ...CDCOption) *DataObject {
	spec, ok := cdcTable[CDC(strings.ToUpper(strings.TrimSpace(string(cdc))))]
	if !ok {
		return &DataObject{Name: name, CDC: string(cdc)}
	}
	b := &cdcBuild{withCancel: true, optional: map[string]bool{}, settingFC: SP, maxPts: 1}
	for _, opt := range opts {
		opt(b)
	}
	b.resolveGroups(spec.attrs)

	do := &DataObject{Name: name, CDC: string(cdc)}
	for _, a := range spec.attrs {
		if a.ctlValSlot {
			a = b.trackedCtlVal(a)
		}
		if da := b.attribute(a); da != nil {
			inheritTrgOps(da)
			if da.Name == "maxPts" && da.Value != nil {
				da.Value = mms.NewUint32(uint32(b.maxPts))
			}
			do.Attributes = append(do.Attributes, da)
		}
	}
	if spec.ctlVal != nil && b.hasCtlModel {
		do.Attributes = append(do.Attributes, b.controlAttributes(*spec.ctlVal)...)
	}
	for _, sub := range spec.subObjects {
		if sub.Optional && !b.optional[sub.Name] {
			continue
		}
		if !sub.Array {
			do.Objects = append(do.Objects, NewDataObject(sub.Name, sub.CDC, opts...))
			continue
		}
		for ix := 1; ix <= b.maxPts; ix++ {
			do.Objects = append(do.Objects,
				NewDataObject(fmt.Sprintf("%s(%d)", sub.Name, ix), sub.CDC, opts...))
		}
	}
	return do
}

// resolveGroups applies the presence groups of a class to the attributes
// asked for: the first member of an AtLeastOne group is built when no
// member is asked for, and asking for one member of an AllOrNone group
// asks for all of them.
func (b *cdcBuild) resolveGroups(attrs []CDCAttribute) {
	oneOfAsked := map[string]bool{}
	allAsked := map[string]bool{}
	for _, a := range attrs {
		if a.oneOf != "" && b.optional[a.Name] {
			oneOfAsked[a.oneOf] = true
		}
		if a.allOrNone != "" && b.optional[a.Name] {
			allAsked[a.allOrNone] = true
		}
	}
	// The optional set is shared with nested objects through opts; copy
	// it before adding to it.
	opt := make(map[string]bool, len(b.optional))
	for k, v := range b.optional {
		opt[k] = v
	}
	for _, a := range attrs {
		if a.oneOf != "" && !oneOfAsked[a.oneOf] {
			opt[a.Name] = true
			oneOfAsked[a.oneOf] = true
		}
		if a.allOrNone != "" && allAsked[a.allOrNone] {
			opt[a.Name] = true
		}
	}
	b.optional = opt
}

// trackedCtlVal gives the ctlVal slot of a tracking class the type of the
// tracked control's ctlVal, or a boolean.
func (b *cdcBuild) trackedCtlVal(slot CDCAttribute) CDCAttribute {
	v := daBool(slot.Name, slot.FC)
	if spec, ok := cdcTable[b.tracked]; ok && spec.ctlVal != nil {
		v = *spec.ctlVal
		v.Children = cloneAttrs(v.Children)
		v.Name = slot.Name
		v.FC = slot.FC
		for i := range v.Children {
			v.Children[i].FC = slot.FC
		}
	}
	v.trg, v.trgSet = slot.trg, slot.trgSet
	return v
}

// attribute materialises one table entry, or nil when it is an optional
// one that was not asked for.
func (b *cdcBuild) attribute(a CDCAttribute) *DataAttribute {
	if a.Optional && !b.optional[a.Name] {
		return nil
	}
	fc := a.FC
	if fc == SP {
		fc = b.settingFC
	}
	trg := cdcTrgOps(a.Name, fc)
	if a.trgSet && fc == a.FC {
		trg = a.trg
	}
	da := &DataAttribute{Name: a.Name, FC: fc, Kind: a.Kind, TrgOps: trg}
	if a.Kind == mms.TypeStructure {
		for _, c := range a.Children {
			// AnalogueValue carries i or f; exactly one is built.
			if (c.Name == "i" || c.Name == "f") && isAnalogue(a) {
				if (c.Name == "i") != b.integerAnalg {
					continue
				}
				child := c
				child.Optional = false
				da.Children = append(da.Children, b.attributeFC(child, fc))
				continue
			}
			if cd := b.attributeFC(c, fc); cd != nil {
				da.Children = append(da.Children, cd)
			}
		}
		if a.Array {
			// An array of a constructed type: the members are the element
			// template, as the SCL loader builds one.
			da.Kind = mms.TypeArray
			da.Count = b.maxPts
		}
		return da
	}
	if a.Array {
		elems := make([]*mms.Value, b.maxPts)
		for i := range elems {
			elems[i] = zeroValue(a.Kind, a.Size)
		}
		da.Kind = mms.TypeArray
		da.Count = b.maxPts
		da.Value = mms.NewArray(elems...)
		return da
	}
	da.Value = zeroValue(a.Kind, a.Size)
	return da
}

// attributeFC materialises a member of a structure, which inherits its
// parent's functional constraint and trigger options.
func (b *cdcBuild) attributeFC(a CDCAttribute, fc FC) *DataAttribute {
	if a.Optional && !b.optional[a.Name] {
		return nil
	}
	child := a
	child.FC = fc
	da := b.attribute(child)
	if da != nil {
		da.FC = fc
		da.TrgOps = 0 // inherited from the enclosing attribute below
	}
	return da
}

// inheritTrgOps gives every component of a structured attribute the
// attribute's own trigger options, which cover all of it.
func inheritTrgOps(da *DataAttribute) {
	for _, c := range da.Children {
		c.TrgOps = da.TrgOps
		inheritTrgOps(c)
	}
}

// cdcTrgOps is the trigger option of a common data class attribute,
// following the tables of IEC 61850-7-3: q is qchg; the timestamp, the
// deadbanded-away instantaneous values and the substitution group trigger
// nothing; the analogue values also trigger on update, and a frozen
// counter value only on update; every other status, measurand, setting
// and configuration attribute is dchg. Descriptions, blocking, control
// structures, service tracking and extensions trigger nothing, and neither
// does a value in a setting group: the SG and SE variants of the 7-3
// setting classes have no trigger options, only the SP form does. A table
// entry whose 7-3 options differ from these says so with withTrg.
func cdcTrgOps(name string, fc FC) TrgOps {
	switch fc {
	case ST, MX, SP, SV, CF:
	default:
		return 0
	}
	switch name {
	case "q":
		return TrgQualityChange
	case "t", "instMag", "instCVal", "frTm", "subVal", "subMag", "subCVal", "subQ", "subID", "subEna":
		return 0
	case "mag", "cVal":
		return TrgDataChange | TrgDataUpdate
	case "frVal":
		return TrgDataUpdate
	}
	return TrgDataChange
}

// isAnalogue reports whether a structure is an AnalogueValue, whose i and
// f members are alternatives rather than both present.
func isAnalogue(a CDCAttribute) bool {
	if a.Kind != mms.TypeStructure || len(a.Children) != 2 {
		return false
	}
	return a.Children[0].Name == "i" && a.Children[1].Name == "f"
}

// controlAttributes builds ctlModel and the control structures the model
// calls for: Oper always, SBO or SBOw for the select-before-operate
// models, and Cancel unless it was turned off.
func (b *cdcBuild) controlAttributes(ctlVal CDCAttribute) []*DataAttribute {
	out := []*DataAttribute{{
		Name: "ctlModel", FC: CF, Kind: mms.TypeInteger,
		Value: mms.NewInt32(int32(b.ctlModel)),
	}}
	if b.ctlModel == CtlStatusOnly {
		return out
	}
	if b.ctlModel == CtlSBONormal {
		out = append(out, &DataAttribute{
			Name: "SBO", FC: CO, Kind: mms.TypeVisibleString, Value: mms.NewVisibleString(""),
		})
	}
	if b.ctlModel == CtlSBOEnhanced {
		out = append(out, b.attribute(ctlStructure("SBOw", ctlVal, true)))
	}
	out = append(out, b.attribute(ctlStructure("Oper", ctlVal, true)))
	if b.withCancel {
		// Cancel repeats the operate parameters without the checks.
		out = append(out, b.attribute(ctlStructure("Cancel", ctlVal, false)))
	}
	return out
}

// ctlStructure is the operate structure of IEC 61850-7-3:
// { ctlVal, origin{orCat, orIdent}, ctlNum, T, Test [, Check] }.
func ctlStructure(name string, ctlVal CDCAttribute, withCheck bool) CDCAttribute {
	ctlVal.Name = "ctlVal"
	ctlVal.FC = CO
	ctlVal.Optional = false
	members := []CDCAttribute{
		ctlVal,
		daStruct("origin", CO,
			daInt("orCat", CO),
			daOctet("orIdent", CO),
		),
		{Name: "ctlNum", FC: CO, Kind: mms.TypeUnsigned},
		{Name: "T", FC: CO, Kind: mms.TypeUTCTime},
		daBool("Test", CO),
	}
	if withCheck {
		members = append(members, daBits("Check", CO, 2))
	}
	return daStruct(name, CO, members...)
}

// zeroValue is the served default of a leaf: zero of its type, an
// all-clear quality for a 13-bit string, the epoch for timestamps.
func zeroValue(kind mms.Type, size int) *mms.Value {
	switch kind {
	case mms.TypeBoolean:
		return mms.NewBool(false)
	case mms.TypeInteger:
		return mms.NewInt32(0)
	case mms.TypeUnsigned:
		return mms.NewUint32(0)
	case mms.TypeFloat32:
		return mms.NewFloat32(0)
	case mms.TypeFloat64:
		return mms.NewFloat64(0)
	case mms.TypeVisibleString:
		return mms.NewVisibleString("")
	case mms.TypeMMSString:
		return mms.NewMMSString("")
	case mms.TypeOctetString:
		return mms.NewOctetString(nil)
	case mms.TypeBitString:
		if size <= 0 {
			size = 8
		}
		return mms.NewBitString(size)
	case mms.TypeUTCTime:
		return mms.NewUTCTime(time.Unix(0, 0).UTC(), 0)
	case mms.TypeBinaryTime:
		return mms.NewBinaryTime(time.Unix(0, 0).UTC())
	}
	return nil
}

func cloneAttrs(in []CDCAttribute) []CDCAttribute {
	if in == nil {
		return nil
	}
	out := make([]CDCAttribute, len(in))
	copy(out, in)
	for i := range out {
		out[i].Children = cloneAttrs(in[i].Children)
	}
	return out
}

// Table helpers. They keep the class tables below readable: each entry is
// one attribute with its functional constraint and type.

func daBool(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeBoolean}
}

func daInt(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeInteger}
}

func daFloat(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeFloat32}
}

func daString(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeVisibleString}
}

func daOctet(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeOctetString}
}

func daBits(name string, fc FC, size int) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeBitString, Size: size}
}

func daStruct(name string, fc FC, children ...CDCAttribute) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeStructure, Children: children}
}

// daQuality and daTime are the quality and timestamp every status and
// measurand class carries.
func daQuality(fc FC) CDCAttribute { return daBits("q", fc, 13) }
func daTime(fc FC) CDCAttribute {
	return CDCAttribute{Name: "t", FC: fc, Kind: mms.TypeUTCTime}
}

// daAnalogue is an AnalogueValue: an integer "i" or a float "f", of which
// the builder emits one.
func daAnalogue(name string, fc FC) CDCAttribute {
	return daStruct(name, fc, daInt("i", fc), daFloat("f", fc))
}

// daUnits is a Unit: the SI unit and its multiplier.
func daUnits(fc FC) CDCAttribute {
	return daStruct("units", fc, daInt("SIUnit", fc), daInt("multiplier", fc))
}

func optional(a CDCAttribute) CDCAttribute {
	a.Optional = true
	return a
}

// array makes a an array of maxPts elements.
func array(a CDCAttribute) CDCAttribute {
	a.Array = true
	return a
}

// withTrg gives a the trigger options t, where cdcTrgOps would derive
// others from its name.
func withTrg(a CDCAttribute, t TrgOps) CDCAttribute {
	a.trg, a.trgSet = t, true
	return a
}

// noTrg is an attribute that triggers nothing.
func noTrg(a CDCAttribute) CDCAttribute { return withTrg(a, 0) }

func oneOf(group string, a CDCAttribute) CDCAttribute {
	a.oneOf = group
	return a
}

func allOrNone(group string, a CDCAttribute) CDCAttribute {
	a.allOrNone = group
	return a
}

func daUint(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeUnsigned}
}

// daUnicode is a Unicode255, which 8-1 maps to an MMS string.
func daUnicode(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeMMSString}
}

func daTimeNamed(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeUTCTime}
}

func daEntryTime(name string, fc FC) CDCAttribute {
	return CDCAttribute{Name: name, FC: fc, Kind: mms.TypeBinaryTime}
}

func daUnitsNamed(name string, fc FC) CDCAttribute {
	u := daUnits(fc)
	u.Name = name
	return u
}

// daVector is a Vector: a magnitude and an optional angle.
func daVector(name string, fc FC) CDCAttribute {
	return daStruct(name, fc, daAnalogue("mag", fc), optional(daAnalogue("ang", fc)))
}

// daSVC is a ScaledValueConfig, the scaling of an integer AnalogueValue.
func daSVC(name string, fc FC) CDCAttribute {
	return daStruct(name, fc, daFloat("scaleFactor", fc), daFloat("offset", fc))
}

// daOrigin is an Originator: the category and identity of whoever issued
// the last control.
func daOrigin(fc FC) CDCAttribute {
	return daStruct("origin", fc, daInt("orCat", fc), daOctet("orIdent", fc))
}

// daPoint is a Point of a curve.
func daPoint(name string, fc FC) CDCAttribute {
	return daStruct(name, fc, daFloat("xVal", fc), daFloat("yVal", fc), optional(daFloat("zVal", fc)))
}

// daCell is a Cell of a histogram: its lower bound, and optionally its
// upper bound and a second dimension.
func daCell(name string, fc FC) CDCAttribute {
	return daStruct(name, fc, daFloat("xStart", fc),
		optional(daFloat("xEnd", fc)), optional(daFloat("yStart", fc)), optional(daFloat("yEnd", fc)))
}

// daCalendar is a CalendarTime, a recurring time: the third Sunday of
// every month at 02:00, say.
func daCalendar(name string, fc FC) CDCAttribute {
	return daStruct(name, fc,
		daUint("occ", fc), daInt("occType", fc), daInt("occPer", fc),
		daInt("weekDay", fc), daInt("month", fc),
		daUint("day", fc), daUint("hr", fc), daUint("mn", fc))
}

// daPhyComAddr is the PHYCOMADDR of IEC 61850-8-1, the destination of a
// GOOSE or sampled-value stream: MAC address, VLAN priority and
// identifier, and APPID. It is the structure the server serves as a
// control block's DstAddress.
func daPhyComAddr(name string, fc FC) CDCAttribute {
	return daStruct(name, fc,
		daOctet("Addr", fc), daUint("PRIORITY", fc), daUint("VID", fc), daUint("APPID", fc))
}

// substitution is the SV group a status, measurand or controllable class
// may carry: the substituted value takes the type of the value it
// replaces, so the caller passes a bare attribute of the right kind.
func substitution(valueKind CDCAttribute) []CDCAttribute {
	return substitutionAs("subVal", valueKind)
}

// substitutionAs is substitution for the classes whose substituted value
// has its own name: subMag for MV, subCVal for CMV.
func substitutionAs(name string, valueKind CDCAttribute) []CDCAttribute {
	sub := valueKind
	sub.Name = name
	sub.FC = SV
	subQ := daQuality(SV)
	subQ.Name = "subQ"
	return []CDCAttribute{
		optional(daBool("subEna", SV)),
		optional(sub),
		optional(subQ),
		optional(daString("subID", SV)),
	}
}

// subOf is substitution for a class whose value lives inside a structure:
// the substituted value keeps the structure's shape, so the caller passes
// the value attribute as it appears in the class.
func subOf(value CDCAttribute) []CDCAttribute { return substitution(value) }

type cdcSpec struct {
	attrs      []CDCAttribute
	subObjects []CDCSubObject
	// ctlVal is the type of the control value, for the controllable
	// classes only. The control structures are assembled around it.
	ctlVal *CDCAttribute
}

func spec(attrs ...CDCAttribute) cdcSpec { return cdcSpec{attrs: attrs} }

func (s cdcSpec) with(more ...CDCAttribute) cdcSpec {
	s.attrs = append(append([]CDCAttribute(nil), s.attrs...), more...)
	return s
}

func (s cdcSpec) controlledBy(ctlVal CDCAttribute) cdcSpec {
	s.ctlVal = &ctlVal
	return s
}

func (s cdcSpec) containing(subs ...CDCSubObject) cdcSpec {
	s.subObjects = subs
	return s
}

// cdcTable is the per-class attribute table, following the NSD of
// IEC 61850-7-3 Edition 2.1 (2007B5), which model/nsd_test.go checks it
// against. Entries are in the order 7-3 lists them; optional() marks the
// ones a caller has to ask for. The general description and namespace
// attributes other than d (dU, cdcName, dataNs) are not in the tables.
var cdcTable = map[CDC]cdcSpec{
	// --- Status information ---
	CDCSPS: spec(daBool("stVal", ST), daQuality(ST), daTime(ST)).
		with(substitution(daBool("", ST))...).
		with(optional(daString("d", DC))),
	CDCDPS: spec(daBits("stVal", ST, 2), daQuality(ST), daTime(ST)).
		with(substitution(daBits("", ST, 2))...).
		with(optional(daString("d", DC))),
	CDCINS: spec(withTrg(daInt("stVal", ST), TrgDataChange|TrgDataUpdate), daQuality(ST), daTime(ST)).
		with(substitution(daInt("", ST))...).
		with(optional(daUnits(CF)), optional(daString("d", DC))),
	CDCENS: spec(withTrg(daInt("stVal", ST), TrgDataChange|TrgDataUpdate), daQuality(ST), daTime(ST)).
		with(substitution(daInt("", ST))...).
		with(optional(daString("d", DC))),
	CDCVSS: spec(daString("stVal", ST), daQuality(ST), daTime(ST)).
		with(optional(daString("d", DC))),
	CDCACT: spec(
		daBool("general", ST),
		optional(daBool("phsA", ST)), optional(daBool("phsB", ST)),
		optional(daBool("phsC", ST)), optional(daBool("neut", ST)),
		daQuality(ST), daTime(ST),
		optional(daString("d", DC)),
	),
	CDCACD: spec(
		daBool("general", ST), daInt("dirGeneral", ST),
		optional(daBool("phsA", ST)), optional(daInt("dirPhsA", ST)),
		optional(daBool("phsB", ST)), optional(daInt("dirPhsB", ST)),
		optional(daBool("phsC", ST)), optional(daInt("dirPhsC", ST)),
		optional(daBool("neut", ST)), optional(daInt("dirNeut", ST)),
		daQuality(ST), daTime(ST),
		optional(daString("d", DC)),
	),
	// SEC counts security violations (IEC 62351-7 and the GSAL node of
	// 7-4): the count, the severity of the last one, and where it came
	// from.
	CDCSEC: spec(
		daUint("cnt", ST),
		noTrg(daInt("sev", ST)),
		daTime(ST),
		optional(noTrg(daOctet("addr", ST))),
		optional(noTrg(daString("addInfo", ST))),
		optional(daString("d", DC)),
	),
	CDCBCR: spec(
		CDCAttribute{Name: "actVal", FC: ST, Kind: mms.TypeInteger},
		optional(CDCAttribute{Name: "frVal", FC: ST, Kind: mms.TypeInteger}),
		optional(CDCAttribute{Name: "frTm", FC: ST, Kind: mms.TypeUTCTime}),
		daQuality(ST), daTime(ST),
		optional(daUnits(CF)), daFloat("pulsQty", CF),
		optional(daBool("frEna", CF)), optional(daTimeNamed("strTm", CF)),
		optional(daInt("frPd", CF)), optional(daBool("frRs", CF)),
		optional(daString("d", DC)),
	),
	// HST is a histogram: hstVal counts per cell, hstRangeC the cell
	// bounds, both maxPts long (WithMaxPts).
	CDCHST: spec(
		withTrg(array(daInt("hstVal", ST)), TrgDataChange|TrgDataUpdate),
		daQuality(ST), daTime(ST),
		daUint("numPts", CF),
		array(daCell("hstRangeC", CF)),
		daUnitsNamed("xUnits", CF), optional(daUnitsNamed("yUnits", CF)), optional(daUnits(CF)),
		daUint("maxPts", CF),
		daString("xD", DC), optional(daUnicode("xDU", DC)),
		optional(daString("yD", DC)), optional(daUnicode("yDU", DC)),
		optional(daString("d", DC)),
	),
	// ORS is an object reference status: the reference an object is
	// currently using, as FSCC.ActSchdRef names the active schedule.
	CDCORS: spec(daString("stVal", ST), daQuality(ST), daTime(ST)).
		with(optional(daString("d", DC))),
	// TCS is a time status: stVal is itself a timestamp.
	CDCTCS: spec(withTrg(daTimeNamed("stVal", ST), TrgDataChange|TrgDataUpdate), daQuality(ST), daTime(ST)).
		with(optional(daString("d", DC))),

	// --- Measurand information ---
	CDCMV: spec(
		optional(daAnalogue("instMag", MX)),
		daAnalogue("mag", MX),
		optional(daInt("range", MX)),
		daQuality(MX), daTime(MX),
	).with(substitutionAs("subMag", daAnalogue("", MX))...).
		with(
			optional(daBool("blkEna", BL)),
			optional(daUnits(CF)),
			optional(daUint("db", CF)),
			optional(daUint("zeroDb", CF)),
			optional(daSVC("sVC", CF)),
			optional(daUint("smpRate", CF)),
			optional(daFloat("dbRef", CF)),
			optional(daFloat("zeroDbRef", CF)),
			optional(daString("d", DC)),
		),
	CDCCMV: spec(
		optional(daVector("instCVal", MX)),
		daVector("cVal", MX),
		optional(daInt("range", MX)),
		optional(daInt("rangeAng", MX)),
		daQuality(MX), daTime(MX),
	).with(substitutionAs("subCVal", daVector("", MX))...).
		with(
			optional(daBool("blkEna", BL)),
			optional(daUnits(CF)),
			optional(daUint("db", CF)),
			optional(daUint("dbAng", CF)),
			optional(daUint("zeroDb", CF)),
			optional(daSVC("magSVC", CF)),
			optional(daSVC("angSVC", CF)),
			optional(daInt("angRef", CF)),
			optional(daUint("smpRate", CF)),
			optional(daFloat("dbRef", CF)),
			optional(daFloat("zeroDbRef", CF)),
			optional(daFloat("dbAngRef", CF)),
			optional(daString("d", DC)),
		),
	CDCSAV: spec(daAnalogue("instMag", MX), daQuality(MX)).
		with(optional(daTime(MX)), optional(daUnits(CF)), optional(daString("d", DC))),
	CDCWYE: spec(optional(daInt("angRef", CF)), optional(daString("d", DC))).
		containing(
			CDCSubObject{Name: "phsA", CDC: CDCCMV},
			CDCSubObject{Name: "phsB", CDC: CDCCMV},
			CDCSubObject{Name: "phsC", CDC: CDCCMV},
			CDCSubObject{Name: "neut", CDC: CDCCMV, Optional: true},
			CDCSubObject{Name: "net", CDC: CDCCMV, Optional: true},
			CDCSubObject{Name: "res", CDC: CDCCMV, Optional: true},
		),
	CDCDEL: spec(optional(daInt("angRef", CF)), optional(daString("d", DC))).
		containing(
			CDCSubObject{Name: "phsAB", CDC: CDCCMV},
			CDCSubObject{Name: "phsBC", CDC: CDCCMV},
			CDCSubObject{Name: "phsCA", CDC: CDCCMV},
		),
	// SEQ is a set of sequence components. c2 and c3 are optional in 7-3
	// (mandatory for a synchrophasor), so they are asked for by name.
	CDCSEQ: spec(noTrg(daInt("seqT", MX)), optional(daInt("phsRef", CF)), optional(daString("d", DC))).
		containing(
			CDCSubObject{Name: "c1", CDC: CDCCMV},
			CDCSubObject{Name: "c2", CDC: CDCCMV, Optional: true},
			CDCSubObject{Name: "c3", CDC: CDCCMV, Optional: true},
		),
	// HMV, HWYE and HDEL are harmonics: arrays of complex values, maxPts
	// long, with the evaluation parameters alongside.
	CDCHMV: spec(harmonicAttrs(false)...).
		containing(CDCSubObject{Name: "har", CDC: CDCCMV, Array: true}),
	CDCHWYE: spec(harmonicAttrs(true)...).
		containing(
			CDCSubObject{Name: "phsAHar", CDC: CDCCMV, Array: true},
			CDCSubObject{Name: "phsBHar", CDC: CDCCMV, Array: true, Optional: true},
			CDCSubObject{Name: "phsCHar", CDC: CDCCMV, Array: true, Optional: true},
			CDCSubObject{Name: "neutHar", CDC: CDCCMV, Array: true, Optional: true},
			CDCSubObject{Name: "netHar", CDC: CDCCMV, Array: true, Optional: true},
			CDCSubObject{Name: "resHar", CDC: CDCCMV, Array: true, Optional: true},
		),
	CDCHDEL: spec(harmonicAttrs(true)...).
		containing(
			CDCSubObject{Name: "phsABHar", CDC: CDCCMV, Array: true},
			CDCSubObject{Name: "phsBCHar", CDC: CDCCMV, Array: true, Optional: true},
			CDCSubObject{Name: "phsCAHar", CDC: CDCCMV, Array: true, Optional: true},
		),

	// --- Controllable information ---
	CDCSPC: spec(daBool("stVal", ST), daQuality(ST), daTime(ST)).
		with(substitution(daBool("", ST))...).
		with(
			optional(daBool("stSeld", ST)),
			optional(daUint("sboTimeout", CF)), optional(daInt("sboClass", CF)),
			optional(daUint("operTimeout", CF)), optional(daString("d", DC)),
		).
		controlledBy(daBool("ctlVal", CO)),
	CDCDPC: spec(daBits("stVal", ST, 2), daQuality(ST), daTime(ST)).
		with(substitution(daBits("", ST, 2))...).
		with(
			optional(daBool("stSeld", ST)),
			optional(daUint("sboTimeout", CF)), optional(daInt("sboClass", CF)),
			optional(daString("d", DC)),
		).
		controlledBy(daBool("ctlVal", CO)),
	CDCINC: spec(withTrg(daInt("stVal", ST), TrgDataChange|TrgDataUpdate), daQuality(ST), daTime(ST)).
		with(substitution(daInt("", ST))...).
		with(
			optional(daBool("stSeld", ST)),
			optional(daUnits(CF)), optional(daInt("minVal", CF)),
			optional(daInt("maxVal", CF)), optional(daUint("stepSize", CF)),
			optional(daUint("sboTimeout", CF)), optional(daString("d", DC)),
		).
		controlledBy(daInt("ctlVal", CO)),
	CDCENC: spec(daInt("stVal", ST), daQuality(ST), daTime(ST)).
		with(substitution(daInt("", ST))...).
		with(optional(daBool("stSeld", ST)), optional(daString("d", DC))).
		controlledBy(daInt("ctlVal", CO)),
	CDCBSC: spec(
		daStruct("valWTr", ST, daInt("posVal", ST), daBool("transInd", ST)),
		daQuality(ST), daTime(ST),
	).with(
		subOf(daStruct("valWTr", SV, daInt("posVal", SV), daBool("transInd", SV)))...,
	).with(
		optional(daBool("stSeld", ST)),
		daBool("persistent", CF),
		optional(daInt("minVal", CF)), optional(daInt("maxVal", CF)),
		optional(daString("d", DC)),
	).controlledBy(daBits("ctlVal", CO, 2)), // Tcmd: stop, lower, higher
	// ISC is an integer-controlled step position, a tap changer that is
	// told the position rather than lower or higher.
	CDCISC: spec(
		optional(noTrg(daOrigin(ST))), optional(noTrg(daUint("ctlNum", ST))),
		daStruct("valWTr", ST, daInt("posVal", ST), daBool("transInd", ST)),
		daQuality(ST), daTime(ST),
		optional(daBool("stSeld", ST)),
		optional(withTrg(daBool("opRcvd", OR), TrgDataChange)),
		optional(withTrg(daBool("opOk", OR), TrgDataChange)),
		optional(daTimeNamed("tOpOk", OR)),
	).with(
		subOf(daStruct("valWTr", SV, daInt("posVal", SV), daBool("transInd", SV)))...,
	).with(
		optional(daBool("blkEna", BL)),
		optional(daUint("sboTimeout", CF)), optional(daInt("sboClass", CF)),
		optional(daInt("minVal", CF)), optional(daInt("maxVal", CF)),
		optional(daUint("operTimeout", CF)),
		optional(daString("d", DC)),
	).controlledBy(daInt("ctlVal", CO)),
	CDCAPC: spec(daAnalogue("mxVal", MX), daQuality(MX), daTime(MX)).
		with(subOf(daAnalogue("", MX))...).
		with(
			optional(daBool("stSeld", MX)),
			optional(daUnits(CF)), optional(daUint("db", CF)),
			optional(daAnalogue("minVal", CF)), optional(daAnalogue("maxVal", CF)),
			optional(daAnalogue("stepSize", CF)),
			optional(daUint("sboTimeout", CF)), optional(daString("d", DC)),
		).
		controlledBy(daAnalogue("ctlVal", CO)),
	// BAC is an analogue value controlled by lower and higher steps, as a
	// Petersen coil's position is (ANCR.ColChg).
	CDCBAC: spec(
		optional(noTrg(daOrigin(MX))), optional(noTrg(daUint("ctlNum", MX))),
		daAnalogue("mxVal", MX),
		daQuality(MX), daTime(MX),
		optional(daBool("stSeld", MX)),
		optional(withTrg(daBool("opRcvd", OR), TrgDataChange)),
		optional(withTrg(daBool("opOk", OR), TrgDataChange)),
		optional(daTimeNamed("tOpOk", OR)),
	).with(subOf(daAnalogue("", MX))...).
		with(
			optional(daBool("blkEna", BL)),
			daBool("persistent", CF),
			optional(daUint("sboTimeout", CF)), optional(daInt("sboClass", CF)),
			optional(daUnits(CF)), optional(daUint("db", CF)),
			optional(daSVC("sVC", CF)),
			optional(daAnalogue("minVal", CF)), optional(daAnalogue("maxVal", CF)),
			optional(daAnalogue("stepSize", CF)),
			optional(daUint("operTimeout", CF)),
			optional(daFloat("dbRef", CF)),
			optional(daString("d", DC)),
		).
		controlledBy(daBits("ctlVal", CO, 2)), // Tcmd: stop, lower, higher

	// --- Settings ---
	CDCSPG: spec(daBool("setVal", SP)).with(optional(daString("d", DC))),
	CDCING: spec(daInt("setVal", SP)).
		with(
			optional(daUnits(CF)), optional(daInt("minVal", CF)),
			optional(daInt("maxVal", CF)), optional(daUint("stepSize", CF)),
			optional(daString("d", DC)),
		),
	CDCENG: spec(daInt("setVal", SP)).with(optional(daString("d", DC))),
	// ORG is an object reference setting: the input an LN takes its value
	// from (LLN0.InRef, LGOS.GoCBRef), with an optional test source.
	CDCORG: spec(
		daString("setSrcRef", SP),
		allOrNone("test", optional(daString("setTstRef", SP))),
		optional(daString("setSrcCB", SP)),
		optional(daString("setTstCB", SP)),
		optional(daString("intAddr", SP)),
		allOrNone("test", optional(daBool("tstEna", SP))),
		optional(daString("purpose", DC)),
		optional(daString("d", DC)),
	),
	// TSG is a time setting, as an absolute time or a calendar rule; one
	// of them is present, setTm unless setCal is asked for.
	CDCTSG: spec(
		oneOf("time", optional(daTimeNamed("setTm", SP))),
		oneOf("time", optional(daCalendar("setCal", SP))),
		optional(daString("d", DC)),
	),
	// CUG is a currency setting: an ISO 4217 code.
	CDCCUG: spec(daString("cur", SP), optional(daString("d", DC))),
	CDCVSG: spec(daString("setVal", SP), optional(daString("d", DC))),
	CDCASG: spec(daAnalogue("setMag", SP)).
		with(
			optional(daUnits(CF)), optional(daAnalogue("minVal", CF)),
			optional(daAnalogue("maxVal", CF)), optional(daAnalogue("stepSize", CF)),
			optional(daString("d", DC)),
		),
	// CURVE is a curve setting by characteristic and parameters.
	CDCCURVE: spec(
		daInt("setCharact", SP),
		optional(daFloat("setParA", SP)), optional(daFloat("setParB", SP)),
		optional(daFloat("setParC", SP)), optional(daFloat("setParD", SP)),
		optional(daFloat("setParE", SP)), optional(daFloat("setParF", SP)),
		optional(daString("d", DC)),
	),
	// CSG is a curve shape setting: the points of the curve, maxPts long.
	CDCCSG: spec(
		optional(daFloat("pointZ", SP)),
		daUint("numPts", SP),
		array(daPoint("crvPts", SP)),
		daUnitsNamed("xUnits", CF), daUnitsNamed("yUnits", CF), optional(daUnitsNamed("zUnits", CF)),
		daUint("maxPts", CF),
		daString("xD", DC), optional(daUnicode("xDU", DC)),
		daString("yD", DC), optional(daUnicode("yDU", DC)),
		optional(daString("zD", DC)), optional(daUnicode("zDU", DC)),
		optional(daString("d", DC)),
	),

	// --- Description ---
	CDCLPL: spec(daString("vendor", DC), daString("swRev", DC)).
		with(
			optional(daString("d", DC)), optional(daString("configRev", DC)),
			optional(daString("ldNs", EX)),
		),
	CDCDPL: spec(daString("vendor", DC)).
		with(
			optional(daString("hwRev", DC)), optional(daString("swRev", DC)),
			optional(daString("serNum", DC)), optional(daString("model", DC)),
			optional(daString("location", DC)),
		),
	// CSD is a curve shape description: a CSG's shape, read-only.
	CDCCSD: spec(
		daUnitsNamed("xUnits", DC), daString("xD", DC), optional(daUnicode("xDU", DC)),
		daUnitsNamed("yUnits", DC), daString("yD", DC), optional(daUnicode("yDU", DC)),
		optional(daUnitsNamed("zUnits", DC)), optional(daString("zD", DC)), optional(daUnicode("zDU", DC)),
		daUint("numPts", DC),
		array(daPoint("crvPts", DC)),
		daUint("maxPts", CF),
		optional(daString("d", DC)),
	),
	// VSD is a visible string description.
	CDCVSD: spec(daString("val", DC), optional(daString("d", DC))),

	// --- Service tracking (IEC 61850-7-2 Edition 2, the LTRK node) ---
	// Each records the last service applied to one kind of object: who
	// asked, what for, the outcome, and the object's state afterwards.
	CDCCST: spec(tracking(true)...).with(optional(daString("d", DC))),
	CDCBTS: spec(tracking(true)...).with(
		daString("rptID", SR), daBool("rptEna", SR), daString("datSet", SR),
		daUint("confRev", SR), daBits("optFlds", SR, 10), daUint("bufTm", SR),
		daUint("sqNum", SR), daBits("trgOps", SR, 6), daUint("intgPd", SR),
		daBool("gi", SR), daBool("purgeBuf", SR), daOctet("entryID", SR),
		daEntryTime("timeOfEntry", SR),
		optional(daInt("resvTms", SR)), optional(daOctet("owner", SR)),
		optional(daString("d", DC)),
	),
	CDCUTS: spec(tracking(true)...).with(
		daString("rptID", SR), daBool("rptEna", SR), daBool("resv", SR),
		daString("datSet", SR), daUint("confRev", SR), daBits("optFlds", SR, 10),
		daUint("bufTm", SR), daUint("sqNum", SR), daBits("trgOps", SR, 6),
		daUint("intgPd", SR), daBool("gi", SR),
		optional(daOctet("owner", SR)),
		optional(daString("d", DC)),
	),
	// LTS tracks the ACSI log control block. The log's own state
	// (OldEntrTm, NewEntr...) belongs to the LOG class, not to the block.
	CDCLTS: spec(tracking(true)...).with(
		daBool("logEna", SR), daString("datSet", SR), daUint("bufTm", SR),
		daBits("trgOps", SR, 6), daUint("intgPd", SR), daString("logRef", SR),
		optional(daString("d", DC)),
	),
	CDCGTS: spec(tracking(true)...).with(
		daBool("goEna", SR), daString("goID", SR), daString("datSet", SR),
		daUint("confRev", SR), daBool("ndsCom", SR),
		daPhyComAddr("dstAddress", SR),
		optional(daString("d", DC)),
	),
	CDCMTS: spec(tracking(true)...).with(
		daBool("svEna", SR), daString("msvID", SR), daString("datSet", SR),
		daUint("confRev", SR), daUint("smpRate", SR), daBits("optFlds", SR, 10),
		daInt("smpMod", SR),
		daPhyComAddr("dstAddress", SR),
		optional(daString("d", DC)),
	),
	CDCNTS: spec(tracking(false)...).with(
		daBool("svEna", SR), daBool("resv", SR), daString("usvID", SR),
		daString("datSet", SR), daUint("confRev", SR), daInt("smpMod", SR),
		daUint("smpRate", SR), daBits("optFlds", SR, 10),
		daPhyComAddr("dstAddress", SR),
		optional(daString("d", DC)),
	),
	CDCSTS: spec(tracking(true)...).with(
		daUint("numOfSG", SR), daUint("actSG", SR), daUint("editSG", SR),
		daBool("cnfEdit", SR), daTimeNamed("lActTm", SR),
		optional(daUint("resvTms", SR)),
		optional(daString("d", DC)),
	),
	CDCCTS: spec(tracking(true)...).with(
		CDCAttribute{Name: "ctlVal", FC: SR, Kind: mms.TypeBoolean, ctlValSlot: true},
		optional(daTimeNamed("operTm", SR)),
		daOrigin(SR),
		daUint("ctlNum", SR),
		daTimeNamed("T", SR),
		daBool("Test", SR),
		daBits("Check", SR, 2),
		daInt("respAddCause", SR),
		optional(daString("d", DC)),
	),
}

// harmonicAttrs are the evaluation parameters of HMV, and with angRef
// those of HWYE and HDEL.
func harmonicAttrs(withAngRef bool) []CDCAttribute {
	out := []CDCAttribute{
		daUint("numHar", CF), daUint("numCyc", CF), daUint("evalTm", CF),
	}
	if withAngRef {
		out = append(out, optional(daInt("angRef", CF)))
	}
	return append(out,
		optional(daUint("smpRate", CF)),
		daFloat("frequency", CF),
		optional(daInt("hvRef", CF)),
		optional(daUint("rmsCyc", CF)),
		daUint("maxPts", CF),
		optional(daString("d", DC)),
	)
}

// tracking is the common part of the service tracking classes: the
// object the service addressed, the service and its outcome, who asked,
// and when. NTS has no certificate issuer.
func tracking(withCertIssuer bool) []CDCAttribute {
	out := []CDCAttribute{
		withTrg(daString("objRef", SR), TrgDataUpdate),
		daInt("serviceType", SR),
		daInt("errorCode", SR),
		optional(daOctet("originatorID", SR)),
		daTime(SR),
	}
	if withCertIssuer {
		out = append(out, optional(daUnicode("certIssuer", SR)))
	}
	return out
}
