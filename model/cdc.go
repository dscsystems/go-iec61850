package model

import (
	"fmt"
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
	Children []CDCAttribute
}

// CDCSubObject describes a data object nested inside another, as the phase
// measurands of a WYE are.
type CDCSubObject struct {
	Name     string
	CDC      CDC
	Optional bool
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

// NewDataObject builds a data object of the given common data class: its
// mandatory attributes, any optional ones asked for, and any nested data
// objects the class defines, each with a zero value of its type.
//
//	spc := model.NewDataObject("SPCSO1", model.CDCSPC,
//		model.WithControlModel(model.CtlSBOEnhanced))
//	mv := model.NewDataObject("AnIn1", model.CDCMV,
//		model.WithOptional("units", "db"))
//
// It panics on a class it does not know: the class names are constants,
// and a caller assembling one at run time can check CDCAttributes first.
func NewDataObject(name string, cdc CDC, opts ...CDCOption) *DataObject {
	spec, ok := cdcTable[cdc]
	if !ok {
		panic(fmt.Sprintf("model: unknown common data class %q", cdc))
	}
	b := &cdcBuild{withCancel: true, optional: map[string]bool{}, settingFC: SP}
	for _, opt := range opts {
		opt(b)
	}

	do := &DataObject{Name: name, CDC: string(cdc)}
	for _, a := range spec.attrs {
		if da := b.attribute(a); da != nil {
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
		do.Objects = append(do.Objects, NewDataObject(sub.Name, sub.CDC, opts...))
	}
	return do
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
	da := &DataAttribute{Name: a.Name, FC: fc, Kind: a.Kind}
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
		return da
	}
	da.Value = zeroValue(a.Kind, a.Size)
	return da
}

// attributeFC materialises a member of a structure, which inherits its
// parent's functional constraint.
func (b *cdcBuild) attributeFC(a CDCAttribute, fc FC) *DataAttribute {
	if a.Optional && !b.optional[a.Name] {
		return nil
	}
	child := a
	child.FC = fc
	da := b.attribute(child)
	if da != nil {
		da.FC = fc
	}
	return da
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

// substitution is the SV group every status and measurand class may carry.
func substitution(valueKind CDCAttribute) []CDCAttribute {
	sub := valueKind
	sub.Name = "subVal"
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

// cdcTable is the per-class attribute table. Entries are in the order
// IEC 61850-7-3 lists them, mandatory attributes first; optional() marks
// the ones a caller has to ask for.
var cdcTable = map[CDC]cdcSpec{
	// --- Status information ---
	CDCSPS: spec(daBool("stVal", ST), daQuality(ST), daTime(ST)).
		with(substitution(daBool("", ST))...).
		with(optional(daString("d", DC))),
	CDCDPS: spec(daBits("stVal", ST, 2), daQuality(ST), daTime(ST)).
		with(substitution(daBits("", ST, 2))...).
		with(optional(daString("d", DC))),
	CDCINS: spec(daInt("stVal", ST), daQuality(ST), daTime(ST)).
		with(substitution(daInt("", ST))...).
		with(optional(daUnits(CF)), optional(daString("d", DC))),
	CDCENS: spec(daInt("stVal", ST), daQuality(ST), daTime(ST)).
		with(substitution(daInt("", ST))...).
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
	CDCBCR: spec(
		CDCAttribute{Name: "actVal", FC: ST, Kind: mms.TypeInteger},
		daQuality(ST), daTime(ST),
		optional(CDCAttribute{Name: "frVal", FC: ST, Kind: mms.TypeInteger}),
		optional(CDCAttribute{Name: "frTm", FC: ST, Kind: mms.TypeUTCTime}),
		optional(daFloat("pulsQty", CF)), optional(daUnits(CF)),
		optional(daString("d", DC)),
	),

	// --- Measurand information ---
	CDCMV: spec(daAnalogue("mag", MX), daQuality(MX), daTime(MX)).
		with(
			optional(daAnalogue("instMag", MX)),
			optional(daInt("range", MX)),
			optional(daUnits(CF)),
			optional(daInt("db", CF)),
			optional(daInt("zeroDb", CF)),
			optional(daString("d", DC)),
		),
	CDCCMV: spec(
		daStruct("cVal", MX, daAnalogue("mag", MX), optional(daAnalogue("ang", MX))),
		daQuality(MX), daTime(MX),
	).with(
		optional(daInt("range", MX)),
		optional(daUnits(CF)),
		optional(daInt("db", CF)),
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

	// --- Controllable information ---
	CDCSPC: spec(daBool("stVal", ST), daQuality(ST), daTime(ST)).
		with(
			optional(daBool("stSeld", ST)),
			optional(daInt("sboTimeout", CF)), optional(daInt("sboClass", CF)),
			optional(daInt("operTimeout", CF)), optional(daString("d", DC)),
		).
		controlledBy(daBool("ctlVal", CO)),
	CDCDPC: spec(daBits("stVal", ST, 2), daQuality(ST), daTime(ST)).
		with(
			optional(daBool("stSeld", ST)),
			optional(daInt("sboTimeout", CF)), optional(daInt("sboClass", CF)),
			optional(daString("d", DC)),
		).
		controlledBy(daBool("ctlVal", CO)),
	CDCINC: spec(daInt("stVal", ST), daQuality(ST), daTime(ST)).
		with(
			optional(daBool("stSeld", ST)),
			optional(daUnits(CF)), optional(daInt("minVal", CF)),
			optional(daInt("maxVal", CF)), optional(daInt("stepSize", CF)),
			optional(daInt("sboTimeout", CF)), optional(daString("d", DC)),
		).
		controlledBy(daInt("ctlVal", CO)),
	CDCENC: spec(daInt("stVal", ST), daQuality(ST), daTime(ST)).
		with(optional(daBool("stSeld", ST)), optional(daString("d", DC))).
		controlledBy(daInt("ctlVal", CO)),
	CDCBSC: spec(
		daStruct("valWTr", ST, daInt("posVal", ST), daBool("transInd", ST)),
		daQuality(ST), daTime(ST),
	).with(
		optional(daBool("stSeld", ST)),
		optional(daInt("minVal", CF)), optional(daInt("maxVal", CF)),
		optional(daString("d", DC)),
	).controlledBy(daInt("ctlVal", CO)),
	CDCAPC: spec(daAnalogue("mxVal", MX), daQuality(MX), daTime(MX)).
		with(
			optional(daBool("stSeld", ST)),
			optional(daUnits(CF)), optional(daInt("db", CF)),
			optional(daAnalogue("minVal", CF)), optional(daAnalogue("maxVal", CF)),
			optional(daAnalogue("stepSize", CF)),
			optional(daInt("sboTimeout", CF)), optional(daString("d", DC)),
		).
		controlledBy(daAnalogue("ctlVal", CO)),

	// --- Settings ---
	CDCSPG: spec(daBool("setVal", SP)).with(optional(daString("d", DC))),
	CDCING: spec(daInt("setVal", SP)).
		with(
			optional(daUnits(CF)), optional(daInt("minVal", CF)),
			optional(daInt("maxVal", CF)), optional(daInt("stepSize", CF)),
			optional(daString("d", DC)),
		),
	CDCENG: spec(daInt("setVal", SP)).with(optional(daString("d", DC))),
	CDCASG: spec(daAnalogue("setMag", SP)).
		with(
			optional(daUnits(CF)), optional(daAnalogue("minVal", CF)),
			optional(daAnalogue("maxVal", CF)), optional(daAnalogue("stepSize", CF)),
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
}
