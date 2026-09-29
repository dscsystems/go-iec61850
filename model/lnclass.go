package model

import (
	"sort"
	"strings"
)

// LNObject describes one data object of a logical node class (IEC 61850-7-4):
// its name, the common data class it is built from, and whether the class
// requires it.
type LNObject struct {
	Name     string
	CDC      CDC
	Optional bool
	// Multi marks a data object 7-4 lets a node carry several of (Omulti,
	// Mmulti), instantiated with a number: Ind1, Ind2, AnIn1... A
	// mandatory one needs at least one instance.
	Multi bool

	// opts are the build options the object always takes: the control a
	// tracking object of LTRK tracks, for example.
	opts []CDCOption
}

// lnClassTable holds the logical node classes of IEC 61850-7-4 Edition 2
// and 2.1 that are templated here, following the NSD of 7-4, which
// model/nsd_test.go checks it against when it is available.
//
// The table errs one way only. A data object is marked mandatory only where
// 7-4 makes it mandatory in every Edition 2 release; one whose presence
// condition is conditional, or changed between releases, is optional here.
// A data object this table does not list is not a defect: the class may
// define it and the table not carry it, or it may be a vendor extension. So
// CheckLogicalNode reports what the table is sure of — a mandatory object
// missing, or an object under the wrong class — and nothing else.
var lnClassTable = map[string][]LNObject{}

func init() {
	// The data every domain logical node has (7-4 "DomainLN").
	domain := []LNObject{
		lnOpt("Mod", CDCENC), lnM("Beh", CDCENS), lnOpt("Health", CDCENS),
		lnOpt("NamPlt", CDCLPL), lnMulti("InRef", CDCORG),
	}
	// Local and remote operation, of the nodes that can be operated from
	// either (7-4 "ControlledLN" and the switching and control classes).
	local := []LNObject{lnOpt("LocKey", CDCSPS), lnOpt("LocSta", CDCSPC)}
	equipment := []LNObject{lnOpt("EEName", CDCDPL), lnOpt("EEHealth", CDCENS)}
	// Start and operate of a protection function.
	protection := []LNObject{lnM("Str", CDCACD), lnM("Op", CDCACT)}
	class := func(parts ...[]LNObject) []LNObject {
		var out []LNObject
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}

	lnClassTable = map[string][]LNObject{
		// --- System logical nodes (L) ---
		"LLN0": {
			lnM("Mod", CDCENC), lnM("Beh", CDCENS), lnM("Health", CDCENS),
			lnM("NamPlt", CDCLPL),
			lnOpt("Loc", CDCSPS), lnOpt("LocKey", CDCSPS), lnOpt("LocSta", CDCSPC),
			lnOpt("OpTmh", CDCINS), lnOpt("Diag", CDCSPC), lnOpt("LEDRs", CDCSPC),
			lnOpt("MltLev", CDCSPG), lnOpt("GrRef", CDCORG),
			lnMulti("InRef", CDCORG),
		},
		// LPHD is the physical device, not a function, and has no
		// behaviour of its own.
		"LPHD": {
			lnOpt("NamPlt", CDCLPL),
			lnM("PhyNam", CDCDPL), lnM("PhyHealth", CDCENS),
			lnOpt("OutOv", CDCSPS), lnM("Proxy", CDCSPS), lnOpt("InOv", CDCSPS),
			lnOpt("NumPwrUp", CDCINS), lnOpt("WrmStr", CDCINS), lnOpt("WacTrg", CDCINS),
			lnOpt("PwrUp", CDCSPS), lnOpt("PwrDn", CDCSPS), lnOpt("PwrSupAlm", CDCSPS),
			lnOpt("RsStat", CDCSPC), lnOpt("Sim", CDCSPC),
		},
		// LTRK records the last service of each kind (IEC 61850-7-2
		// Edition 2); a control tracking object carries the ctlVal of the
		// control it tracks.
		"LTRK": class(domain, []LNObject{
			lnTrk("SpcTrk", CDCSPC), lnTrk("DpcTrk", CDCDPC), lnTrk("IncTrk", CDCINC),
			lnTrk("EncTrk", CDCENC), lnTrk("ApcFTrk", CDCAPC),
			withOpts(lnTrk("ApcIntTrk", CDCAPC), WithIntegerAnalogue()),
			lnTrk("BscTrk", CDCBSC), lnTrk("IscTrk", CDCISC), lnTrk("BacTrk", CDCBAC),
			lnOpt("GenTrk", CDCCST),
			lnOpt("UrcbTrk", CDCUTS), lnOpt("BrcbTrk", CDCBTS), lnOpt("LocbTrk", CDCLTS),
			lnOpt("GocbTrk", CDCGTS), lnOpt("MsvcbTrk", CDCMTS), lnOpt("UsvcbTrk", CDCNTS),
			lnOpt("SgcbTrk", CDCSTS),
		}),

		// --- Control (C) and interlocking ---
		"CSWI": class(domain, []LNObject{lnOpt("Loc", CDCSPS)}, local, []LNObject{
			lnOpt("OpOpn", CDCACT), lnOpt("SelOpn", CDCSPS),
			lnOpt("OpCls", CDCACT), lnOpt("SelCls", CDCSPS),
			lnOpt("Pos", CDCDPC),
			lnOpt("PosA", CDCDPC), lnOpt("PosB", CDCDPC), lnOpt("PosC", CDCDPC),
		}),
		"CILO": class(domain, []LNObject{lnM("EnaOpn", CDCSPS), lnM("EnaCls", CDCSPS)}),

		// --- Generic (G) ---
		"GGIO": class(domain, equipment, []LNObject{lnOpt("Loc", CDCSPS)}, local, []LNObject{
			lnMulti("AnIn", CDCMV), lnMulti("AnOut", CDCAPC), lnMulti("CntVal", CDCBCR),
			lnMulti("Ind", CDCSPS), lnMulti("IntIn", CDCINS), lnMulti("Alm", CDCSPS),
			lnMulti("SPCSO", CDCSPC), lnMulti("DPCSO", CDCDPC), lnMulti("ISCSO", CDCINC),
		}),
		"GAPC": class(domain, []LNObject{
			lnOpt("Str", CDCACD), lnOpt("Op", CDCACT),
			lnMulti("SPCSO", CDCSPC), lnMulti("DPCSO", CDCDPC), lnMulti("ISCSO", CDCINC),
		}),

		// --- Measurement (M) ---
		"MMXU": class(domain, []LNObject{
			lnOpt("TotW", CDCMV), lnOpt("TotVAr", CDCMV), lnOpt("TotVA", CDCMV),
			lnOpt("TotPF", CDCMV), lnOpt("Hz", CDCMV),
			lnOpt("PPV", CDCDEL), lnOpt("PhV", CDCWYE), lnOpt("A", CDCWYE),
			lnOpt("W", CDCWYE), lnOpt("VAr", CDCWYE), lnOpt("VA", CDCWYE),
			lnOpt("PF", CDCWYE), lnOpt("Z", CDCWYE),
		}),
		"MMXN": class(domain, []LNObject{
			lnOpt("Amp", CDCMV), lnOpt("Vol", CDCMV), lnOpt("Watt", CDCMV),
			lnOpt("VolAmpr", CDCMV), lnOpt("VolAmp", CDCMV), lnOpt("PwrFact", CDCMV),
			lnOpt("Imp", CDCCMV), lnOpt("Hz", CDCMV),
		}),
		"MSQI": class(domain, []LNObject{lnOpt("SeqA", CDCSEQ), lnOpt("SeqV", CDCSEQ)}),

		// --- Protection (P) ---
		"PTOC": class(domain, protection, []LNObject{
			lnOpt("TmACrv", CDCCURVE), lnOpt("StrVal", CDCASG), lnOpt("TmMult", CDCASG),
			lnOpt("MinOpTmms", CDCING), lnOpt("MaxOpTmms", CDCING),
			lnOpt("OpDlTmms", CDCING), lnOpt("TypRsCrv", CDCENG),
			lnOpt("RsDlTmms", CDCING), lnOpt("DirMod", CDCENG),
		}),
		"PTOV": class(domain, protection, []LNObject{
			lnOpt("StrVal", CDCASG), lnOpt("OpDlTmms", CDCING), lnOpt("RsDlTmms", CDCING),
		}),
		"PTUV": class(domain, protection, []LNObject{
			lnOpt("StrVal", CDCASG), lnOpt("OpDlTmms", CDCING), lnOpt("RsDlTmms", CDCING),
		}),
		"PDIS": class(domain, protection, []LNObject{
			lnOpt("PoRch", CDCASG), lnOpt("PhStr", CDCASG), lnOpt("GndStr", CDCASG),
			lnOpt("OpDlTmms", CDCING),
		}),
		"PDIF": class(domain, []LNObject{lnOpt("Str", CDCACD), lnM("Op", CDCACT)}),
		// PTRC needs a trip or an operate output, 7-4 does not say which.
		"PTRC": class(domain, []LNObject{
			lnOpt("Tr", CDCACT), lnOpt("Op", CDCACT), lnOpt("Str", CDCACD),
		}),

		// --- Protection related (R) ---
		"RREC": class(domain, []LNObject{
			lnM("Op", CDCACT), lnM("AutoRecSt", CDCENS),
			lnOpt("BlkRec", CDCSPC), lnOpt("ChkRec", CDCSPC), lnOpt("Auto", CDCSPS),
		}),

		// --- Switchgear (X) ---
		"XCBR": class(domain, equipment, []LNObject{
			lnM("Loc", CDCSPS)}, local, []LNObject{
			lnM("OpCnt", CDCINS), lnOpt("CBOpCap", CDCENS), lnOpt("POWCap", CDCENS),
			lnOpt("MaxOpCap", CDCINS), lnOpt("Dsc", CDCSPS),
			lnM("Pos", CDCDPC), lnM("BlkOpn", CDCSPC), lnM("BlkCls", CDCSPC),
			lnOpt("ChaMotEna", CDCSPC), lnOpt("SumSwARs", CDCBCR),
		}),
		"XSWI": class(domain, equipment, []LNObject{
			lnM("Loc", CDCSPS)}, local, []LNObject{
			lnM("OpCnt", CDCINS), lnM("SwTyp", CDCENS), lnOpt("SwOpCap", CDCENS),
			lnOpt("MaxOpCap", CDCINS), lnOpt("Dsc", CDCSPS),
			lnM("Pos", CDCDPC), lnM("BlkOpn", CDCSPC), lnM("BlkCls", CDCSPC),
			lnOpt("ChaMotEna", CDCSPC),
		}),
	}
}

func lnM(name string, cdc CDC) LNObject   { return LNObject{Name: name, CDC: cdc} }
func lnOpt(name string, cdc CDC) LNObject { return LNObject{Name: name, CDC: cdc, Optional: true} }

func lnMulti(name string, cdc CDC) LNObject {
	return LNObject{Name: name, CDC: cdc, Optional: true, Multi: true}
}

// lnTrk is an optional control tracking object of LTRK, tracking a control
// of class tracked.
func lnTrk(name string, tracked CDC) LNObject {
	return withOpts(lnOpt(name, CDCCTS), WithTrackedControl(tracked))
}

func withOpts(o LNObject, opts ...CDCOption) LNObject {
	o.opts = append(append([]CDCOption(nil), o.opts...), opts...)
	return o
}

// LNClassObjects returns the data objects of a logical node class, in the
// order 7-4 lists them, or nil when the class has no template here. The
// result is a copy.
func LNClassObjects(class string) []LNObject {
	objs, ok := lnClassTable[normLNClass(class)]
	if !ok {
		return nil
	}
	return append([]LNObject(nil), objs...)
}

// KnownLNClass reports whether the named logical node class has a template.
func KnownLNClass(class string) bool {
	_, ok := lnClassTable[normLNClass(class)]
	return ok
}

// KnownLNClasses returns the logical node classes that have templates,
// sorted.
func KnownLNClasses() []string {
	out := make([]string, 0, len(lnClassTable))
	for c := range lnClassTable {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func normLNClass(class string) string { return strings.ToUpper(strings.TrimSpace(class)) }

// LNOption adjusts how a logical node is built.
type LNOption func(*lnBuild)

type lnBuild struct {
	asked   []string
	objOpts map[string][]CDCOption
}

// WithObjects includes optional data objects of the class by name. A
// multi-instance object is asked for by instance name, "Ind1" or "AnIn3";
// asking for its bare name builds the first instance. Names the class does
// not define are ignored.
func WithObjects(names ...string) LNOption {
	return func(b *lnBuild) { b.asked = append(b.asked, names...) }
}

// WithObjectOptions builds the named data object with opts, after any
// options the class gives it: a control model for Pos, say. name is an
// instance name ("SPCSO1") or, for every instance of a multi-instance
// object, its bare name ("SPCSO").
func WithObjectOptions(name string, opts ...CDCOption) LNOption {
	return func(b *lnBuild) { b.objOpts[name] = append(b.objOpts[name], opts...) }
}

// NewLogicalNode builds a logical node of a 7-4 class: every data object
// the class makes mandatory, and the optional ones asked for with
// WithObjects, each built by NewDataObject from its common data class. A
// mandatory multi-instance object gets its first instance.
//
//	xcbr := model.NewLogicalNode("Q0", "XCBR", "1",
//		model.WithObjects("SumSwARs"),
//		model.WithObjectOptions("Pos", model.WithControlModel(model.CtlSBOEnhanced)))
//
// The node is named prefix+class+inst, and LLN0 is always "LLN0". A class
// with no template here yields the named node with no data objects;
// KnownLNClass says which classes have one.
func NewLogicalNode(prefix, class, inst string, opts ...LNOption) *LogicalNode {
	class = normLNClass(class)
	ln := &LogicalNode{Name: prefix + class + inst, Class: class}
	if class == "LLN0" {
		ln.Name = "LLN0"
	}
	b := &lnBuild{objOpts: map[string][]CDCOption{}}
	for _, o := range opts {
		o(b)
	}
	for _, obj := range lnClassTable[class] {
		for _, name := range b.instances(obj) {
			// The class's options, then those given for every instance,
			// then those given for this one, so the most specific wins.
			o := append([]CDCOption(nil), obj.opts...)
			if name != obj.Name {
				o = append(o, b.objOpts[obj.Name]...)
			}
			o = append(o, b.objOpts[name]...)
			ln.Objects = append(ln.Objects, NewDataObject(name, obj.CDC, o...))
		}
	}
	return ln
}

// instances returns the names obj is built under: none, its own name, or
// for a multi-instance object the instances asked for.
func (b *lnBuild) instances(obj LNObject) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range b.asked {
		switch {
		case n == obj.Name && obj.Multi:
			n = obj.Name + "1"
		case n == obj.Name:
		case obj.Multi && instanceOf(n, obj.Name):
		default:
			continue
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 && !obj.Optional {
		if obj.Multi {
			return []string{obj.Name + "1"}
		}
		return []string{obj.Name}
	}
	return out
}

// instanceOf reports whether name is an instance of the multi-instance data
// object base: base followed by a number from 1.
func instanceOf(name, base string) bool {
	num, ok := strings.CutPrefix(name, base)
	if !ok || num == "" || num[0] == '0' {
		return false
	}
	for _, r := range num {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CheckLogicalNode compares a logical node with the 7-4 template of its
// class, and reports each mandatory data object that is missing and each
// data object built from a common data class other than the one 7-4 gives
// it. Edition 1 used INS, INC and ING where Edition 2 uses the enumerated
// ENS, ENC and ENG; either is accepted. A node whose class has no template,
// or that has no class (a model retrieved from a server), is not checked.
func CheckLogicalNode(ln *LogicalNode) []Diagnostic {
	return checkLogicalNode(ln, ln.Name)
}

// CheckLNClasses runs CheckLogicalNode on every logical node of the model.
// The diagnostics are returned, not added to m.Diagnostics: conformance to
// 7-4 is a question about the device, not a problem interpreting the file.
func (m *Model) CheckLNClasses() []Diagnostic {
	var out []Diagnostic
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			out = append(out, checkLogicalNode(ln, ld.Name+"/"+ln.Name)...)
		}
	}
	return out
}

func checkLogicalNode(ln *LogicalNode, path string) []Diagnostic {
	objs, ok := lnClassTable[normLNClass(ln.Class)]
	if !ok {
		return nil
	}
	var out []Diagnostic
	present := map[string]bool{}
	for _, do := range ln.Objects {
		obj, ok := lnObjectFor(objs, do.Name)
		if !ok {
			continue
		}
		present[obj.Name] = true
		if do.CDC != "" && !cdcCompatible(obj.CDC, do.CDC) {
			out = append(out, Addf(path+"."+do.Name,
				"data object of class %s, IEC 61850-7-4 gives %s.%s the class %s",
				do.CDC, ln.Class, obj.Name, obj.CDC))
		}
	}
	for _, obj := range objs {
		if !obj.Optional && !present[obj.Name] {
			out = append(out, Addf(path, "mandatory data object %s (%s) of %s is missing",
				obj.Name, obj.CDC, ln.Class))
		}
	}
	return out
}

// lnObjectFor finds the class entry a data object name instantiates.
func lnObjectFor(objs []LNObject, name string) (LNObject, bool) {
	for _, o := range objs {
		if o.Name == name || (o.Multi && instanceOf(name, o.Name)) {
			return o, true
		}
	}
	return LNObject{}, false
}

// cdcCompatible reports whether a data object of class got may stand for
// one of class want: the same class, or the Edition 1 integer class of an
// Edition 2 enumerated one.
func cdcCompatible(want CDC, got string) bool {
	g := CDC(strings.ToUpper(strings.TrimSpace(got)))
	if g == want {
		return true
	}
	switch want {
	case CDCENS:
		return g == CDCINS
	case CDCENC:
		return g == CDCINC
	case CDCENG:
		return g == CDCING
	}
	return false
}
