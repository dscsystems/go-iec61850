package scl

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// LoadModel parses the SCL file at path and instantiates the runtime
// model of one IED. See BuildModel for the option semantics.
func LoadModel(path string, opts ...Option) (*model.Model, error) {
	s, err := ParseFile(path)
	if err != nil {
		return nil, err
	}
	return BuildModel(s, opts...)
}

// BuildModel instantiates the runtime model of one IED from a parsed SCL
// document: logical devices and nodes are expanded from the data type
// templates, DOI/SDI/DAI initial values are applied, and datasets and
// control blocks (including GSE/SMV addresses from the Communication
// section) are resolved.
//
// Initial values are applied per setting group (Val@sGroup) and per array
// element (DAI@sAddr, DOI/SDI@ix), and the group SettingControl declares
// active is the one the objects carry. What is not understood is recorded
// as a diagnostic on the model rather than failing the build, so a single
// unrecognised construct cannot make a whole IED unreadable; pass
// Strict(true) for the opposite behaviour.
//
// Remaining limitations, kept deliberately: Octet64 and EntryID values must
// be written as hexadecimal, a Timestamp must be RFC 3339, and report
// instances beyond those the configuration declares are not created.
func BuildModel(s *SCL, opts ...Option) (*model.Model, error) {
	var o buildOptions
	for _, opt := range opts {
		opt(&o)
	}
	d := &diag{opts: o.opts}
	d.addAll(s.Edition().validate("SCL"))
	for _, name := range s.DroppedNames() {
		for _, p := range s.Dropped()[name] {
			d.add(p, "element <"+name+"> is present in the document and is not "+
				"decoded, along with anything nested inside it")
		}
	}

	ied, err := findIED(s, o.ied)
	if err != nil {
		return nil, err
	}
	ap, err := findAP(ied, o.ap)
	if err != nil {
		return nil, err
	}
	if a := ap.Services; a != nil {
		if len(a.NameLength) > 0 {
			d.add(sprintf("SCL/IED[%s]/AccessPoint[%s]/Services", ied.Name, ap.Name),
				sprintf("nameLength=%s: the name-length limit is not enforced on "+
					"object references or item IDs", a.NameLength))
		}
		if a.SupSubscription != nil && (a.SupSubscription.MaxGo > 0 || a.SupSubscription.MaxSv > 0) {
			d.addf("SCL/IED[%s]/Services/SupSubscription", ied.Name,
				"subscription supervision is declared but not implemented")
		}
	}

	b := newBuilder(s, d)
	b.led = ied.Name
	m := &model.Model{Name: ied.Name}
	for i := range ap.Server.LDevices {
		lde := &ap.Server.LDevices[i]
		b.ledInst = lde.Inst
		ld := &model.LogicalDevice{Name: ied.Name + lde.Inst, Inst: lde.Inst}
		var lns []*LN
		if lde.LN0 != nil {
			lns = append(lns, lde.LN0)
		}
		for j := range lde.LNs {
			lns = append(lns, &lde.LNs[j])
		}
		for _, lne := range lns {
			// Diagnostics name the logical node as well as the object, so
			// a shared data type template does not report the same
			// attribute three times without saying where.
			prevLN := b.curLN
			b.curLN = lnName(lne)
			ln, err := b.buildLN(ied.Name, ap.Name, lde.Inst, lne)
			b.curLN = prevLN
			if err != nil {
				return nil, fmt.Errorf("scl: %s/%s: %w", ied.Name+lde.Inst, lnName(lne), err)
			}
			ld.Nodes = append(ld.Nodes, ln)
		}
		// The active setting group is declared once per logical device,
		// on LN0, and its values are spread over every node. Applying it
		// is therefore a whole-device step, after every node is built.
		for _, ln := range ld.Nodes {
			if ln.SettingControl != nil {
				b.applyActiveGroup(ld, ln.SettingControl.ActSG)
				break
			}
		}
		m.Devices = append(m.Devices, ld)
	}
	// Services/ConfReportControl@maxBuf is the device's report-buffer
	// capacity: apply it to the buffered blocks as their queue depth, so
	// the server buffers what the configuration says rather than its own
	// default. The access point's declaration wins over the IED's.
	if maxBuf := reportMaxBuf(ied, ap); maxBuf > 0 {
		for _, ld := range m.Devices {
			for _, ln := range ld.Nodes {
				for _, rc := range ln.ReportControls {
					if rc.Buffered && rc.MaxQueueSize == 0 {
						rc.MaxQueueSize = maxBuf
					}
				}
			}
		}
	}
	for _, g := range b.settingGroups() {
		m.SettingGroups = append(m.SettingGroups, model.SettingGroup{
			Number: g.Number, LD: g.LD, Values: g.Values,
		})
	}
	m.Diagnostics = d.all
	if err := d.err(); err != nil {
		return nil, err
	}
	return m, nil
}

// applyActiveGroup writes the values of setting group n onto the attributes
// they name, so the model serves the group the device declares active.
// Group 0 is the active group of Val elements that carried no sGroup,
// which buildDOI has already applied.
func (b *builder) applyActiveGroup(ld *model.LogicalDevice, n int) {
	if n <= 0 {
		return
	}
	for _, sv := range b.groupValues[n] {
		i := strings.IndexByte(sv.Path, '/')
		if i < 0 {
			continue
		}
		segs := strings.Split(sv.Path[i+1:], ".")
		if len(segs) < 2 {
			continue
		}
		ln := ld.Node(segs[0])
		if ln == nil {
			continue
		}
		da, ok := resolvePath(ln.Object(segs[1]), segs[2:])
		if !ok {
			continue
		}
		da.Value = sv.Value.Clone()
	}
}

// resolvePath walks the remaining segments of an attribute path from a data
// object, descending through sub-objects and structured attributes alike,
// and returns the leaf attribute the path names.
func resolvePath(do *model.DataObject, segs []string) (*model.DataAttribute, bool) {
	var da *model.DataAttribute
	for _, name := range segs {
		if da != nil {
			da = da.Child(name)
			if da == nil {
				return nil, false
			}
			continue
		}
		if do == nil {
			return nil, false
		}
		if sub := do.Child(name); sub != nil {
			do = sub
			continue
		}
		da = do.Attribute(name)
		if da == nil {
			return nil, false
		}
	}
	return da, da != nil
}

// settingGroups turns the recorded per-group values into setting groups,
// ordered by group number so the active group comes first.
func (b *builder) settingGroups() []model.SettingGroup {
	if len(b.groupValues) == 0 {
		return nil
	}
	nums := make([]int, 0, len(b.groupValues))
	for n := range b.groupValues {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	out := make([]model.SettingGroup, 0, len(nums))
	for _, n := range nums {
		g := model.SettingGroup{Number: n, Values: map[string]*mms.Value{}}
		for _, sv := range b.groupValues[n] {
			g.Values[sv.Path] = sv.Value
			if g.LD == "" {
				if i := strings.IndexByte(sv.Path, '/'); i >= 0 {
					g.LD = sv.Path[:i]
				}
			}
		}
		out = append(out, g)
	}
	return out
}

// reportMaxBuf returns the configured report-buffer capacity, zero if the
// document declares none.
func reportMaxBuf(ied *IED, ap *AccessPoint) int {
	for _, svc := range []*Services{ap.Services, ied.Services} {
		if svc != nil && svc.ConfReportControl != nil && svc.ConfReportControl.MaxBuf > 0 {
			return svc.ConfReportControl.MaxBuf
		}
	}
	return 0
}

func findIED(s *SCL, name string) (*IED, error) {
	if len(s.IEDs) == 0 {
		return nil, fmt.Errorf("scl: document contains no IED")
	}
	if name == "" {
		return &s.IEDs[0], nil
	}
	for i := range s.IEDs {
		if s.IEDs[i].Name == name {
			return &s.IEDs[i], nil
		}
	}
	return nil, fmt.Errorf("scl: IED %q not found", name)
}

func findAP(ied *IED, name string) (*AccessPoint, error) {
	for i := range ied.AccessPoints {
		ap := &ied.AccessPoints[i]
		if name != "" && ap.Name != name {
			continue
		}
		if ap.Server != nil {
			return ap, nil
		}
		if name != "" {
			return nil, fmt.Errorf("scl: access point %q of IED %q has no Server", name, ied.Name)
		}
	}
	if name != "" {
		return nil, fmt.Errorf("scl: access point %q not found in IED %q", name, ied.Name)
	}
	return nil, fmt.Errorf("scl: IED %q has no access point with a Server", ied.Name)
}

// knownCDCs reports whether this library has an attribute template for a
// common data class. A document using a class outside the table still
// loads: the SCL-supplied attributes are used as they are, and the class is
// reported as a diagnostic.
var knownCDCs = model.CDCName

func lnName(lne *LN) string {
	if lne.LNClass == "LLN0" {
		return "LLN0"
	}
	return lne.Prefix + lne.LNClass + lne.Inst
}

// builder resolves data type templates and remembers enum type bindings
// so that DAI values given as enum literal names can be applied.
type builder struct {
	scl            *SCL
	diag           *diag
	lnTypes        map[string]*LNodeType
	lnTypesByClass map[string]*LNodeType
	doTypes        map[string]*DOType
	daTypes        map[string]*DAType
	enums          map[string]*EnumType
	enumOf         map[*model.DataAttribute]string // Enum leaf -> EnumType id
	// groupValues collects the per-setting-group initial values of FC SG
	// and SE attributes, keyed by group number. Val elements carrying an
	// sGroup give one value per group; without it the value applies to the
	// active group only.
	groupValues map[int][]settingValue
	// curLN and curDO are the logical node and the dotted path of the data
	// object being built, for diagnostics.
	curLN string
	curDO string
	// led and ledInst are the IED name and logical-device instance
	// currently being built, so setting-group values are recorded against
	// a full reference.
	led     string
	ledInst string
}

// settingValue is one initial value of an FC SG or SE attribute, in a
// named setting group.
type settingValue struct {
	// Path is the reference of the attribute, e.g.
	// "SIMPLEIOLD0/GGIO1.AnIn1.setVal".
	Path  string
	Value *mms.Value
}

// ledRef is the name of the logical device being built, which is the MMS
// domain name: IED name plus the device instance.
func (b *builder) ledRef() string { return b.led + b.ledInst }

// ref joins a logical device name to an attribute path with the "/" that
// separates the two halves of an object reference.
func (b *builder) ref(path, name string) string {
	return b.ledRef() + "/" + joinPath(path, name)
}

func newBuilder(s *SCL, d *diag) *builder {
	b := &builder{
		scl:         s,
		diag:        d,
		lnTypes:     map[string]*LNodeType{},
		doTypes:     map[string]*DOType{},
		daTypes:     map[string]*DAType{},
		enums:       map[string]*EnumType{},
		enumOf:      map[*model.DataAttribute]string{},
		groupValues: map[int][]settingValue{},
	}
	if t := s.DataTypeTemplates; t != nil {
		// LNodeType identity is the pair (id, lnClass), so index both
		// ways: by id alone for the common case, and by id+class so a
		// document reusing an id across node classes still resolves.
		byClass := map[string]*LNodeType{}
		for i := range t.LNodeTypes {
			lt := &t.LNodeTypes[i]
			if _, dup := b.lnTypes[lt.ID]; !dup {
				b.lnTypes[lt.ID] = lt
			}
			byClass[lt.ID+"\x00"+lt.LNClass] = lt
		}
		b.lnTypesByClass = byClass
		for i := range t.DOTypes {
			b.doTypes[t.DOTypes[i].ID] = &t.DOTypes[i]
		}
		for i := range t.DATypes {
			b.daTypes[t.DATypes[i].ID] = &t.DATypes[i]
		}
		for i := range t.EnumTypes {
			b.enums[t.EnumTypes[i].ID] = &t.EnumTypes[i]
		}
	}
	return b
}

// lnType resolves a logical node type, preferring an exact (id, lnClass)
// match and falling back to the id alone.
func (b *builder) lnType(id, lnClass string) (*LNodeType, bool) {
	if lt, ok := b.lnTypesByClass[id+"\x00"+lnClass]; ok {
		return lt, true
	}
	lt, ok := b.lnTypes[id]
	return lt, ok
}

func (b *builder) buildLN(iedName, apName, ldInst string, lne *LN) (*model.LogicalNode, error) {
	lnt, ok := b.lnType(lne.LNType, lne.LNClass)
	if !ok {
		return nil, fmt.Errorf("LNodeType %q not found", lne.LNType)
	}
	ln := &model.LogicalNode{Name: lnName(lne), Class: lne.LNClass}
	for _, doe := range lnt.DOs {
		do, err := b.buildDO(doe.Name, doe.Type, 0)
		if err != nil {
			return nil, fmt.Errorf("DO %s: %w", doe.Name, err)
		}
		ln.Objects = append(ln.Objects, do)
	}

	// Apply instance values.
	for i := range lne.DOIs {
		doi := &lne.DOIs[i]
		do := ln.Object(doi.Name)
		if do == nil {
			if base, _, ok := splitArrayName(doi.Name); ok {
				do = ln.Object(base)
			}
		}
		if do == nil {
			return nil, fmt.Errorf("DOI %q has no matching DO in type %q", doi.Name, lne.LNType)
		}
		// A DOI with an ix addresses one element of an array-valued DO,
		// which the model holds as "Name(n)".
		if ix := strings.TrimSpace(doi.Ix); ix != "" {
			if n, ok := arrayIndex(ix); ok {
				if el := do.Child(fmt.Sprintf("%s(%d)", doi.Name, n)); el != nil {
					do = el
				} else {
					b.diag.addf(joinPath(lnName(lne), doi.Name), "DOI ix=%s addresses an "+
						"instance of %q that the type does not declare as an array", ix, doi.Name)
				}
			} else {
				b.diag.addf(joinPath(lnName(lne), doi.Name), "DOI ix=%q is not an "+
					"array index; the value is applied to the object as a whole", ix)
			}
		}
		if err := b.applyDOI(do, doi.DAIs, doi.SDIs, joinPath(lnName(lne), doi.Name)); err != nil {
			return nil, fmt.Errorf("DOI %s: %w", doi.Name, err)
		}
	}

	// Datasets.
	for i := range lne.DataSets {
		ds, err := buildDataSet(iedName, ldInst, &lne.DataSets[i])
		if err != nil {
			return nil, err
		}
		ln.DataSets = append(ln.DataSets, ds)
	}

	// Control blocks.
	for i := range lne.ReportControls {
		ln.ReportControls = append(ln.ReportControls, b.buildReportControl(&lne.ReportControls[i]))
	}
	for i := range lne.GSEControls {
		ln.GSEControls = append(ln.GSEControls, b.buildGSEControl(iedName, apName, ldInst, &lne.GSEControls[i]))
	}
	for i := range lne.SampledValueControls {
		ln.SVControls = append(ln.SVControls, b.buildSVControl(iedName, apName, ldInst, &lne.SampledValueControls[i]))
	}
	for i := range lne.LogControls {
		ln.LogControls = append(ln.LogControls, buildLogControl(&lne.LogControls[i]))
	}
	if sg := lne.SettingControl; sg != nil {
		ln.SettingControl = &model.SettingControl{
			NumOfSGs: sg.NumOfSGs, ActSG: sg.ActSG, ResvTms: sg.ResvTms,
		}
	}
	return ln, nil
}

// buildDO expands a DOType (and its SDOs, recursively) into a DataObject.
func (b *builder) buildDO(name, typeID string, depth int) (*model.DataObject, error) {
	if depth > 16 {
		return nil, fmt.Errorf("SDO nesting too deep at %q", typeID)
	}
	dot, ok := b.doTypes[typeID]
	if !ok {
		return nil, fmt.Errorf("DOType %q not found", typeID)
	}
	prevDO := b.curDO
	b.curDO = joinPath(prevDO, name)
	defer func() { b.curDO = prevDO }()

	do := &model.DataObject{Name: name, CDC: dot.CDC}
	if dot.CDC != "" && !knownCDCs(dot.CDC) {
		b.diag.addf(b.path(name), "common data class %q is not one this library has "+
			"attribute templates for; the SCL-provided attributes are used as they are", dot.CDC)
	}
	for i := range dot.DAs {
		dae := &dot.DAs[i]
		da, err := b.buildDA(dae.Name, dae.FC, dae.BType, dae.Type, dae.Count, trgOpsOfDA(dae), dae.Vals, 0)
		if err != nil {
			return nil, fmt.Errorf("DA %s: %w", dae.Name, err)
		}
		do.Attributes = append(do.Attributes, da)
	}
	for i := range dot.SDOs {
		sdo := &dot.SDOs[i]
		sub, err := b.buildDO(sdo.Name, sdo.Type, depth+1)
		if err != nil {
			return nil, fmt.Errorf("SDO %s: %w", sdo.Name, err)
		}
		// An SDO with a count is an array: the sub-object is repeated,
		// which is how multi-instance data objects such as PhsA are
		// expressed, and how a DO with a count reaches the model at all.
		if n, isArray, tooBig := arrayCount(sdo.Count); tooBig {
			b.diag.addf(b.path(sdo.Name), "count=%q is beyond the %d-element limit "+
				"this library will allocate; no instances were created",
				sdo.Count, maxArrayCount)
			continue
		} else if isArray {
			for ix := 1; ix <= n; ix++ {
				do.Objects = append(do.Objects, cloneDO(sub, fmt.Sprintf("%s(%d)", sdo.Name, ix)))
			}
			continue
		}
		do.Objects = append(do.Objects, sub)
	}
	return do, nil
}

// trgOpsOfDA reads the trigger options of a DA or BDA. All three default
// to false in the schema, so an absent attribute means "no trigger".
func trgOpsOfDA(dae *DA) model.TrgOps {
	var trg model.TrgOps
	if dae.Dchg {
		trg |= model.TrgDataChange
	}
	if dae.Qchg {
		trg |= model.TrgQualityChange
	}
	if dae.Dupd {
		trg |= model.TrgDataUpdate
	}
	return trg
}

// trgOpsOfBDA reads the trigger options of a BDA. Members inherit the
// options of the enclosing DA, which are carried in trg.
func trgOpsOfBDA(bda *BDA, inherited model.TrgOps) model.TrgOps {
	trg := inherited
	if bda.Dchg {
		trg |= model.TrgDataChange
	}
	if bda.Qchg {
		trg |= model.TrgQualityChange
	}
	if bda.Dupd {
		trg |= model.TrgDataUpdate
	}
	return trg
}

// cloneDO deep-copies a data object under a new name, so that the instances
// of an array have independent values.
func cloneDO(src *model.DataObject, name string) *model.DataObject {
	dst := &model.DataObject{Name: name, CDC: src.CDC}
	for _, a := range src.Attributes {
		dst.Attributes = append(dst.Attributes, cloneDA(a, a.Name))
	}
	for _, s := range src.Objects {
		dst.Objects = append(dst.Objects, cloneDO(s, s.Name))
	}
	return dst
}

func cloneDA(src *model.DataAttribute, name string) *model.DataAttribute {
	dst := &model.DataAttribute{
		Name: name, FC: src.FC, FCName: src.FCName, Kind: src.Kind,
		BType: src.BType, Count: src.Count, TrgOps: src.TrgOps,
	}
	if src.Value != nil {
		dst.Value = src.Value.Clone()
	}
	for _, c := range src.Children {
		dst.Children = append(dst.Children, cloneDA(c, c.Name))
	}
	return dst
}

// arrayCount parses a count attribute. The schema type is a union of
// xs:unsignedInt and an enumeration literal, so a non-numeric count is
// legal and means "not an array". tooBig reports a numeric count beyond
// maxArrayCount, which is a corrupt or hostile value rather than a
// legitimate one.
func arrayCount(count string) (n int, isArray, tooBig bool) {
	v, err := strconv.Atoi(strings.TrimSpace(count))
	if err != nil || v <= 0 {
		return 0, false, false
	}
	if v > maxArrayCount {
		return 0, false, true
	}
	return v, true, false
}

// maxArrayCount bounds an array the document asks for, so a corrupt or
// hostile count cannot make the loader allocate without limit. It is well
// above anything a real device declares.
const maxArrayCount = 1 << 16

// buildDA expands one DA or BDA. fcRaw is the functional-constraint
// mnemonic as written, which is kept alongside the parsed FC so an unknown
// one is still usable. Arrays of basic types get an array value with
// per-element defaults; arrays of constructed types keep Count with a nil
// value.
func (b *builder) buildDA(name, fcRaw, bType, typeID, count string, trg model.TrgOps, vals []Val, depth int) (*model.DataAttribute, error) {
	if depth > 16 {
		return nil, fmt.Errorf("attribute nesting too deep at %q", name)
	}
	fc := model.ParseFCLenient(fcRaw)
	if fc == model.FCUnknown {
		b.diag.addf(b.path(name), "functional constraint %q on DA %s is not one this "+
			"library knows; it is carried verbatim and the attribute is readable under it",
			fcRaw, name)
	}
	da := &model.DataAttribute{Name: name, FC: fc, FCName: fcRaw, BType: bType, TrgOps: trg}
	n, isArray, tooBig := arrayCount(count)
	if tooBig {
		b.diag.addf(b.path(name), "count=%q is beyond the %d-element limit this "+
			"library will allocate; the attribute is present but has no elements",
			count, maxArrayCount)
	}

	if bType == "Struct" {
		dat, ok := b.daTypes[typeID]
		if !ok {
			// Without the type template the structure's members are
			// unknown, but the object still exists; record it and leave
			// it valueless rather than failing the whole load.
			b.diag.addf(b.path(name), "DAType %q of structured DA %s not found; "+
				"the structure is present but has no members", typeID, name)
			da.Kind = mms.TypeStructure
			return da, nil
		}
		da.Kind = mms.TypeStructure
		for i := range dat.BDAs {
			bda := &dat.BDAs[i]
			// A DA's trigger options cover all its components: a change
			// to mag.f is a change of mag (IEC 61850-7-2).
			child, err := b.buildDA(bda.Name, fcRaw, bda.BType, bda.Type, bda.Count,
				trgOpsOfBDA(bda, trg), bda.Vals, depth+1)
			if err != nil {
				return nil, fmt.Errorf("BDA %s: %w", bda.Name, err)
			}
			da.Children = append(da.Children, child)
		}
		if isArray {
			da.Kind = mms.TypeArray
			da.Count = n
		}
		return da, nil
	}

	kind, known := kindOf(bType)
	if !known {
		b.diag.addf(b.path(name), "basic type %q of DA %s is not in the "+
			"IEC 61850-8-1 type enumeration; the attribute has no value until one is written",
			bType, name)
		da.Kind = mms.TypeNone
		return da, nil
	}
	if bType == "Enum" {
		b.enumOf[da] = typeID
	}
	if isArray {
		da.Kind = mms.TypeArray
		da.Count = n
		elems := make([]*mms.Value, n)
		for i := range elems {
			elems[i] = defaultValue(kind, bType)
		}
		da.Value = mms.NewArray(elems...)
		return da, nil
	}
	da.Kind = kind
	da.Value = defaultValue(kind, bType)
	if len(vals) > 0 {
		if err := b.setValue(da, vals[0].Value); err != nil {
			return nil, err
		}
	}
	return da, nil
}

// path builds a diagnostic path from the attribute name being built.
func (b *builder) path(name string) string {
	return joinPath(joinPath(b.curLN, b.curDO), name)
}

func joinPath(prefix, name string) string {
	switch {
	case prefix == "":
		return name
	case name == "":
		return prefix
	}
	return prefix + "." + name
}

// kindOf maps an SCL basic type name to an MMS value type. The full
// tPredefinedBasicTypeEnum of IEC 61850-8-1 is covered, so a document that
// uses a type this library has not seen does not fail the load: unknown
// types yield TypeNone and a diagnostic, and the attribute stays in the
// tree so that datasets, report control blocks and control models which
// name it still resolve.
func kindOf(bType string) (mms.Type, bool) {
	switch bType {
	case "BOOLEAN":
		return mms.TypeBoolean, true
	case "INT8", "INT16", "INT24", "INT32", "INT64", "INT128", "Enum",
		"DACount":
		return mms.TypeInteger, true
	case "INT8U", "INT16U", "INT24U", "INT32U", "INT64U":
		return mms.TypeUnsigned, true
	case "FLOAT32":
		return mms.TypeFloat32, true
	case "FLOAT64":
		return mms.TypeFloat64, true
	case "VisString32", "VisString64", "VisString65", "VisString129",
		"VisString255", "ObjRef", "Currency":
		return mms.TypeVisibleString, true
	case "Unicode255":
		return mms.TypeMMSString, true
	case "Octet6", "Octet16", "Octet64", "EntryID", "PhyComAddr":
		return mms.TypeOctetString, true
	case "Quality", "Dbpos", "Tcmd", "Check", "TrgOps", "OptFlds",
		"SvOptFlds", "LogOptFlds":
		return mms.TypeBitString, true
	case "Timestamp":
		return mms.TypeUTCTime, true
	case "EntryTime":
		return mms.TypeBinaryTime, true
	}
	return mms.TypeNone, false
}

// bitLenOf returns the bit-string width of a bit-string basic type. The
// widths are fixed by IEC 61850-8-1; the default covers the remaining
// bit-string types of the enumeration.
func bitLenOf(bType string) int {
	switch bType {
	case "Quality":
		return 13
	case "Dbpos", "Tcmd", "Check":
		return 2
	case "TrgOps":
		return 6
	case "OptFlds", "SvOptFlds", "LogOptFlds":
		return 10
	}
	return 8
}

// defaultValue returns a served default for a leaf attribute: zero of the
// basic type, an all-clear Quality, or the Unix epoch for timestamps.
func defaultValue(kind mms.Type, bType string) *mms.Value {
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
		if bType == "Quality" {
			return model.QualityGood.Value()
		}
		return mms.NewBitString(bitLenOf(bType))
	case mms.TypeUTCTime:
		return mms.NewUTCTime(time.Unix(0, 0).UTC(), 0)
	case mms.TypeBinaryTime:
		return mms.NewBinaryTime(time.Unix(0, 0).UTC())
	}
	return nil
}

// setValue parses an SCL Val string into the attribute's value.
func (b *builder) setValue(da *model.DataAttribute, raw string) error {
	s := strings.TrimSpace(raw)
	fail := func(err error) error {
		return fmt.Errorf("value %q for %s (%s): %w", s, da.Name, da.BType, err)
	}
	if da.BType == "Enum" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			da.Value = mms.NewInt64(v)
			return nil
		}
		et := b.enums[b.enumOf[da]]
		if et != nil {
			for _, ev := range et.EnumVals {
				if strings.TrimSpace(ev.Name) == s {
					da.Value = mms.NewInt64(int64(ev.Ord))
					return nil
				}
			}
		}
		return fail(fmt.Errorf("unknown enum literal"))
	}
	switch da.Kind {
	case mms.TypeBoolean:
		v, err := strconv.ParseBool(s)
		if err != nil {
			return fail(err)
		}
		da.Value = mms.NewBool(v)
	case mms.TypeInteger:
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fail(err)
		}
		da.Value = mms.NewInt64(v)
	case mms.TypeUnsigned:
		v, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return fail(err)
		}
		da.Value = mms.NewUint32(uint32(v))
	case mms.TypeFloat32:
		v, err := strconv.ParseFloat(s, 32)
		if err != nil {
			return fail(err)
		}
		da.Value = mms.NewFloat32(float32(v))
	case mms.TypeFloat64:
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fail(err)
		}
		da.Value = mms.NewFloat64(v)
	case mms.TypeVisibleString:
		da.Value = mms.NewVisibleString(s)
	case mms.TypeMMSString:
		da.Value = mms.NewMMSString(s)
	case mms.TypeOctetString:
		bts, err := hex.DecodeString(s)
		if err != nil {
			return fail(err)
		}
		da.Value = mms.NewOctetString(bts)
	case mms.TypeBitString:
		v := mms.NewBitString(bitLenOf(da.BType))
		for i, c := range s {
			if i >= v.BitLen() || (c != '0' && c != '1') {
				return fail(fmt.Errorf("expected a %d-bit binary string", v.BitLen()))
			}
			v.SetBit(i, c == '1')
		}
		da.Value = v
	case mms.TypeUTCTime:
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return fail(err)
		}
		da.Value = mms.NewUTCTime(t, 0)
	default:
		return fail(fmt.Errorf("cannot apply Val to kind %v", da.Kind))
	}
	return nil
}

// applyDOI walks DAI/SDI elements below a data object. An SDI names
// either a sub data object or a structured data attribute. path is the
// dotted path of do, for diagnostics and for setting-group values.
func (b *builder) applyDOI(do *model.DataObject, dais []DAI, sdis []SDI, path string) error {
	for i := range dais {
		dai := &dais[i]
		da := do.Attribute(dai.Name)
		if da == nil {
			// Array members are named "AnIn(2)" in the model but the
			// DAI may address the whole array by its base name.
			if da = arrayAttr(do, dai.Name); da == nil {
				return fmt.Errorf("DAI %q has no matching DA", dai.Name)
			}
		}
		b.applyVals(da, dai, path)
	}
	for i := range sdis {
		sdi := &sdis[i]
		if sub := b.sdiTarget(do, sdi, path); sub != nil {
			if err := b.applyDOI(sub, sdi.DAIs, sdi.SDIs, joinPath(path, sub.Name)); err != nil {
				return fmt.Errorf("SDI %s: %w", sdi.Name, err)
			}
			continue
		}
		if da := do.Attribute(sdi.Name); da != nil {
			if err := b.applySDIonDA(da, sdi, joinPath(path, sdi.Name)); err != nil {
				return fmt.Errorf("SDI %s: %w", sdi.Name, err)
			}
			continue
		}
		return fmt.Errorf("SDI %q matches neither an SDO nor a DA", sdi.Name)
	}
	return nil
}

// sdiTarget resolves an SDI to the sub-object or structured attribute it
// addresses. An SDI naming an array-valued sub-object without its index
// selects the first element, which is what SDI@ix overrides.
func (b *builder) sdiTarget(do *model.DataObject, sdi *SDI, path string) *model.DataObject {
	if sub := do.Child(sdi.Name); sub != nil {
		return sub
	}
	// "phsA" with an ix of n addresses "phsA(n)"; without one, the first.
	if _, _, indexed := splitArrayName(sdi.Name); !indexed {
		n := 1
		ix := strings.TrimSpace(sdi.Ix)
		if ix != "" {
			if v, ok := arrayIndex(ix); ok {
				n = v
			} else {
				b.diag.addf(joinPath(path, sdi.Name), "SDI ix=%q is not an array "+
					"index; the first element is used", sdi.Ix)
			}
		}
		if el := do.Child(fmt.Sprintf("%s(%d)", sdi.Name, n)); el != nil {
			return el
		} else if ix != "" {
			b.diag.addf(joinPath(path, sdi.Name), "SDI ix=%s addresses element %d of "+
				"%q, which the type does not declare as an array", ix, n, sdi.Name)
			return nil
		}
	}
	return nil
}

// applyVals applies the Val elements of a DAI, honouring the sAddr
// sub-address and the sGroup setting group. vals selects the elements that
// apply here: the first one when sAddr does not narrow it to an element.
func (b *builder) applyVals(da *model.DataAttribute, dai *DAI, path string) {
	// An sAddr names an element of an array attribute, or a member of a
	// structure; a DAI without one applies to the whole attribute.
	elem := -1
	if s := strings.TrimSpace(dai.SAddr); s != "" {
		if da.Kind != mms.TypeArray {
			b.diag.addf(joinPath(path, da.Name), "DAI sAddr=%q is given, but %s is "+
				"not an array; the value is applied to the whole attribute", dai.SAddr, da.Name)
		} else if n, ok := arrayIndex(s); ok && n >= 1 && n <= da.Count {
			elem = n - 1
		} else {
			b.diag.addf(joinPath(path, da.Name), "DAI sAddr=%q does not select an "+
				"element of the %d-element array %s", dai.SAddr, da.Count, da.Name)
		}
	}
	for i := range dai.Vals {
		v := &dai.Vals[i]
		if elem >= 0 {
			if arr := da.Value; arr != nil {
				cur := arr.Index(elem)
				if cur == nil {
					b.diag.addf(joinPath(path, da.Name), "sAddr %q does not select an "+
						"element of the %d-element array", dai.SAddr, da.Count)
					continue
				}
				tmp := &model.DataAttribute{
					Name: da.Name, FC: da.FC, FCName: da.FCName,
					Kind: cur.Type(), BType: da.BType, TrgOps: da.TrgOps,
				}
				if err := b.setValue(tmp, v.Value); err != nil {
					b.diag.add(joinPath(path, da.Name), err.Error())
					continue
				}
				arr.SetIndex(elem, tmp.Value)
			}
			continue
		}
		// The value is applied to the attribute itself, because that is
		// what resolves an enum literal against its EnumType. A Val
		// carrying an sGroup other than the active one is then rolled
		// back, leaving only the per-group record.
		group := b.groupOf(v.SGroup)
		prev := da.Value
		if err := b.setValue(da, v.Value); err != nil {
			b.diag.add(joinPath(path, da.Name), err.Error())
			continue
		}
		if group > 0 {
			if da.FC == model.SG || da.FC == model.SE {
				key := b.ref(path, da.Name)
				b.groupValues[group] = append(b.groupValues[group], settingValue{
					Path:  key,
					Value: da.Value.Clone(),
				})
			}
			da.Value = prev
		}
	}
}

// groupOf resolves an sGroup attribute to a group number. A Val without
// sGroup applies to the active group, numbered 0. A group number that is
// not a plain integer is reported and ignored.
func (b *builder) groupOf(sGroup string) int {
	s := strings.TrimSpace(sGroup)
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 255 {
		b.diag.addf("", "Val sGroup=%q is not a setting-group number (0..255); "+
			"the value is applied to the active group only", sGroup)
		return 0
	}
	return n
}

// arrayAttr returns the attribute an array base name refers to, so a DAI
// naming "AnIn" reaches "AnIn(1)".
func arrayAttr(do *model.DataObject, name string) *model.DataAttribute {
	if base, _, ok := splitArrayName(name); ok {
		return do.Attribute(base)
	}
	return nil
}

// parseIndex reads an array index and returns it zero-based, as SCL array
// indices are one-based.
func parseIndex(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n - 1, err == nil && n > 0
}

// arrayIndex reads an SCL array index (the ix attribute of a DOI, SDI, DAI
// or FCDA) as a one-based element number.
//
// The base of ix is not settled by the standard: IEC 61850-6 TISSUE 1808
// asks the question, and both spellings occur in files from different
// tools. Treating 0 as the first element is the only reading under which
// both work, so it is what this does: ix=0 and ix=1 both name element one,
// and an ix of n names element n for n above one. An ix that cannot be a
// one-based index at all is reported.
func arrayIndex(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0, false
	}
	if n == 0 {
		return 1, true
	}
	return n, true
}

// splitArrayName splits "AnIn(3)" into "AnIn" and 3.
func splitArrayName(s string) (base string, index int, ok bool) {
	i := strings.LastIndex(s, "(")
	if i < 0 || !strings.HasSuffix(s, ")") {
		return s, 0, false
	}
	n, err := strconv.Atoi(s[i+1 : len(s)-1])
	if err != nil || n <= 0 {
		return s, 0, false
	}
	return s[:i], n, true
}

func (b *builder) applySDIonDA(da *model.DataAttribute, sdi *SDI, path string) error {
	for i := range sdi.DAIs {
		dai := &sdi.DAIs[i]
		c := da.Child(dai.Name)
		if c == nil {
			return fmt.Errorf("DAI %q has no matching member", dai.Name)
		}
		b.applyVals(c, dai, path)
	}
	for i := range sdi.SDIs {
		sub := &sdi.SDIs[i]
		c := da.Child(sub.Name)
		if c == nil {
			return fmt.Errorf("SDI %q has no matching member", sub.Name)
		}
		if err := b.applySDIonDA(c, sub, joinPath(path, sub.Name)); err != nil {
			return fmt.Errorf("SDI %s: %w", sub.Name, err)
		}
	}
	return nil
}

// buildDataSet resolves FCDA entries to object references. Array index
// notation in doName/daName (e.g. "phsA(2)") is passed through verbatim,
// and FCDA@ix is the Ed 2 alternative that names the same instance
// numerically.
func buildDataSet(iedName, ldInst string, dse *DataSet) (*model.DataSet, error) {
	ds := &model.DataSet{Name: dse.Name}
	for _, f := range dse.FCDAs {
		fc := model.ParseFCLenient(f.FC)
		if fc == model.FCUnknown {
			// Carried verbatim: a dataset under a constraint this library
			// does not know still resolves and still reports.
		}
		li := f.LDInst
		if li == "" {
			li = ldInst
		}
		ln := f.Prefix + f.LNClass + f.LNInst
		if f.LNClass == "LLN0" {
			ln = "LLN0"
		}
		doName, daName := f.DOName, f.DAName
		if ix := strings.TrimSpace(f.Ix); ix != "" {
			// ix selects an element of the innermost array the member
			// names. Where the member names an attribute — the usual case
			// when the array is an attribute array — the index goes there;
			// otherwise it goes on the data object.
			if n, ok := arrayIndex(ix); ok {
				target := &doName
				if daName != "" {
					target = &daName
				}
				if *target != "" {
					if _, _, already := splitArrayName(*target); !already {
						*target = fmt.Sprintf("%s(%d)", *target, n)
					}
				}
			}
		}
		ref := iedName + li + "/" + ln
		if doName != "" {
			ref += "." + doName
		}
		if daName != "" {
			ref += "." + daName
		}
		r, err := model.ParseRef(ref)
		if err != nil {
			return nil, fmt.Errorf("dataset %s: %w", dse.Name, err)
		}
		ds.Entries = append(ds.Entries, model.FCDA{Ref: r, FC: fc, FCName: f.FC})
	}
	return ds, nil
}

// maxRCBInstances is how many instances of one indexed report control
// block the server names. IEC 61850-6 defines the two-digit suffix
// "01".."99"; a document asking for more would need names the standard
// does not define, so the count is capped.
const maxRCBInstances = 99

func (b *builder) buildReportControl(r *ReportControl) *model.ReportControl {
	rc := &model.ReportControl{
		Name:     r.Name,
		RptID:    r.RptID,
		DataSet:  r.DatSet,
		ConfRev:  r.ConfRev,
		Buffered: r.Buffered,
		BufTime:  r.BufTime,
		IntgPd:   r.IntgPd,
		TrgOps:   trgOpsOf(r.TrgOps),
	}
	rc.RptEnabled = 1
	if r.RptEnab != nil && r.RptEnab.Max > 0 {
		rc.RptEnabled = r.RptEnab.Max
	}
	// IEC 61850-6: an unindexed block is a single instance under its own
	// name, whatever RptEnabled says.
	if ix := strings.TrimSpace(r.Indexed); ix == "false" || ix == "0" {
		rc.NotIndexed = true
		rc.RptEnabled = 1
	}
	if rc.RptEnabled > maxRCBInstances {
		b.diag.addf("ReportControl "+r.Name, "RptEnabled max=%d exceeds the %d "+
			"two-digit instance names IEC 61850-6 defines; capped", rc.RptEnabled, maxRCBInstances)
		rc.RptEnabled = maxRCBInstances
	}
	if r.RptEnab != nil && len(r.RptEnab.ClientLN) > 0 {
		b.diag.addf("ReportControl "+r.Name, "%d ClientLN reservation(s) are declared but "+
			"pre-reserved instances are not implemented", len(r.RptEnab.ClientLN))
	}
	if of := r.OptFields; of != nil {
		// bufOvfl defaults to true in the schema, so absence means on.
		set := func(s string, def bool, f model.OptFlds) {
			if boolAttr(s, def) {
				rc.OptFlds |= f
			}
		}
		set(of.SeqNum, false, model.OptSeqNum)
		set(of.TimeStamp, false, model.OptTimeOfEntry)
		set(of.ReasonCode, false, model.OptReasonCode)
		set(of.DataSet, false, model.OptDataSetName)
		set(of.DataRef, false, model.OptDataRef)
		set(of.BufOvfl, true, model.OptBufOvfl)
		set(of.EntryID, false, model.OptEntryID)
		set(of.ConfigRef, false, model.OptConfRev)
		set(of.Segmentation, false, model.OptSegmentation)
	}
	// The Ed 1 per-block buffer depth, superseded in Ed 2 by the device-wide
	// Services/ConfReportControl@maxBuf. Honoured when present so an Ed 1
	// file keeps its configured depth.
	if r.BufDepth > 0 && r.Buffered {
		rc.MaxQueueSize = r.BufDepth
	}
	return rc
}

// trgOpsOf converts a TrgOps element. Per the schema, gi defaults to true
// (also when the element is absent).
func trgOpsOf(t *TrgOps) model.TrgOps {
	if t == nil {
		return model.TrgGI
	}
	var ops model.TrgOps
	if t.Dchg {
		ops |= model.TrgDataChange
	}
	if t.Qchg {
		ops |= model.TrgQualityChange
	}
	if t.Dupd {
		ops |= model.TrgDataUpdate
	}
	if t.Period {
		ops |= model.TrgIntegrity
	}
	if boolAttr(t.GI, true) {
		ops |= model.TrgGI
	}
	return ops
}

// buildGSEControl instantiates a GOOSE control block. Type selects the
// legacy GSSE variant, and Protocol names the transmission profile:
// "R-GOOSE" for routable GOOSE, which this library reports but does not
// implement.
func (b *builder) buildGSEControl(iedName, apName, ldInst string, g *GSEControl) *model.GSEControl {
	gc := &model.GSEControl{
		Name:    g.Name,
		GoID:    g.AppID,
		DataSet: g.DatSet,
		ConfRev: g.ConfRev,
		Type:    gsTypeOf(g.Type),
	}
	if gc.GoID == "" {
		gc.GoID = g.Name
	}
	if t := gc.Type; t != model.GOOSE {
		b.diag.addf("GSEControl "+g.Name, "type=%q is a legacy or vendor GOOSE variant; "+
			"it is configured as a plain GOOSE control block", g.Type)
	}
	if p := protocolOf(g.Protocol); p != "" {
		gc.Protocol = p
		if p == "R-GOOSE" {
			b.diag.addf("GSEControl "+g.Name, "Protocol is R-GOOSE: routable GOOSE "+
				"requires the IEC 61850-90-5 session and security profile, which is not "+
				"implemented; the block is treated as plain GOOSE")
		}
	}
	if gse := findGSE(b.scl, iedName, apName, ldInst, g.Name); gse != nil {
		gc.DstMAC, gc.AppID, gc.VLANID, gc.VLANPri = addressOf(gse.Address)
		gc.MinTime = durMS(gse.MinTime)
		gc.MaxTime = durMS(gse.MaxTime)
		gc.FixedOffs = durMS(gse.FixedOffs)
	}
	return gc
}

// gsTypeOf maps the type attribute of a GSEControl to a model type.
func gsTypeOf(t string) model.GSType {
	switch strings.ToUpper(strings.TrimSpace(t)) {
	case "", "GOOSE":
		return model.GOOSE
	case "GSSE":
		return model.GSSE
	}
	return model.GOOSE
}

// protocolOf returns the value of a Protocol element, which is a text node
// in the namespace of the transmission profile.
func protocolOf(p *Protocol) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(p.Value)
}

// buildSVControl instantiates a sampled-value control block, including the
// Ed 2 SmvOpts optional-field set and the sample mode. R-SV is reported and
// treated as plain multicast SV.
func (b *builder) buildSVControl(iedName, apName, ldInst string, s *SampledValueControl) *model.SVControl {
	sc := &model.SVControl{
		Name:      s.Name,
		SvID:      s.SmvID,
		DataSet:   s.DatSet,
		ConfRev:   s.ConfRev,
		SmpRate:   s.SmpRate,
		NoASDU:    s.NofASDU,
		Multicast: boolAttr(s.Multicast, true),
		SmpMod:    smpModOf(s.SmpMod),
	}
	if p := protocolOf(s.Protocol); p != "" {
		sc.Protocol = p
		if p == "R-SV" {
			b.diag.addf("SampledValueControl "+s.Name, "Protocol is R-SV: routable "+
				"sampled values require the IEC 61850-90-5 session and security profile, "+
				"which is not implemented; the block is treated as plain SV")
		}
	}
	if o := s.SmvOpts; o != nil {
		sc.Opts.RefreshTime = boolAttr(o.RefreshTime, false)
		sc.Opts.SampleSynchronized = boolAttr(o.SampleSynchronized, false)
		sc.Opts.SampleRate = boolAttr(o.SampleRate, false)
		sc.Opts.DataSet = boolAttr(o.DataSet, false)
		sc.Opts.Security = boolAttr(o.Security, false)
		sc.Opts.Timestamp = boolAttr(o.Timestamp, false)
		sc.Opts.SynchSourceID = boolAttr(o.SynchSourceId, false)
	}
	if smv := findSMV(b.scl, iedName, apName, ldInst, s.Name); smv != nil {
		sc.DstMAC, sc.AppID, sc.VLANID, sc.VLANPri = addressOf(smv.Address)
	}
	return sc
}

// smpModOf maps the smpMod attribute, defaulting to SmpPerPeriod.
func smpModOf(s string) model.SmpMod {
	switch SmpMod(strings.TrimSpace(s)) {
	case SmpPerSec:
		return model.SmpPerSec
	case SecPerSmp:
		return model.SecPerSmp
	}
	return model.SmpPerPeriod
}

func buildLogControl(l *LogControl) *model.LogControl {
	return &model.LogControl{
		Name:       l.Name,
		DataSet:    l.DatSet,
		LogName:    l.LogName,
		TrgOps:     trgOpsOf(l.TrgOps),
		IntgPd:     l.IntgPd,
		LogEna:     boolAttr(l.LogEna, true),
		BufTime:    l.BufTime,
		ReasonCode: boolAttr(l.ReasonCode, true),
	}
}

// boolAttr parses an optional boolean attribute with a schema default.
func boolAttr(s string, def bool) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return v
}

// findGSE locates the Communication GSE entry for a control block,
// preferring the exact access point and falling back to any access point
// of the IED.
func findGSE(s *SCL, iedName, apName, ldInst, cbName string) *GSE {
	var fallback *GSE
	if s.Communication == nil {
		return nil
	}
	for i := range s.Communication.SubNetworks {
		sn := &s.Communication.SubNetworks[i]
		for j := range sn.ConnectedAPs {
			cap := &sn.ConnectedAPs[j]
			if cap.IEDName != iedName {
				continue
			}
			for k := range cap.GSEs {
				g := &cap.GSEs[k]
				if g.CBName != cbName || (g.LDInst != "" && g.LDInst != ldInst) {
					continue
				}
				if cap.APName == apName {
					return g
				}
				if fallback == nil {
					fallback = g
				}
			}
		}
	}
	return fallback
}

func findSMV(s *SCL, iedName, apName, ldInst, cbName string) *SMV {
	var fallback *SMV
	if s.Communication == nil {
		return nil
	}
	for i := range s.Communication.SubNetworks {
		sn := &s.Communication.SubNetworks[i]
		for j := range sn.ConnectedAPs {
			cap := &sn.ConnectedAPs[j]
			if cap.IEDName != iedName {
				continue
			}
			for k := range cap.SMVs {
				v := &cap.SMVs[k]
				if v.CBName != cbName || (v.LDInst != "" && v.LDInst != ldInst) {
					continue
				}
				if cap.APName == apName {
					return v
				}
				if fallback == nil {
					fallback = v
				}
			}
		}
	}
	return fallback
}

// addressOf extracts MAC, APPID and VLAN parameters from an Address.
// APPID and VLAN-ID are hexadecimal per IEC 61850-6; VLAN-PRIORITY is
// decimal. Unparseable parameters are left zero.
func addressOf(a *Address) (mac [6]byte, appID, vlanID uint16, prio uint8) {
	if a == nil {
		return
	}
	get := func(name string) (string, bool) {
		for _, p := range a.Ps {
			if p.Type == name || p.Type == "tP_"+name {
				return strings.TrimSpace(p.Value), true
			}
		}
		return "", false
	}
	if s, ok := get("MAC-Address"); ok {
		if m, err := parseMAC(s); err == nil {
			mac = m
		}
	}
	if s, ok := get("APPID"); ok {
		if v, err := strconv.ParseUint(s, 16, 16); err == nil {
			appID = uint16(v)
		}
	}
	if s, ok := get("VLAN-ID"); ok {
		if v, err := strconv.ParseUint(s, 16, 12); err == nil {
			vlanID = uint16(v)
		}
	}
	if s, ok := get("VLAN-PRIORITY"); ok {
		if v, err := strconv.ParseUint(s, 10, 3); err == nil {
			prio = uint8(v)
		}
	}
	return
}

// AddressP returns the value of one address parameter, for a caller that
// needs a parameter the model does not carry. The P types of an access
// point include the IP address, the OSI presentation and session selectors
// and the MMS port, none of which the object model needs.
func (a *Address) Param(name string) (string, bool) {
	if a == nil {
		return "", false
	}
	for _, p := range a.Ps {
		if p.Type == name || p.Type == "tP_"+name {
			return strings.TrimSpace(p.Value), true
		}
	}
	return "", false
}

// IP returns the IPv4 address of the access point, if the document declares
// one. The value may carry a prefix length ("192.168.1.10/24").
func (ca *ConnectedAP) IP() (string, bool) {
	s, ok := ca.Address.Param("IP")
	if !ok {
		return "", false
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s, s != ""
}

// parseMAC parses "01-0C-CD-01-00-01" (or colon-separated) MAC addresses.
func parseMAC(s string) ([6]byte, error) {
	var mac [6]byte
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == ':' })
	if len(parts) != 6 {
		return mac, fmt.Errorf("scl: bad MAC address %q", s)
	}
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return mac, fmt.Errorf("scl: bad MAC address %q: %w", s, err)
		}
		mac[i] = byte(v)
	}
	return mac, nil
}

// durMS interprets a MinTime/MaxTime element as milliseconds.
func durMS(d *DurUnits) uint32 {
	if d == nil {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(d.Value), 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}
