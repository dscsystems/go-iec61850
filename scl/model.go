package scl

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Option adjusts model instantiation.
type Option func(*buildOptions)

type buildOptions struct {
	ied string
	ap  string
}

// ForIED selects the IED to instantiate; the default is the first IED in
// the document.
func ForIED(name string) Option { return func(o *buildOptions) { o.ied = name } }

// WithAccessPoint selects the access point of the chosen IED; the default
// is the first access point that contains a Server.
func WithAccessPoint(name string) Option { return func(o *buildOptions) { o.ap = name } }

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
// Limitations, kept deliberately: only the first Val of a DAI is applied
// (setting-group specific values are ignored), array elements cannot be
// addressed by DAI, Octet64 values must be hexadecimal, and log/report
// instances beyond configuration are not created here.
func BuildModel(s *SCL, opts ...Option) (*model.Model, error) {
	var o buildOptions
	for _, opt := range opts {
		opt(&o)
	}

	ied, err := findIED(s, o.ied)
	if err != nil {
		return nil, err
	}
	ap, err := findAP(ied, o.ap)
	if err != nil {
		return nil, err
	}

	b := newBuilder(s)
	m := &model.Model{Name: ied.Name}
	for i := range ap.Server.LDevices {
		lde := &ap.Server.LDevices[i]
		ld := &model.LogicalDevice{Name: ied.Name + lde.Inst, Inst: lde.Inst}
		var lns []*LN
		if lde.LN0 != nil {
			lns = append(lns, lde.LN0)
		}
		for j := range lde.LNs {
			lns = append(lns, &lde.LNs[j])
		}
		for _, lne := range lns {
			ln, err := b.buildLN(ied.Name, ap.Name, lde.Inst, lne)
			if err != nil {
				return nil, fmt.Errorf("scl: %s/%s: %w", ied.Name+lde.Inst, lnName(lne), err)
			}
			ld.Nodes = append(ld.Nodes, ln)
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
	return m, nil
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

func lnName(lne *LN) string {
	if lne.LNClass == "LLN0" {
		return "LLN0"
	}
	return lne.Prefix + lne.LNClass + lne.Inst
}

// builder resolves data type templates and remembers enum type bindings
// so that DAI values given as enum literal names can be applied.
type builder struct {
	scl     *SCL
	lnTypes map[string]*LNodeType
	doTypes map[string]*DOType
	daTypes map[string]*DAType
	enums   map[string]*EnumType
	enumOf  map[*model.DataAttribute]string // Enum leaf -> EnumType id
}

func newBuilder(s *SCL) *builder {
	b := &builder{
		scl:     s,
		lnTypes: map[string]*LNodeType{},
		doTypes: map[string]*DOType{},
		daTypes: map[string]*DAType{},
		enums:   map[string]*EnumType{},
		enumOf:  map[*model.DataAttribute]string{},
	}
	if t := s.DataTypeTemplates; t != nil {
		for i := range t.LNodeTypes {
			b.lnTypes[t.LNodeTypes[i].ID] = &t.LNodeTypes[i]
		}
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

func (b *builder) buildLN(iedName, apName, ldInst string, lne *LN) (*model.LogicalNode, error) {
	lnt, ok := b.lnTypes[lne.LNType]
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
			return nil, fmt.Errorf("DOI %q has no matching DO in type %q", doi.Name, lne.LNType)
		}
		if err := b.applyDOI(do, doi.DAIs, doi.SDIs); err != nil {
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
		ln.ReportControls = append(ln.ReportControls, buildReportControl(&lne.ReportControls[i]))
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
		ln.SettingControl = &model.SettingControl{NumOfSGs: sg.NumOfSGs, ActSG: sg.ActSG}
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
	do := &model.DataObject{Name: name, CDC: dot.CDC}
	for i := range dot.DAs {
		dae := &dot.DAs[i]
		fc, err := model.ParseFC(dae.FC)
		if err != nil {
			return nil, fmt.Errorf("DA %s: %w", dae.Name, err)
		}
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
		da, err := b.buildDA(dae.Name, fc, dae.BType, dae.Type, dae.Count, trg, dae.Vals, 0)
		if err != nil {
			return nil, fmt.Errorf("DA %s: %w", dae.Name, err)
		}
		do.Attributes = append(do.Attributes, da)
	}
	for _, sdo := range dot.SDOs {
		sub, err := b.buildDO(sdo.Name, sdo.Type, depth+1)
		if err != nil {
			return nil, fmt.Errorf("SDO %s: %w", sdo.Name, err)
		}
		do.Objects = append(do.Objects, sub)
	}
	return do, nil
}

// buildDA expands one DA or BDA. BDA members inherit the FC of the
// enclosing DA. Arrays of basic types get an array value with per-element
// defaults; arrays of constructed types keep Count with a nil value.
func (b *builder) buildDA(name string, fc model.FC, bType, typeID, count string, trg model.TrgOps, vals []Val, depth int) (*model.DataAttribute, error) {
	if depth > 16 {
		return nil, fmt.Errorf("attribute nesting too deep at %q", name)
	}
	da := &model.DataAttribute{Name: name, FC: fc, BType: bType, TrgOps: trg}
	n, _ := strconv.Atoi(strings.TrimSpace(count)) // non-numeric counts ignored

	if bType == "Struct" {
		dat, ok := b.daTypes[typeID]
		if !ok {
			return nil, fmt.Errorf("DAType %q not found", typeID)
		}
		da.Kind = mms.TypeStructure
		for i := range dat.BDAs {
			bda := &dat.BDAs[i]
			child, err := b.buildDA(bda.Name, fc, bda.BType, bda.Type, bda.Count, 0, bda.Vals, depth+1)
			if err != nil {
				return nil, fmt.Errorf("BDA %s: %w", bda.Name, err)
			}
			da.Children = append(da.Children, child)
		}
		if n > 0 {
			da.Kind = mms.TypeArray
			da.Count = n
		}
		return da, nil
	}

	kind, err := kindOf(bType)
	if err != nil {
		return nil, err
	}
	if bType == "Enum" {
		b.enumOf[da] = typeID
	}
	if n > 0 {
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

// kindOf maps an SCL basic type name to an MMS value type. Unknown basic
// types are an error; extend the switch as new types are needed.
func kindOf(bType string) (mms.Type, error) {
	switch bType {
	case "BOOLEAN":
		return mms.TypeBoolean, nil
	case "INT8", "INT16", "INT24", "INT32", "INT64", "INT128", "Enum":
		return mms.TypeInteger, nil
	case "INT8U", "INT16U", "INT24U", "INT32U", "INT64U":
		return mms.TypeUnsigned, nil
	case "FLOAT32":
		return mms.TypeFloat32, nil
	case "FLOAT64":
		return mms.TypeFloat64, nil
	case "VisString32", "VisString64", "VisString65", "VisString129",
		"VisString255", "ObjRef", "Currency":
		return mms.TypeVisibleString, nil
	case "Unicode255":
		return mms.TypeMMSString, nil
	case "Octet6", "Octet16", "Octet64", "EntryID":
		return mms.TypeOctetString, nil
	case "Quality", "Dbpos", "Tcmd", "Check", "TrgOps", "OptFlds":
		return mms.TypeBitString, nil
	case "Timestamp":
		return mms.TypeUTCTime, nil
	case "EntryTime":
		return mms.TypeBinaryTime, nil
	}
	return mms.TypeNone, fmt.Errorf("unsupported bType %q", bType)
}

// bitLenOf returns the bit-string width of a bit-string basic type.
func bitLenOf(bType string) int {
	switch bType {
	case "Quality":
		return 13
	case "Dbpos", "Tcmd", "Check":
		return 2
	case "TrgOps":
		return 6
	case "OptFlds":
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
// either a sub data object or a structured data attribute.
func (b *builder) applyDOI(do *model.DataObject, dais []DAI, sdis []SDI) error {
	for i := range dais {
		dai := &dais[i]
		da := do.Attribute(dai.Name)
		if da == nil {
			return fmt.Errorf("DAI %q has no matching DA", dai.Name)
		}
		if len(dai.Vals) > 0 {
			if err := b.setValue(da, dai.Vals[0].Value); err != nil {
				return err
			}
		}
	}
	for i := range sdis {
		sdi := &sdis[i]
		if sub := do.Child(sdi.Name); sub != nil {
			if err := b.applyDOI(sub, sdi.DAIs, sdi.SDIs); err != nil {
				return fmt.Errorf("SDI %s: %w", sdi.Name, err)
			}
			continue
		}
		if da := do.Attribute(sdi.Name); da != nil {
			if err := b.applySDIonDA(da, sdi); err != nil {
				return fmt.Errorf("SDI %s: %w", sdi.Name, err)
			}
			continue
		}
		return fmt.Errorf("SDI %q matches neither an SDO nor a DA", sdi.Name)
	}
	return nil
}

func (b *builder) applySDIonDA(da *model.DataAttribute, sdi *SDI) error {
	for i := range sdi.DAIs {
		dai := &sdi.DAIs[i]
		c := da.Child(dai.Name)
		if c == nil {
			return fmt.Errorf("DAI %q has no matching member", dai.Name)
		}
		if len(dai.Vals) > 0 {
			if err := b.setValue(c, dai.Vals[0].Value); err != nil {
				return err
			}
		}
	}
	for i := range sdi.SDIs {
		sub := &sdi.SDIs[i]
		c := da.Child(sub.Name)
		if c == nil {
			return fmt.Errorf("SDI %q has no matching member", sub.Name)
		}
		if err := b.applySDIonDA(c, sub); err != nil {
			return fmt.Errorf("SDI %s: %w", sub.Name, err)
		}
	}
	return nil
}

// buildDataSet resolves FCDA entries to object references. Array index
// notation in doName/daName (e.g. "phsA(2)") is passed through verbatim.
func buildDataSet(iedName, ldInst string, dse *DataSet) (*model.DataSet, error) {
	ds := &model.DataSet{Name: dse.Name}
	for _, f := range dse.FCDAs {
		fc, err := model.ParseFC(f.FC)
		if err != nil {
			return nil, fmt.Errorf("dataset %s: %w", dse.Name, err)
		}
		li := f.LDInst
		if li == "" {
			li = ldInst
		}
		ln := f.Prefix + f.LNClass + f.LNInst
		if f.LNClass == "LLN0" {
			ln = "LLN0"
		}
		ref := iedName + li + "/" + ln
		if f.DOName != "" {
			ref += "." + f.DOName
		}
		if f.DAName != "" {
			ref += "." + f.DAName
		}
		r, err := model.ParseRef(ref)
		if err != nil {
			return nil, fmt.Errorf("dataset %s: %w", dse.Name, err)
		}
		ds.Entries = append(ds.Entries, model.FCDA{Ref: r, FC: fc})
	}
	return ds, nil
}

func buildReportControl(r *ReportControl) *model.ReportControl {
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
	if of := r.OptFields; of != nil {
		set := func(on bool, f model.OptFlds) {
			if on {
				rc.OptFlds |= f
			}
		}
		set(of.SeqNum, model.OptSeqNum)
		set(of.TimeStamp, model.OptTimeOfEntry)
		set(of.ReasonCode, model.OptReasonCode)
		set(of.DataSet, model.OptDataSetName)
		set(of.DataRef, model.OptDataRef)
		set(of.BufOvfl, model.OptBufOvfl)
		set(of.EntryID, model.OptEntryID)
		set(of.ConfigRef, model.OptConfRev)
		set(of.Segmentation, model.OptSegmentation)
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

func (b *builder) buildGSEControl(iedName, apName, ldInst string, g *GSEControl) *model.GSEControl {
	gc := &model.GSEControl{
		Name:    g.Name,
		GoID:    g.AppID,
		DataSet: g.DatSet,
		ConfRev: g.ConfRev,
	}
	if gc.GoID == "" {
		gc.GoID = g.Name
	}
	if gse := findGSE(b.scl, iedName, apName, ldInst, g.Name); gse != nil {
		gc.DstMAC, gc.AppID, gc.VLANID, gc.VLANPri = addressOf(gse.Address)
		gc.MinTime = durMS(gse.MinTime)
		gc.MaxTime = durMS(gse.MaxTime)
	}
	return gc
}

func (b *builder) buildSVControl(iedName, apName, ldInst string, s *SampledValueControl) *model.SVControl {
	sc := &model.SVControl{
		Name:      s.Name,
		SvID:      s.SmvID,
		DataSet:   s.DatSet,
		ConfRev:   s.ConfRev,
		SmpRate:   s.SmpRate,
		NoASDU:    s.NofASDU,
		Multicast: boolAttr(s.Multicast, true),
	}
	if smv := findSMV(b.scl, iedName, apName, ldInst, s.Name); smv != nil {
		sc.DstMAC, sc.AppID, sc.VLANID, sc.VLANPri = addressOf(smv.Address)
	}
	return sc
}

func buildLogControl(l *LogControl) *model.LogControl {
	return &model.LogControl{
		Name:    l.Name,
		DataSet: l.DatSet,
		LogName: l.LogName,
		TrgOps:  trgOpsOf(l.TrgOps),
		IntgPd:  l.IntgPd,
		LogEna:  boolAttr(l.LogEna, true),
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
