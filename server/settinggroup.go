package server

import (
	"strings"
	"sync"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// sgManager implements server-side setting groups for one logical device:
// it materialises the SGCB and keeps per-group copies of the SG/SE setting
// values, switching which copy is live as the client selects groups.
type sgManager struct {
	ld      *model.LogicalDevice
	sgcb    *model.DataObject
	numOfSG uint8
	// resvTms is the reservation time in milliseconds from SCL, zero when
	// the document declares none.
	resvTms int
	// now stamps LActTm with the server's clock quality.
	now func() *mms.Value

	mu     sync.Mutex
	actSG  uint8
	editSG uint8

	// settings pairs an SG (active) and SE (edit) attribute for one
	// setting, with a per-group value store.
	settings []*sgSetting
}

type sgSetting struct {
	sg     *model.DataAttribute // FC SG (active view)
	se     *model.DataAttribute // FC SE (edit view), may be nil
	ref    string               // "LD/LN.DO.DA", the key the model groups by
	groups []*mms.Value         // one value per setting group
}

// newSGManager scans ld for SG/SE setting attributes and materialises the
// SGCB in LLN0. Returns nil if the device has no setting-constrained
// attributes.
func newSGManager(ld *model.LogicalDevice, numOfSG uint8, resvTms int, now func() *mms.Value) *sgManager {
	if numOfSG == 0 {
		numOfSG = 1
	}
	if now == nil {
		now = mms.NewUTCTimeNow
	}
	m := &sgManager{ld: ld, numOfSG: numOfSG, actSG: 1, resvTms: resvTms, now: now}

	// Pair SG and SE attributes by their DO path within each LN.
	for _, ln := range ld.Nodes {
		sgAttrs := map[string]*model.DataAttribute{}
		seAttrs := map[string]*model.DataAttribute{}
		for _, do := range ln.Objects {
			collectSGAttrs(model.ObjectReference(ln.Name+"."+do.Name), do, sgAttrs, seAttrs)
		}
		for path, sg := range sgAttrs {
			s := &sgSetting{sg: sg, se: seAttrs[path], ref: ld.Name + "/" + path}
			s.groups = make([]*mms.Value, numOfSG)
			for i := range s.groups {
				s.groups[i] = sg.Value.Clone()
			}
			m.settings = append(m.settings, s)
		}
	}
	if len(m.settings) == 0 {
		return nil
	}

	lln0 := ld.Node("LLN0")
	if lln0 == nil {
		return nil
	}
	m.sgcb = buildSGCB(numOfSG, m.resvTms, now())
	lln0.Objects = append(lln0.Objects, m.sgcb)
	return m
}

func collectSGAttrs(path model.ObjectReference, do *model.DataObject, sg, se map[string]*model.DataAttribute) {
	for _, a := range do.Attributes {
		collectSGAttr(path.Child(a.Name), a, sg, se)
	}
	for _, sub := range do.Objects {
		collectSGAttrs(path.Child(sub.Name), sub, sg, se)
	}
}

func collectSGAttr(path model.ObjectReference, a *model.DataAttribute, sg, se map[string]*model.DataAttribute) {
	if len(a.Children) == 0 {
		switch a.FC {
		case model.SG:
			sg[string(path)] = a
		case model.SE:
			se[string(path)] = a
		}
		return
	}
	for _, c := range a.Children {
		collectSGAttr(path.Child(c.Name), c, sg, se)
	}
}

// buildSGCB materialises the setting group control block of IEC 61850-7-2
// under FC SP in LLN0. ResvTms, the reservation time, is present only when
// the configuration declares one.
func buildSGCB(numOfSG uint8, resvTms int, lActTm *mms.Value) *model.DataObject {
	attr := func(name string, v *mms.Value) *model.DataAttribute {
		return &model.DataAttribute{Name: name, FC: model.SP, Kind: v.Type(), Value: v}
	}
	do := &model.DataObject{Name: "SGCB", Attributes: []*model.DataAttribute{
		attr("NumOfSG", mms.NewUint8(numOfSG)),
		attr("ActSG", mms.NewUint8(1)),
		attr("EditSG", mms.NewUint8(0)),
		attr("CnfEdit", mms.NewBool(false)),
		attr("LActTm", lActTm),
	}}
	if resvTms > 0 {
		do.Attributes = append(do.Attributes, attr("ResvTms", mms.NewUint32(uint32(resvTms))))
	}
	return do
}

// seedGroups fills each setting group's store with the value the source
// configuration recorded for it, so a document that gives one initial value
// per sGroup is served as configured instead of every group starting from
// the first. A group the document does not mention keeps the attribute's
// own value, which is the active group's.
func (m *sgManager) seedGroups(groups []model.SettingGroup) {
	if len(groups) == 0 || len(m.settings) == 0 {
		return
	}
	byRef := make(map[string]*sgSetting, len(m.settings))
	for _, s := range m.settings {
		byRef[s.ref] = s
	}
	for _, g := range groups {
		if g.Number <= 0 || int(g.Number) > int(m.numOfSG) {
			continue // group 0 is the active group; beyond the count has no store
		}
		for ref, v := range g.Values {
			if s, ok := byRef[ref]; ok {
				s.groups[g.Number-1] = v.Clone()
			}
		}
	}
}

// isSGCBWrite reports whether item addresses this device's SGCB and
// returns the attribute name.
func isSGCBWrite(item string) (attr string, ok bool) {
	parts := strings.Split(item, "$")
	if len(parts) == 4 && parts[0] == "LLN0" && parts[1] == "SP" && parts[2] == "SGCB" {
		return parts[3], true
	}
	return "", false
}

// editing reports whether a setting group is open for editing, the only
// time its SE values may be written.
func (m *sgManager) editing() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.editSG >= 1 && m.editSG <= m.numOfSG
}

// checkWrite validates an SGCB write before it is stored (IEC 61850-7-2
// setting group services). Only ActSG, EditSG and CnfEdit are writable;
// a group number outside 1..NumOfSG (0 also allowed for EditSG, which
// ends editing) is invalid, and confirming an edit needs one open.
func (m *sgManager) checkWrite(attr string, v *mms.Value) byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch attr {
	case "ActSG":
		if g := v.Int64(); g < 1 || g > int64(m.numOfSG) {
			return byte(mms.AccessObjectValueInvalid)
		}
	case "EditSG":
		if g := v.Int64(); g < 0 || g > int64(m.numOfSG) {
			return byte(mms.AccessObjectValueInvalid)
		}
	case "CnfEdit":
		if v.Bool() && (m.editSG < 1 || m.editSG > m.numOfSG) {
			return byte(mms.AccessTemporarilyUnavailable)
		}
	default:
		return byte(mms.AccessObjectAccessDenied)
	}
	return 0xff
}

// onSGCBWrite handles ActSG/EditSG/CnfEdit writes. Called with the model
// write lock held.
func (m *sgManager) onSGCBWrite(attr string, v *mms.Value) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch attr {
	case "ActSG":
		g := uint8(v.Int64())
		if g >= 1 && g <= m.numOfSG {
			m.actSG = g
			m.sgcb.Attribute("ActSG").Value = mms.NewUint8(g)
			m.sgcb.Attribute("LActTm").Value = m.now()
			for _, s := range m.settings {
				s.sg.Value = s.groups[g-1].Clone()
			}
		}
	case "EditSG":
		g := uint8(v.Int64())
		m.editSG = g
		m.sgcb.Attribute("EditSG").Value = mms.NewUint8(g)
		if g >= 1 && g <= m.numOfSG {
			for _, s := range m.settings {
				if s.se != nil {
					s.se.Value = s.groups[g-1].Clone()
				}
			}
		}
	case "CnfEdit":
		if v.Bool() && m.editSG >= 1 && m.editSG <= m.numOfSG {
			for _, s := range m.settings {
				if s.se != nil {
					s.groups[m.editSG-1] = s.se.Value.Clone()
					if m.editSG == m.actSG {
						s.sg.Value = s.se.Value.Clone()
					}
				}
			}
			m.editSG = 0
			m.sgcb.Attribute("EditSG").Value = mms.NewUint8(0)
			m.sgcb.Attribute("CnfEdit").Value = mms.NewBool(false)
		}
	}
}
