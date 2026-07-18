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
	groups []*mms.Value         // one value per setting group
}

// newSGManager scans ld for SG/SE setting attributes and materialises the
// SGCB in LLN0. Returns nil if the device has no setting-constrained
// attributes.
func newSGManager(ld *model.LogicalDevice, numOfSG uint8) *sgManager {
	if numOfSG == 0 {
		numOfSG = 1
	}
	m := &sgManager{ld: ld, numOfSG: numOfSG, actSG: 1}

	// Pair SG and SE attributes by their DO path within each LN.
	for _, ln := range ld.Nodes {
		sgAttrs := map[string]*model.DataAttribute{}
		seAttrs := map[string]*model.DataAttribute{}
		for _, do := range ln.Objects {
			collectSGAttrs(model.ObjectReference(ln.Name+"."+do.Name), do, sgAttrs, seAttrs)
		}
		for path, sg := range sgAttrs {
			s := &sgSetting{sg: sg, se: seAttrs[path]}
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
	m.sgcb = buildSGCB(numOfSG)
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

func buildSGCB(numOfSG uint8) *model.DataObject {
	attr := func(name string, v *mms.Value) *model.DataAttribute {
		return &model.DataAttribute{Name: name, FC: model.SP, Kind: v.Type(), Value: v}
	}
	return &model.DataObject{Name: "SGCB", Attributes: []*model.DataAttribute{
		attr("NumOfSG", mms.NewUint8(numOfSG)),
		attr("ActSG", mms.NewUint8(1)),
		attr("EditSG", mms.NewUint8(0)),
		attr("CnfEdit", mms.NewBool(false)),
		attr("LActTm", mms.NewUTCTimeNow()),
	}}
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
			m.sgcb.Attribute("LActTm").Value = mms.NewUTCTimeNow()
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
