package server

import (
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Service tracking (IEC 61850-7-2 Edition 2, the LTRK logical node). An
// LTRK carries one tracking object per kind of service: BrcbTrk, UrcbTrk,
// LocbTrk, GocbTrk, MsvcbTrk, UsvcbTrk and SgcbTrk for the control blocks,
// SpcTrk, DpcTrk, IncTrk, EncTrk, ApcFTrk, ApcIntTrk, BscTrk, IscTrk and
// BacTrk for the controls. Each time a client runs a tracked service the
// server records in the matching object which object it addressed
// (objRef), which service it was (serviceType), how it ended (errorCode)
// and when (t), with a copy of the block's state after it, or of the
// command. A client subscribes to a tracking object like to any data: its
// objRef raises data-update, so a data set holding it reports every
// service, even one that changed nothing.
//
// The services tracked and the error codes follow libiec61850, which the
// interop suite compares this server with: a SetDataValues on a control
// block attribute is tracked as the block's Set...Values, each attribute
// written counting as one, and a data access error maps to a service
// error as there. An LTRK in the addressed object's own logical device
// tracks it; failing one there, the first in the server does.

// trackingKinds are the tracking object names this server writes; an
// object named with an instance number ("EncTrk1") counts as its kind.
var trackingKinds = map[string]bool{
	"SpcTrk": true, "DpcTrk": true, "IncTrk": true, "EncTrk": true, "ApcFTrk": true,
	"ApcIntTrk": true, "BscTrk": true, "IscTrk": true, "BacTrk": true,
	"BrcbTrk": true, "UrcbTrk": true, "LocbTrk": true, "GocbTrk": true,
	"MsvcbTrk": true, "UsvcbTrk": true, "SgcbTrk": true,
}

// commonTracking are the attributes every tracking object has, which the
// server sets itself rather than copying from the tracked object.
var commonTracking = map[string]bool{
	"objRef": true, "serviceType": true, "errorCode": true, "originatorID": true,
	"t": true, "certIssuer": true, "d": true,
}

// trkObj is one tracking object.
type trkObj struct {
	ref model.ObjectReference // "LD/LTRK1.BrcbTrk"
	do  *model.DataObject
}

// tracker finds the tracking objects of a model.
type tracker struct {
	byLD  map[string]map[string]*trkObj // by device, then kind
	first map[string]*trkObj
}

func buildTracker(m *model.Model) *tracker {
	t := &tracker{byLD: make(map[string]map[string]*trkObj), first: make(map[string]*trkObj)}
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			if ln.Class != "LTRK" && !(ln.Class == "" && strings.HasPrefix(ln.Name, "LTRK")) {
				continue
			}
			for _, do := range ln.Objects {
				kind := strings.TrimRight(do.Name, "0123456789")
				if !trackingKinds[kind] {
					continue
				}
				o := &trkObj{ref: model.ObjectReference(ld.Name + "/" + ln.Name + "." + do.Name), do: do}
				if t.byLD[ld.Name] == nil {
					t.byLD[ld.Name] = make(map[string]*trkObj)
				}
				if t.byLD[ld.Name][kind] == nil {
					t.byLD[ld.Name][kind] = o
				}
				if t.first[kind] == nil {
					t.first[kind] = o
				}
			}
		}
	}
	return t
}

func (t *tracker) lookup(ld, kind string) *trkObj {
	if o := t.byLD[ld][kind]; o != nil {
		return o
	}
	return t.first[kind]
}

// trackRecord is one tracked service.
type trackRecord struct {
	ld     string // the device of the addressed object
	kind   string // the tracking object's kind
	objRef string // ACSI reference of the addressed object
	svc    model.ServiceType
	err    model.ServiceError
	// src is the control block whose state is copied, nil for a control.
	src *model.DataObject
	// ctl is the command of a control service, nil otherwise.
	ctl *ctlTrack
	// requested is the attribute a Set...Values wrote, with the value
	// asked for, recorded over the block's state; nil for none.
	requested *model.DataAttribute
}

// ctlTrack is what a control tracking object records of a command.
type ctlTrack struct {
	ctlVal, oper *mms.Value // the ctlVal, and the Oper/SBOw/Cancel structure
	orCat        int64
	orIdent      []byte
	ctlNum       uint8
	cause        model.AddCause
}

// track writes rec into its tracking object, noting the changes in cs so
// that reports and logs see them. Called with the model write lock held.
func (s *Server) track(cs changeSet, rec trackRecord) {
	o := s.tracker.lookup(rec.ld, rec.kind)
	if o == nil {
		return
	}
	set := func(name string, v *mms.Value) {
		if da := o.do.Attribute(name); da != nil {
			s.setTracked(cs, o.ref.Child(name), da, v)
		}
	}
	if rec.src != nil {
		for _, da := range o.do.Attributes {
			if commonTracking[da.Name] {
				continue
			}
			if src := attributeFold(rec.src.Attributes, da.Name); src != nil {
				s.copyTracked(cs, o.ref.Child(da.Name), da, src)
			}
		}
	}
	if r := rec.requested; r != nil {
		if da := attributeFold(o.do.Attributes, r.Name); da != nil && !commonTracking[da.Name] {
			s.copyTracked(cs, o.ref.Child(da.Name), da, r)
		}
	}
	if c := rec.ctl; c != nil {
		set("ctlVal", c.ctlVal)
		if origin := o.do.Attribute("origin"); origin != nil {
			if da := attributeFold(origin.Children, "orCat"); da != nil {
				s.setTracked(cs, o.ref.Child("origin").Child("orCat"), da, mms.NewInt8(int8(c.orCat)))
			}
			if da := attributeFold(origin.Children, "orIdent"); da != nil {
				s.setTracked(cs, o.ref.Child("origin").Child("orIdent"), da, mms.NewOctetString(c.orIdent))
			}
		}
		set("ctlNum", mms.NewUint8(c.ctlNum))
		if c.oper != nil && c.oper.Type() == mms.TypeStructure {
			// Oper and SBOw: ctlVal, origin, ctlNum, T, Test, Check.
			// Cancel: ctlVal, origin, ctlNum, T, Test.
			set("T", c.oper.Index(3))
			set("Test", c.oper.Index(4))
			if c.oper.Len() > 5 {
				set("Check", c.oper.Index(5))
			}
		}
		cause := c.cause
		if cause == model.AddCauseNone {
			cause = model.AddCauseUnknown // AddCauseNone is this library's sentinel, not a value
		}
		set("respAddCause", mms.NewInt8(int8(cause)))
	}
	set("serviceType", mms.NewInt32(int32(rec.svc)))
	set("errorCode", mms.NewInt32(int32(rec.err)))
	set("t", s.now())
	set("objRef", mms.NewVisibleString(rec.objRef))
}

// setTracked stores v in a tracking attribute when it fits its type.
func (s *Server) setTracked(cs changeSet, ref model.ObjectReference, da *model.DataAttribute, v *mms.Value) {
	if v == nil || len(da.Children) > 0 || !valueFits(da, v) {
		return
	}
	old := da.Value
	da.Value = v.Clone()
	if cs != nil {
		cs.record(ref, da, old, da.Value)
	}
}

// copyTracked copies a control block attribute into the tracking
// attribute of the same name, structure by structure. A data set or log
// reference is written in ACSI notation, "LD/LN.name", as libiec61850
// does.
func (s *Server) copyTracked(cs changeSet, ref model.ObjectReference, dst, src *model.DataAttribute) {
	if len(dst.Children) > 0 {
		for _, c := range dst.Children {
			if sc := attributeFold(src.Children, c.Name); sc != nil {
				s.copyTracked(cs, ref.Child(c.Name), c, sc)
			}
		}
		return
	}
	v := src.Value
	if v != nil && (strings.EqualFold(dst.Name, "datSet") || strings.EqualFold(dst.Name, "logRef")) {
		v = mms.NewVisibleString(strings.ReplaceAll(v.Text(), "$", "."))
	}
	s.setTracked(cs, ref, dst, v)
}

// attributeFold finds the attribute named name, ignoring case: a tracking
// object names "rptEna" what the control block calls "RptEna".
func attributeFold(attrs []*model.DataAttribute, name string) *model.DataAttribute {
	for _, a := range attrs {
		if strings.EqualFold(a.Name, name) {
			return a
		}
	}
	return nil
}

// serviceErrorOf maps the data access error a write was answered with to
// the service error a tracking object records, as libiec61850 does.
func serviceErrorOf(code byte) model.ServiceError {
	switch mms.DataAccessError(code) {
	case 0xff:
		return model.ServiceErrorNone
	case mms.AccessTemporarilyUnavailable:
		return model.ServiceErrorInstanceLockedByOtherClient
	case mms.AccessObjectAccessDenied:
		return model.ServiceErrorAccessViolation
	case mms.AccessObjectValueInvalid:
		return model.ServiceErrorParameterValueInappropriate
	case mms.AccessTypeInconsistent, mms.AccessObjectAttributeInconsistent:
		return model.ServiceErrorParameterValueInconsistent
	case mms.AccessObjectNonExistent:
		return model.ServiceErrorInstanceNotAvailable
	}
	return model.ServiceErrorFailedDueToServerConstraint
}

// trackCBWrite tracks a SetDataValues on a control block attribute as the
// block's Set...Values service, answered with code (0xff for success).
// Called with the model write lock held, after the write was applied.
//
// For a report control block the attribute written is then recorded with
// the value the client asked for, refused or not, as libiec61850 records
// it: the tracking object states the service's parameter.
func (h *handler) trackCBWrite(cs changeSet, domain, item string, v *mms.Value, code byte) {
	parts := strings.Split(item, "$")
	if len(parts) < 3 {
		return
	}
	ld := h.s.model.Device(domain)
	if ld == nil {
		return
	}
	ln := ld.Node(parts[0])
	if ln == nil {
		return
	}
	rec := trackRecord{ld: domain, err: serviceErrorOf(code), objRef: domain + "/" + parts[0] + "." + parts[2]}
	switch parts[1] {
	case "BR":
		rec.kind, rec.svc = "BrcbTrk", model.ServiceSetBRCBValues
	case "RP":
		rec.kind, rec.svc = "UrcbTrk", model.ServiceSetURCBValues
	case "LG":
		rec.kind, rec.svc = "LocbTrk", model.ServiceSetLCBValues
	case "GO":
		rec.kind, rec.svc = "GocbTrk", model.ServiceSetGoCBValues
	case "MS":
		rec.kind, rec.svc = "MsvcbTrk", model.ServiceSetMSVCBValues
	case "US":
		rec.kind, rec.svc = "UsvcbTrk", model.ServiceSetUSVCBValues
	case "SP":
		if parts[0] != "LLN0" || parts[2] != "SGCB" || len(parts) != 4 {
			return
		}
		rec.kind = "SgcbTrk"
		switch parts[3] {
		case "ActSG":
			rec.svc = model.ServiceSelectActiveSG
		case "EditSG":
			rec.svc = model.ServiceSelectEditSG
		case "CnfEdit":
			rec.svc = model.ServiceConfirmEditSGValues
		default:
			return
		}
	default:
		return
	}
	if h.s.tracker.lookup(domain, rec.kind) == nil {
		return
	}
	rec.src = cbObject(ln, parts[1], parts[2])
	if rec.src == nil {
		return // not a control block this server serves
	}
	if (parts[1] == "BR" || parts[1] == "RP") && len(parts) == 4 && v != nil {
		rec.requested = &model.DataAttribute{Name: parts[3], Value: v}
	}
	h.s.track(cs, rec)
}

// cbObject finds the materialised control block name under fc in ln.
func cbObject(ln *model.LogicalNode, fc, name string) *model.DataObject {
	for _, do := range ln.Objects {
		if do.Name == name && len(do.Attributes) > 0 && do.Attributes[0].FC.String() == fc {
			return do
		}
	}
	return nil
}

// controlTrackingKind is the tracking object of a controllable object:
// by its CDC, and for an APC by whether its value is a float or an
// integer.
func (s *Server) controlTrackingKind(ref model.ObjectReference, ctlVal *mms.Value) string {
	do, _ := s.model.Lookup(ref, model.CO).(*model.DataObject)
	cdc := ""
	if do != nil {
		cdc = string(do.CDC)
	}
	switch cdc {
	case "SPC":
		return "SpcTrk"
	case "DPC":
		return "DpcTrk"
	case "INC":
		return "IncTrk"
	case "ENC":
		return "EncTrk"
	case "BSC":
		return "BscTrk"
	case "ISC":
		return "IscTrk"
	case "BAC":
		return "BacTrk"
	case "APC":
		if f := ctlVal; f != nil && f.Type() == mms.TypeStructure && f.Len() > 0 && !isFloat(f.Index(0)) {
			return "ApcIntTrk"
		}
		return "ApcFTrk"
	}
	return ""
}

func isFloat(v *mms.Value) bool {
	return v != nil && (v.Type() == mms.TypeFloat32 || v.Type() == mms.TypeFloat64)
}

// trackControl tracks a control service on ref. ctx is the decoded
// command, nil for a select by reading SBO. Called with the model write
// lock held.
func (s *Server) trackControl(cs changeSet, ref model.ObjectReference, svc model.ServiceType,
	serr model.ServiceError, ctx *ControlCtx, oper *mms.Value, cause model.AddCause) {
	var ctlVal *mms.Value
	if ctx != nil {
		ctlVal = ctx.Value
	}
	kind := s.controlTrackingKind(ref, ctlVal)
	if kind == "" {
		return
	}
	rec := trackRecord{ld: ref.LD(), kind: kind, objRef: string(ref), svc: svc, err: serr}
	if ctx != nil {
		rec.ctl = &ctlTrack{ctlVal: ctx.Value, oper: oper, orCat: int64(ctx.Origin),
			orIdent: []byte(ctx.OrIdent), ctlNum: ctx.CtlNum, cause: cause}
	}
	s.track(cs, rec)
}

// trackAsync records tracking outside a client request — a
// CommandTermination sent after the operate was answered — under the
// model lock, reporting its changes. It runs on its own goroutine, so a
// caller holding the lock does not deadlock; it then waits for it, so it
// lands after what that caller records.
func (s *Server) trackAsync(fn func(cs changeSet)) {
	go func() {
		s.mu.Lock()
		cs := make(changeSet)
		fn(cs)
		s.reports.onUpdate(cs)
		s.logs.onUpdate(cs)
		s.mu.Unlock()
	}()
}
