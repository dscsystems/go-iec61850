package server

import (
	"strings"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// ControlCtx describes an incoming control request passed to a handler.
type ControlCtx struct {
	Ref       model.ObjectReference // the controllable object, e.g. "LD/LN.SPCSO1"
	Value     *mms.Value            // ctlVal
	Origin    model.OrCat
	OrIdent   string
	CtlNum    uint8
	Test      bool
	Interlock bool
	Synchro   bool
	Select    bool // true for the select phase (SBOw), false for operate
}

// ControlHandler decides whether a control is allowed and applies its
// effect. Returning model.AddCauseNone accepts the command; any other
// value rejects it with that additional cause.
type ControlHandler func(*ControlCtx) model.AddCause

// OnControl registers a handler for the controllable object at ref. Both
// the select (SBOw) and operate phases are delivered; inspect ctx.Select.
// If no handler is registered, operates are accepted and the object's
// sibling stVal (FC ST) is set to the control value.
func (s *Server) OnControl(ref model.ObjectReference, h ControlHandler) {
	s.ctlMu.Lock()
	if s.controls == nil {
		s.controls = make(map[model.ObjectReference]ControlHandler)
	}
	s.controls[ref] = h
	s.ctlMu.Unlock()
}

// controlWrite handles a write to a control attribute ("...$Oper",
// "$SBOw", "$Cancel"). It returns (handled, accessErrorCode) where code is
// 0xff on success. Called with the model write lock held.
func (h *handler) controlWrite(domain, item string, v *mms.Value, conn *mms.ServerConn) (bool, byte) {
	base, phase, ok := splitControl(item)
	if !ok {
		return false, 0
	}
	h.s.log.Debug("server: control write", "item", item, "phase", phase)
	ld := h.s.model.Device(domain)
	if ld == nil {
		return true, byte(mms.AccessObjectNonExistent)
	}
	// base is "LN$CO$DO..."; build the object reference (drop the CO tag).
	ref := controlRef(domain, base)

	if phase == "Cancel" {
		cc := decodeOper(ref, v)
		if cause := h.s.checkCancel(ref, conn, cc.CtlNum); cause != model.AddCauseNone {
			h.setLastApplError(ld, ref, cc, cause)
			return true, byte(mms.AccessObjectAccessDenied)
		}
		h.s.clearSelection(ref)
		return true, 0xff
	}

	ctx := decodeOper(ref, v)
	ctx.Select = phase == "SBOw"

	// An SBO operate must belong to a live selection: made by this
	// connection, and carrying that select's control number. Both
	// security levels are checked — normal security selects with an SBO
	// read, which carries no ctlNum, so only the reservation is verified
	// there.
	if phase == "Oper" && h.s.requiresSelection(ref) {
		if cause := h.s.checkSelection(ref, conn, ctx.CtlNum); cause != model.AddCauseNone {
			h.setLastApplError(ld, ref, ctx, cause)
			return true, byte(mms.AccessObjectAccessDenied)
		}
	}

	h.s.ctlMu.RLock()
	hdlr := h.s.controls[ref]
	h.s.ctlMu.RUnlock()

	cause := model.AddCauseNone
	if hdlr != nil {
		cause = hdlr(ctx)
	}
	if cause != model.AddCauseNone {
		h.setLastApplError(ld, ref, ctx, cause)
		return true, byte(mms.AccessObjectAccessDenied)
	}

	if ctx.Select {
		// SBOw reserves the object for this connection, under the control
		// number the operate will have to repeat. A reservation another
		// client is holding is not ours to take.
		if !h.s.selectWithValue(ref, conn, ctx.CtlNum) {
			h.setLastApplError(ld, ref, ctx, model.AddCauseObjectAlreadySelected)
			return true, byte(mms.AccessObjectAccessDenied)
		}
	} else {
		// Apply the operate: set the sibling stVal under FC ST.
		h.applyControl(ref, ctx.Value)
		h.s.clearSelection(ref)
		// Enhanced control models confirm with a CommandTermination.
		if h.isEnhanced(ref) && conn != nil {
			h.sendCommandTermination(conn, ref, v)
		}
	}
	return true, 0xff
}

// applyControl reflects an accepted operate into the process image: the
// controllable object's stVal (FC ST) becomes the control value.
func (h *handler) applyControl(ref model.ObjectReference, ctlVal *mms.Value) {
	stRef := ref.Child("stVal")
	if da := h.s.model.Attribute(stRef, model.ST); da != nil && len(da.Children) == 0 {
		da.Value = ctlVal.Clone()
	}
}

func (h *handler) isEnhanced(ref model.ObjectReference) bool {
	cm := h.s.model.Attribute(ref.Child("ctlModel"), model.CF)
	return cm != nil && cm.Value != nil && model.CtlModel(cm.Value.Int64()).Enhanced()
}

// sendCommandTermination emits a positive CommandTermination+ as an
// unconfirmed information report echoing the Oper value (IEC 61850-8-1).
func (h *handler) sendCommandTermination(conn *mms.ServerConn, ref model.ObjectReference, oper *mms.Value) {
	domain := ref.LD()
	path := ref.Path()
	item := path[0] + "$CO$" + strings.Join(path[1:], "$") + "$Oper"
	// InformationReport { listOfVariable [1] { name Oper }, listOfAccessResult [0] { oper } }
	report := commandTerminationReport(domain, item, oper)
	if err := conn.SendUnconfirmed(report); err != nil {
		h.s.log.Debug("server: command termination send failed", "ref", ref, "err", err)
	}
}

func (h *handler) setLastApplError(ld *model.LogicalDevice, ref model.ObjectReference, ctx *ControlCtx, cause model.AddCause) {
	// Best effort: populate LLN0.LastApplError if present in the model.
	lln0 := ld.Node("LLN0")
	if lln0 == nil {
		return
	}
	lae := lln0.Object("LastApplError")
	if lae == nil {
		return
	}
	if a := lae.Attribute("AddCause"); a != nil {
		a.Value = mms.NewInt32(int32(cause))
	}
	if a := lae.Attribute("Error"); a != nil {
		a.Value = mms.NewInt32(1)
	}
}

// decodeOper extracts the fields of an operate/SBOw structure:
// { ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }.
func decodeOper(ref model.ObjectReference, v *mms.Value) *ControlCtx {
	ctx := &ControlCtx{Ref: ref}
	if v == nil || v.Type() != mms.TypeStructure {
		return ctx
	}
	ctx.Value = v.Index(0)
	if origin := v.Index(1); origin != nil && origin.Type() == mms.TypeStructure {
		ctx.Origin = model.OrCat(origin.Index(0).Int64())
		ctx.OrIdent = string(origin.Index(1).Bytes())
	}
	if n := v.Index(2); n != nil {
		ctx.CtlNum = uint8(n.Int64())
	}
	if t := v.Index(4); t != nil {
		ctx.Test = t.Bool()
	}
	if ck := v.Index(5); ck != nil {
		ctx.Interlock = ck.Bit(0)
		ctx.Synchro = ck.Bit(1)
	}
	return ctx
}

// splitControl reports whether item addresses a control attribute and
// returns the "LN$CO$DO..." base and the phase ("Oper", "SBOw",
// "Cancel", "SBO").
func splitControl(item string) (base, phase string, ok bool) {
	parts := strings.Split(item, "$")
	if len(parts) < 4 || parts[1] != "CO" {
		return "", "", false
	}
	for i := len(parts) - 1; i >= 3; i-- {
		switch parts[i] {
		case "Oper", "SBOw", "Cancel", "SBO":
			return strings.Join(parts[:i], "$"), parts[i], true
		}
	}
	return "", "", false
}

// controlRef converts domain + "LN$CO$DO[$SDO]" to "LD/LN.DO[.SDO]".
func controlRef(domain, base string) model.ObjectReference {
	parts := strings.Split(base, "$")
	// parts[0]=LN, parts[1]=CO, parts[2:]=DO path
	path := append([]string{parts[0]}, parts[2:]...)
	return model.ObjectReference(domain + "/" + strings.Join(path, "."))
}

// commandTerminationReport builds the InformationReport carrying a
// positive CommandTermination+ for an enhanced-security operate.
func commandTerminationReport(domain, item string, oper *mms.Value) *asn1.Element {
	return asn1.Cons(asn1.ContextConstructed(0), // informationReport [0]
		asn1.Cons(asn1.ContextConstructed(0), // variableAccessSpec: listOfVariable [0]
			asn1.Cons(asn1.TagSequence,
				asn1.Cons(asn1.ContextConstructed(0), domainSpecificName(domain, item)))),
		asn1.Cons(asn1.ContextConstructed(0), mms.DataElement(oper)), // listOfAccessResult [0]
	)
}
