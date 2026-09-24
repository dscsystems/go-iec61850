package server

import (
	"strings"
	"sync"
	"time"

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

	// Conn is the association the command arrived on, nil only for a
	// command with no association behind it. Origin and OrIdent are what
	// the client claims about itself; this is what the server observed,
	// which is what an audit trail — the originator's IP address — has to
	// be built from. Conn.Peer is the address as a net.Addr, so a
	// *net.TCPAddr yields the IP on its own.
	Conn *mms.ServerConn
	// Peer is Conn's address in text, empty when there is no association.
	Peer string

	// term is the CommandTermination owed for an enhanced-security
	// operate; see DeferTermination.
	term *termination
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
//
// A refused command is answered negatively and, ahead of that answer, with
// a LastApplError report naming the cause (IEC 61850-8-1).
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
	// The control structure is written whole; its members are not
	// separately writable.
	if !strings.HasSuffix(item, "$"+phase) || v == nil || v.Type() != mms.TypeStructure {
		return true, byte(mms.AccessTypeInconsistent)
	}
	// base is "LN$CO$DO..."; build the object reference (drop the CO tag).
	ref := controlRef(domain, base)
	ctlItem := base + "$" + phase
	ctx := decodeOper(ref, v, conn)
	ctx.Select = phase == "SBOw"
	refuse := func(cause model.AddCause) (bool, byte) {
		h.sendLastApplError(conn, domain, ctlItem, ctx, cause)
		return true, byte(mms.AccessObjectAccessDenied)
	}

	cm, declared := h.ctlModel(ref)
	switch {
	case declared && cm == model.CtlStatusOnly:
		// A status-only object offers no control service.
		return refuse(model.AddCauseNotSupported)
	case phase == "SBOw" && declared && cm != model.CtlSBOEnhanced:
		// Select-with-value belongs to SBO with enhanced security only.
		return refuse(model.AddCauseNotSupported)
	}

	if phase == "Cancel" {
		if cause := h.s.checkCancel(ref, conn, ctx.CtlNum); cause != model.AddCauseNone {
			return refuse(cause)
		}
		h.s.clearSelection(ref)
		return true, 0xff
	}

	// An SBO operate must belong to a live selection: made by this
	// connection, and carrying that select's control number. Both
	// security levels are checked: normal security selects with an SBO
	// read, which carries no ctlNum, so only the reservation is verified
	// there.
	if phase == "Oper" && h.s.requiresSelection(ref) {
		if cause := h.s.checkSelection(ref, conn, ctx.CtlNum); cause != model.AddCauseNone {
			return refuse(cause)
		}
	}

	// An enhanced-security operate is concluded by a CommandTermination,
	// which the handler may take over (DeferTermination).
	var term *termination
	if phase == "Oper" && declared && cm.Enhanced() && conn != nil {
		term = h.newTermination(conn, domain, ctlItem, ctx, v)
		ctx.term = term
	}

	h.s.ctlMu.RLock()
	hdlr := h.s.controls[ref]
	h.s.ctlMu.RUnlock()

	cause := model.AddCauseNone
	if hdlr != nil {
		cause = hdlr(ctx)
	}
	if cause != model.AddCauseNone {
		if term != nil {
			term.discard()
		}
		return refuse(cause)
	}

	if ctx.Select {
		// SBOw reserves the object for this connection, under the control
		// number the operate will have to repeat. A reservation another
		// client is holding is not ours to take.
		if !h.s.selectWithValue(ref, conn, ctx.CtlNum) {
			return refuse(model.AddCauseObjectAlreadySelected)
		}
		return true, 0xff
	}
	// Apply the operate: set the sibling stVal under FC ST.
	h.applyControl(ref, ctx.Value)
	h.s.clearSelection(ref)
	if term != nil {
		if term.isDeferred() {
			term.supervise(h.s.operTimeout(ref))
		} else {
			// Sent now, it is held until the operate's response is out.
			term.finish(model.AddCauseNone)
		}
	}
	return true, 0xff
}

// ctlModel is the object's control model, and whether it declares one.
// An object without ctlModel is treated as direct with normal security.
func (h *handler) ctlModel(ref model.ObjectReference) (model.CtlModel, bool) {
	cm := h.s.model.Attribute(ref.Child("ctlModel"), model.CF)
	if cm == nil || cm.Value == nil {
		return model.CtlDirectNormal, false
	}
	return model.CtlModel(cm.Value.Int64()), true
}

// applyControl reflects an accepted operate into the process image: the
// controllable object's stVal (FC ST) becomes the control value.
func (h *handler) applyControl(ref model.ObjectReference, ctlVal *mms.Value) {
	stRef := ref.Child("stVal")
	if da := h.s.model.Attribute(stRef, model.ST); da != nil && len(da.Children) == 0 && ctlVal != nil {
		old := da.Value
		da.Value = ctlVal.Clone()
		// The new status reports like any process change.
		if h.changes != nil {
			h.changes.record(stRef, da, old, da.Value)
		}
	}
}

func (h *handler) isEnhanced(ref model.ObjectReference) bool {
	cm, declared := h.ctlModel(ref)
	return declared && cm.Enhanced()
}

// termination is the CommandTermination owed for one enhanced-security
// operate. It is sent exactly once: by the server as soon as the operate
// is accepted, or by a handler that deferred it, or on operTimeout.
type termination struct {
	once     sync.Once
	send     func(model.AddCause)
	mu       sync.Mutex
	deferred bool
	timer    *time.Timer
}

func (h *handler) newTermination(conn *mms.ServerConn, domain, ctlItem string, ctx *ControlCtx, oper *mms.Value) *termination {
	log := h.s.log
	return &termination{send: func(cause model.AddCause) {
		var report *asn1.Element
		if cause == model.AddCauseNone {
			report = commandTerminationReport(domain, ctlItem, oper)
		} else {
			report = commandTerminationNegativeReport(domain, ctlItem, oper,
				lastApplErrorValue(domain, ctlItem, ctx, cause))
		}
		if err := conn.SendUnconfirmed(report); err != nil {
			log.Debug("server: command termination send failed", "item", ctlItem, "err", err)
		}
	}}
}

func (t *termination) finish(cause model.AddCause) {
	t.once.Do(func() {
		t.mu.Lock()
		if t.timer != nil {
			t.timer.Stop()
		}
		t.mu.Unlock()
		t.send(cause)
	})
}

// discard drops the termination of an operate that was refused: a
// refused operate is not terminated.
func (t *termination) discard() { t.once.Do(func() {}) }

func (t *termination) isDeferred() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.deferred
}

// supervise terminates negatively with time-limit-over if the deferred
// termination has not come within d (no limit when d is zero).
func (t *termination) supervise(d time.Duration) {
	if d <= 0 {
		return
	}
	t.mu.Lock()
	t.timer = time.AfterFunc(d, func() { t.finish(model.AddCauseTimeLimitOver) })
	t.mu.Unlock()
}

// DeferTermination takes over the CommandTermination of an operate on an
// enhanced-security object. The server then does not terminate the
// operate when the handler accepts it; instead the returned function is
// called once execution has ended, with model.AddCauseNone for success
// (CommandTermination+) or the cause of failure (CommandTermination-,
// carrying a LastApplError). It may be called from any goroutine; calls
// after the first are ignored. If it has not been called within the
// object's operTimeout, the server terminates the operate negatively with
// time-limit-over.
//
// For a select, a cancel or a normal-security object there is no
// termination to defer, and the returned function does nothing.
func (c *ControlCtx) DeferTermination() func(model.AddCause) {
	if c.term == nil {
		return func(model.AddCause) {}
	}
	c.term.mu.Lock()
	c.term.deferred = true
	c.term.mu.Unlock()
	return c.term.finish
}

// sendLastApplError reports why a control was refused, ahead of the
// negative response to it (IEC 61850-8-1): an InformationReport of the
// VMD-specific variable LastApplError.
func (h *handler) sendLastApplError(conn *mms.ServerConn, domain, ctlItem string, ctx *ControlCtx, cause model.AddCause) {
	if conn == nil {
		return
	}
	report := asn1.Cons(asn1.ContextConstructed(0), // informationReport [0]
		asn1.Cons(asn1.ContextConstructed(0), // listOfVariable [0]
			asn1.Cons(asn1.TagSequence,
				asn1.Cons(asn1.ContextConstructed(0), vmdSpecificName("LastApplError")))),
		asn1.Cons(asn1.ContextConstructed(0), // listOfAccessResult [0]
			mms.DataElement(lastApplErrorValue(domain, ctlItem, ctx, cause))),
	)
	if err := conn.SendUnconfirmedFirst(report); err != nil {
		h.s.log.Debug("server: LastApplError send failed", "item", ctlItem, "err", err)
	}
}

// lastApplErrorValue is the LastApplError structure (IEC 61850-8-1):
// { CntrlObj, Error, Origin { orCat, orIdent }, ctlNum, AddCause }. The
// reason is in AddCause; Error stays "no error", as it concerns the test
// of an operate rather than its refusal.
func lastApplErrorValue(domain, ctlItem string, ctx *ControlCtx, cause model.AddCause) *mms.Value {
	return mms.NewStructure(
		mms.NewVisibleString(domain+"/"+ctlItem),
		mms.NewInt8(0),
		mms.NewStructure(mms.NewInt8(int8(ctx.Origin)), mms.NewOctetString([]byte(ctx.OrIdent))),
		mms.NewUint8(ctx.CtlNum),
		mms.NewInt8(int8(cause)),
	)
}

func vmdSpecificName(name string) *asn1.Element {
	return asn1.Prim(asn1.ContextPrimitive(0), []byte(name))
}

// decodeOper extracts the fields of an operate/SBOw structure:
// { ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }.
// conn is recorded alongside them so a handler can tell who sent the
// command rather than who it says it is.
func decodeOper(ref model.ObjectReference, v *mms.Value, conn *mms.ServerConn) *ControlCtx {
	ctx := &ControlCtx{Ref: ref, Conn: conn}
	if conn != nil && conn.Peer != nil {
		ctx.Peer = conn.Peer.String()
	}
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
		// Check per IEC 61850-7-2 Table 51: synchrocheck is bit 0.
		ctx.Synchro = ck.Bit(0)
		ctx.Interlock = ck.Bit(1)
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

// commandTerminationNegativeReport builds CommandTermination- (IEC
// 61850-8-1): an InformationReport of LastApplError followed by the Oper
// it terminates.
func commandTerminationNegativeReport(domain, item string, oper, lastApplError *mms.Value) *asn1.Element {
	return asn1.Cons(asn1.ContextConstructed(0), // informationReport [0]
		asn1.Cons(asn1.ContextConstructed(0), // listOfVariable [0]
			asn1.Cons(asn1.TagSequence,
				asn1.Cons(asn1.ContextConstructed(0), vmdSpecificName("LastApplError"))),
			asn1.Cons(asn1.TagSequence,
				asn1.Cons(asn1.ContextConstructed(0), domainSpecificName(domain, item)))),
		asn1.Cons(asn1.ContextConstructed(0), // listOfAccessResult [0]
			mms.DataElement(lastApplError), mms.DataElement(oper)),
	)
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
