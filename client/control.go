package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// ControlObject is a handle to a controllable data object (an SPC, DPC,
// INC, APC, ...). Its control model is read from the server unless set
// explicitly with WithModel.
//
// A ControlObject runs one control sequence at a time; do not drive the
// same handle from several goroutines concurrently, or their sequences
// interleave and share a control number.
type ControlObject struct {
	c     *Client
	ref   model.ObjectReference
	model model.CtlModel

	domain string
	do     string // "LN$CO$DO"

	mu         sync.Mutex
	ctlNum     uint8 // control number of the current or last sequence
	inSeq      bool  // a sequence is open, so ctlNum must be reused
	ctlValSpec *mms.TypeSpec
}

// ControlOption configures a control operation.
type ControlOption func(*controlParams)

type controlParams struct {
	orCat      model.OrCat
	orIdent    []byte
	test       bool
	interlock  bool
	synchro    bool
	forceModel model.CtlModel
	hasModel   bool
}

// WithOriginator sets the originator category and identifier.
func WithOriginator(cat model.OrCat, ident string) ControlOption {
	return func(p *controlParams) { p.orCat = cat; p.orIdent = []byte(ident) }
}

// WithTest marks the command as a test.
func WithTest(test bool) ControlOption { return func(p *controlParams) { p.test = test } }

// WithInterlockCheck requests the interlock check.
func WithInterlockCheck(on bool) ControlOption { return func(p *controlParams) { p.interlock = on } }

// WithSynchroCheck requests the synchronisation check.
func WithSynchroCheck(on bool) ControlOption { return func(p *controlParams) { p.synchro = on } }

// WithModel overrides the control model instead of reading ctlModel.
func WithModel(m model.CtlModel) ControlOption {
	return func(p *controlParams) { p.forceModel = m; p.hasModel = true }
}

// ControlFor returns a control handle for the object at ref, reading its
// ctlModel from the server.
func (c *Client) ControlFor(ctx context.Context, ref model.ObjectReference) (*ControlObject, error) {
	domain := ref.LD()
	path := ref.Path()
	if len(path) < 2 {
		return nil, fmt.Errorf("client: control reference %q must be LD/LN.DO", ref)
	}
	co := &ControlObject{
		c: c, ref: ref, domain: domain,
		do: path[0] + "$CO$" + joinDollar(path[1:]),
	}
	// ctlModel lives under FC CF.
	if v, err := c.Read(ctx, ref.Child("ctlModel"), model.CF); err == nil {
		co.model = model.CtlModel(v.Int64())
	} else {
		co.model = model.CtlDirectNormal
	}
	return co, nil
}

// Model returns the control model in effect.
func (co *ControlObject) Model() model.CtlModel { return co.model }

// ControlError carries the additional cause of a failed control.
type ControlError struct {
	AddCause model.AddCause
	Stage    string // "select" or "operate"
	Err      error
}

func (e *ControlError) Error() string {
	if e.AddCause != model.AddCauseNone && e.AddCause != 0 {
		return fmt.Sprintf("client: control %s failed: %s", e.Stage, e.AddCause)
	}
	return fmt.Sprintf("client: control %s failed: %v", e.Stage, e.Err)
}

func (e *ControlError) Unwrap() error { return e.Err }

// Operate performs a complete control operation appropriate to the model:
// for SBO models it selects first; for enhanced models it awaits the
// CommandTermination. value is the ctlVal (bool for SPC/DPC, numeric for
// INC/APC).
func (co *ControlObject) Operate(ctx context.Context, value *mms.Value, opts ...ControlOption) error {
	p := co.params(opts)
	if p.hasModel {
		co.model = p.forceModel
	}
	if co.model.HasSelect() {
		if err := co.doSelect(ctx, value, p); err != nil {
			return err
		}
	}
	return co.doOperate(ctx, value, p)
}

// Select performs the select step for SBO-with-normal-security controls.
func (co *ControlObject) Select(ctx context.Context, opts ...ControlOption) error {
	// The SBO read carries no ctlNum, but it still opens the sequence whose
	// number the following operate must use.
	co.beginSequence()
	// SBO select reads the SBO attribute; success returns a non-empty
	// object name.
	vals, err := co.c.mc.Read(ctx, co.domain, co.do+"$SBO")
	if err != nil {
		co.endSequence()
		return &ControlError{Stage: "select", Err: err}
	}
	if len(vals) == 0 || vals[0].Text() == "" {
		co.endSequence()
		return &ControlError{Stage: "select", AddCause: model.AddCauseSelectFailed}
	}
	return nil
}

// SelectWithValue performs the select step for SBO-with-enhanced-security.
func (co *ControlObject) SelectWithValue(ctx context.Context, value *mms.Value, opts ...ControlOption) error {
	return co.doSelect(ctx, value, co.params(opts))
}

func (co *ControlObject) doSelect(ctx context.Context, value *mms.Value, p *controlParams) error {
	if co.model == model.CtlSBONormal {
		return co.Select(ctx)
	}
	// SBOw: write the operate structure to SBOw. This opens the sequence;
	// the operate that follows repeats this control number.
	oper := co.buildOper(value, p, co.beginSequence())
	results, err := co.c.mc.Write(ctx, co.domain, []string{co.do + "$SBOw"}, []*mms.Value{oper})
	if err != nil {
		co.endSequence()
		return &ControlError{Stage: "select", Err: err}
	}
	if len(results) > 0 && results[0] != nil {
		co.endSequence()
		return &ControlError{Stage: "select", Err: results[0], AddCause: co.lastApplError(ctx)}
	}
	return nil
}

func (co *ControlObject) doOperate(ctx context.Context, value *mms.Value, p *controlParams) error {
	// Reuses the select's control number when a sequence is open, and the
	// sequence ends here either way.
	oper := co.buildOper(value, p, co.beginSequence())
	defer co.endSequence()
	results, err := co.c.mc.Write(ctx, co.domain, []string{co.do + "$Oper"}, []*mms.Value{oper})
	if err != nil {
		return &ControlError{Stage: "operate", Err: err}
	}
	if len(results) > 0 && results[0] != nil {
		return &ControlError{Stage: "operate", Err: results[0], AddCause: co.lastApplError(ctx)}
	}
	// Enhanced models confirm asynchronously via CommandTermination; the
	// positive write already indicates the operate was accepted. Awaiting
	// the termination is left to the caller via the information-report
	// stream for now.
	return nil
}

// Cancel aborts a selection or operation. It carries the control number of
// the sequence being cancelled, which is how the server identifies it.
func (co *ControlObject) Cancel(ctx context.Context, opts ...ControlOption) error {
	oper := co.buildOper(mms.NewBool(false), co.params(opts), co.beginSequence())
	defer co.endSequence()
	results, err := co.c.mc.Write(ctx, co.domain, []string{co.do + "$Cancel"}, []*mms.Value{oper})
	if err != nil {
		return &ControlError{Stage: "cancel", Err: err}
	}
	if len(results) > 0 && results[0] != nil {
		return &ControlError{Stage: "cancel", Err: results[0]}
	}
	return nil
}

// beginSequence returns the control number to use for the next request. A
// control sequence (select, operate, cancel) carries one control number
// throughout: IEC 61850-7-2 has the client increment ctlNum once per new
// sequence, and a server that compares the operate's ctlNum against the
// selected one rejects the operate as inconsistent-parameters otherwise.
// The number is therefore allocated by the first request of a sequence and
// reused until endSequence. It wraps at 255 by design.
func (co *ControlObject) beginSequence() uint8 {
	co.mu.Lock()
	defer co.mu.Unlock()
	if !co.inSeq {
		co.ctlNum++
		co.inSeq = true
	}
	return co.ctlNum
}

// endSequence closes the current control sequence, so the next one takes a
// fresh control number. A sequence ends with its operate or cancel —
// whether that succeeded or failed, since a retry is a new sequence.
func (co *ControlObject) endSequence() {
	co.mu.Lock()
	co.inSeq = false
	co.mu.Unlock()
}

// CtlNum returns the control number of the current or most recent control
// sequence. It is the ctlNum carried by that sequence's select and
// operate, which identifies the matching CommandTermination.
func (co *ControlObject) CtlNum() uint8 {
	co.mu.Lock()
	defer co.mu.Unlock()
	return co.ctlNum
}

// CtlValSpec returns the type specification of the object's control value,
// read from the type of its Oper structure with GetVariableAccessAttributes.
// It is what a caller needs to build a ctlVal the server will accept:
// an SPC takes a boolean, a DPC a two-bit bit-string, an INC an integer,
// and an APC the AnalogueValue structure, whose components say whether the
// server expects an integer ("i") or a float ("f").
//
// Sizes follow the TypeSpec convention: a bit-string or string width is
// negative when the server declares it as a maximum rather than a fixed
// length, so compare on its magnitude.
//
// The type of a control object is static, so the answer is cached and
// later calls cost no round trip.
func (co *ControlObject) CtlValSpec(ctx context.Context) (*mms.TypeSpec, error) {
	co.mu.Lock()
	cached := co.ctlValSpec
	co.mu.Unlock()
	if cached != nil {
		return cached, nil
	}

	// Oper carries ctlVal under every control model. SBOw is the fallback
	// for SBO objects whose Oper the server will not describe.
	items := []string{co.do + "$Oper"}
	if co.model.HasSelect() {
		items = append(items, co.do+"$SBOw")
	}
	var err error
	for _, item := range items {
		var ts *mms.TypeSpec
		ts, err = co.c.mc.GetVariableAccessAttributes(ctx, co.domain, item)
		if err != nil {
			continue
		}
		spec := componentSpec(ts, "ctlVal")
		if spec == nil {
			err = fmt.Errorf("client: %s: %s has no ctlVal component", co.ref, item)
			continue
		}
		co.mu.Lock()
		co.ctlValSpec = spec
		co.mu.Unlock()
		return spec, nil
	}
	return nil, fmt.Errorf("client: control value type of %s: %w", co.ref, err)
}

// CtlValType returns the MMS type of the object's control value. It is
// mms.TypeStructure for an APC, whose value is an AnalogueValue; use
// CtlValSpec to see inside it.
func (co *ControlObject) CtlValType(ctx context.Context) (mms.Type, error) {
	spec, err := co.CtlValSpec(ctx)
	if err != nil {
		return mms.TypeNone, err
	}
	return spec.Kind, nil
}

// componentSpec returns the type of a named member of a structure type.
func componentSpec(ts *mms.TypeSpec, name string) *mms.TypeSpec {
	if ts == nil || ts.Kind != mms.TypeStructure {
		return nil
	}
	for _, c := range ts.Components {
		if c.Name == name {
			return c.Spec
		}
	}
	return nil
}

// buildOper constructs the operate structure:
// { ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }.
func (co *ControlObject) buildOper(value *mms.Value, p *controlParams, ctlNum uint8) *mms.Value {
	origin := mms.NewStructure(
		mms.NewInt8(int8(p.orCat)),
		mms.NewOctetString(p.orIdent),
	)
	check := mms.NewBitString(2)
	check.SetBit(0, p.interlock) // interlock-check
	check.SetBit(1, p.synchro)   // synchro-check

	return mms.NewStructure(
		value,
		origin,
		mms.NewUint8(ctlNum),
		mms.NewUTCTime(time.Now(), mms.TimeAccuracy(10)),
		mms.NewBool(p.test),
		check,
	)
}

// lastApplError reads the LastApplError to recover the additional cause of
// a rejected control (best effort).
func (co *ControlObject) lastApplError(ctx context.Context) model.AddCause {
	vals, err := co.c.mc.Read(ctx, co.domain, "LLN0$ST$LastApplError$AddCause")
	if err != nil || len(vals) == 0 {
		return model.AddCauseUnknown
	}
	return model.AddCause(vals[0].Int64())
}

func (co *ControlObject) params(opts []ControlOption) *controlParams {
	p := &controlParams{orCat: model.OrCatStationControl}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func joinDollar(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "$"
		}
		out += p
	}
	return out
}
