package client

import (
	"fmt"
	"strings"
	"sync"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// LastApplError is the diagnosis a server reports when it refuses a
// control, ahead of the negative response (IEC 61850-8-1).
type LastApplError struct {
	CntrlObj string // the control variable, "LD/LN$CO$DO$Oper"
	// Error is 0 no error, 1 unknown, 2 timeout test not ok, 3 operator
	// test not ok; the reason for a refusal is in AddCause.
	Error    int
	Origin   model.OrCat
	OrIdent  []byte
	CtlNum   uint8
	AddCause model.AddCause
}

// LastApplError returns the most recent LastApplError the server reported
// on this association, and whether there has been one. Operate, Select and
// Cancel already put its AddCause in their ControlError; this is for
// control structures written directly.
func (c *Client) LastApplError() (LastApplError, bool) {
	if c.ctl == nil {
		return LastApplError{}, false
	}
	c.ctl.mu.Lock()
	defer c.ctl.mu.Unlock()
	return c.ctl.latest, c.ctl.hasLatest
}

// controlReports follows the control-related reports of an association:
// the LastApplError that precedes a negative control response, and the
// CommandTermination that concludes an enhanced-security operate.
//
// Reports are handled on the reader goroutine in the order the server sent
// them, and a server sends a LastApplError before the negative response it
// explains, so the diagnosis is recorded by the time that response is
// returned to the caller.
type controlReports struct {
	mu        sync.Mutex
	last      map[string]LastApplError // by CntrlObj, "LD/LN$CO$DO$Oper"
	latest    LastApplError            // the most recent of any object
	hasLatest bool
	waiters   map[string]chan model.AddCause // CommandTermination awaited, by terminationKey
}

func newControlReports() *controlReports {
	return &controlReports{
		last:    make(map[string]LastApplError),
		waiters: make(map[string]chan model.AddCause),
	}
}

// terminationKey names one operate: the Oper variable and its ctlNum.
func terminationKey(oper string, ctlNum uint8) string {
	return fmt.Sprintf("%s#%d", oper, ctlNum)
}

// handle inspects an information report for control reports:
//
//	LastApplError              a refused select, operate or cancel
//	Oper                       CommandTermination+
//	LastApplError, Oper        CommandTermination-
func (cr *controlReports) handle(ir *mms.InformationReport) {
	if ir.IsVMDNamed || len(ir.VarRefs) == 0 || len(ir.VarRefs) != len(ir.Values) {
		return
	}
	var lae *LastApplError
	operAt := -1
	for i, ref := range ir.VarRefs {
		switch {
		case ref.Domain == "" && ref.Item == "LastApplError":
			if e, ok := parseLastApplError(ir.Values[i]); ok {
				lae = &e
			}
		case ref.Domain != "" && strings.HasSuffix(ref.Item, "$Oper"):
			operAt = i
		}
	}

	cr.mu.Lock()
	defer cr.mu.Unlock()
	if lae != nil {
		cr.last[lae.CntrlObj] = *lae
		cr.latest, cr.hasLatest = *lae, true
	}
	if operAt < 0 {
		return
	}
	oper := ir.Values[operAt]
	if oper == nil || oper.Type() != mms.TypeStructure || oper.Len() < 3 {
		return
	}
	key := terminationKey(ir.VarRefs[operAt].String(), uint8(oper.Index(2).Uint64()))
	ch, ok := cr.waiters[key]
	if !ok {
		return
	}
	cause := model.AddCauseNone
	if lae != nil {
		cause = lae.AddCause
	}
	select {
	case ch <- cause:
	default:
	}
}

// parseLastApplError decodes { CntrlObj, Error, Origin, ctlNum, AddCause }.
func parseLastApplError(v *mms.Value) (LastApplError, bool) {
	if v == nil || v.Type() != mms.TypeStructure || v.Len() < 5 {
		return LastApplError{}, false
	}
	e := LastApplError{
		CntrlObj: v.Index(0).Text(),
		Error:    int(v.Index(1).Int64()),
		CtlNum:   uint8(v.Index(3).Uint64()),
		AddCause: model.AddCause(v.Index(4).Int64()),
	}
	if o := v.Index(2); o != nil && o.Type() == mms.TypeStructure && o.Len() >= 2 {
		e.Origin = model.OrCat(o.Index(0).Int64())
		e.OrIdent = append([]byte(nil), o.Index(1).Bytes()...)
	}
	return e, true
}

// lastApplErrorFor returns the cause a server gave for refusing the
// control variable cntrlObj ("LD/LN$CO$DO$Oper") with ctlNum, or
// AddCauseUnknown when it gave none.
func (cr *controlReports) lastApplErrorFor(cntrlObj string, ctlNum uint8) model.AddCause {
	cr.mu.Lock()
	defer cr.mu.Unlock()
	if e, ok := cr.last[cntrlObj]; ok && e.CtlNum == ctlNum {
		return e.AddCause
	}
	return model.AddCauseUnknown
}

// await registers interest in the CommandTermination of the operate of
// oper ("LD/LN$CO$DO$Oper") with ctlNum. It must be called before the
// operate is sent; the returned func releases the registration.
func (cr *controlReports) await(oper string, ctlNum uint8) (<-chan model.AddCause, func()) {
	key := terminationKey(oper, ctlNum)
	ch := make(chan model.AddCause, 1)
	cr.mu.Lock()
	cr.waiters[key] = ch
	cr.mu.Unlock()
	return ch, func() {
		cr.mu.Lock()
		if cr.waiters[key] == ch {
			delete(cr.waiters, key)
		}
		cr.mu.Unlock()
	}
}
