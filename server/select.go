package server

import (
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// selectTimeout is how long an SBO reservation is held without an operate.
const selectTimeout = 30 * time.Second

// selection is an active SBO reservation of a control object.
type selection struct {
	conn   *mms.ServerConn
	expiry time.Time
	// ctlNum is the control number the select carried, and hasCtlNum says
	// whether it carried one at all: the SBOw form does, the SBO read form
	// has no parameters to carry it in.
	ctlNum    uint8
	hasCtlNum bool
}

// selectSBO reserves a control object for the connection (SBO with normal
// security). It returns the object reference on success or "" if the
// object is already selected by another client. Not applicable to
// direct-control objects, which have no SBO attribute.
func (s *Server) selectSBO(ref model.ObjectReference, conn *mms.ServerConn) string {
	if !s.reserve(ref, conn, 0, false) {
		return "" // reserved by another client
	}
	return string(ref)
}

// selectWithValue reserves a control object for an SBOw select, recording
// the control number the operate has to repeat.
func (s *Server) selectWithValue(ref model.ObjectReference, conn *mms.ServerConn, ctlNum uint8) bool {
	return s.reserve(ref, conn, ctlNum, true)
}

func (s *Server) reserve(ref model.ObjectReference, conn *mms.ServerConn, ctlNum uint8, hasCtlNum bool) bool {
	s.selMu.Lock()
	defer s.selMu.Unlock()
	if s.selections == nil {
		s.selections = make(map[model.ObjectReference]*selection)
	}
	if sel, ok := s.selections[ref]; ok && sel.conn != conn && time.Now().Before(sel.expiry) {
		return false
	}
	s.selections[ref] = &selection{
		conn:      conn,
		expiry:    time.Now().Add(selectTimeout),
		ctlNum:    ctlNum,
		hasCtlNum: hasCtlNum,
	}
	return true
}

// checkSelection validates an operate against the reservation held for ref.
// IEC 61850-7-2 has one control sequence carry one control number: the
// operate must come from the connection that selected the object and must
// repeat the select's ctlNum, or it belongs to some other sequence and the
// server must not execute it.
func (s *Server) checkSelection(ref model.ObjectReference, conn *mms.ServerConn, ctlNum uint8) model.AddCause {
	s.selMu.Lock()
	defer s.selMu.Unlock()
	sel, ok := s.selections[ref]
	if !ok || sel.conn != conn || !time.Now().Before(sel.expiry) {
		return model.AddCauseObjectNotSelected
	}
	if sel.hasCtlNum && sel.ctlNum != ctlNum {
		return model.AddCauseInconsistentParameters
	}
	return model.AddCauseNone
}

// checkCancel validates a cancel the same way, except that cancelling when
// nothing is reserved is allowed: a direct control has no reservation to
// name, and there is nothing to protect.
func (s *Server) checkCancel(ref model.ObjectReference, conn *mms.ServerConn, ctlNum uint8) model.AddCause {
	s.selMu.Lock()
	defer s.selMu.Unlock()
	sel, ok := s.selections[ref]
	if !ok || !time.Now().Before(sel.expiry) {
		return model.AddCauseNone
	}
	if sel.conn != conn {
		// Another client holds it; its sequence is not this one's to end.
		return model.AddCauseObjectNotSelected
	}
	if sel.hasCtlNum && sel.ctlNum != ctlNum {
		return model.AddCauseInconsistentParameters
	}
	return model.AddCauseNone
}

// clearSelection releases any reservation of ref (after operate/cancel).
func (s *Server) clearSelection(ref model.ObjectReference) {
	s.selMu.Lock()
	delete(s.selections, ref)
	s.selMu.Unlock()
}

// releaseSelections drops all reservations held by a closing connection.
func (s *Server) releaseSelections(conn *mms.ServerConn) {
	s.selMu.Lock()
	for ref, sel := range s.selections {
		if sel.conn == conn {
			delete(s.selections, ref)
		}
	}
	s.selMu.Unlock()
}

// requiresSelection reports whether ref uses an SBO control model.
func (s *Server) requiresSelection(ref model.ObjectReference) bool {
	cm := s.model.Attribute(ref.Child("ctlModel"), model.CF)
	return cm != nil && cm.Value != nil && model.CtlModel(cm.Value.Int64()).HasSelect()
}
