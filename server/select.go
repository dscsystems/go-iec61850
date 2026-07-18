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
}

// selectSBO reserves a control object for the connection (SBO with normal
// security). It returns the object reference on success or "" if the
// object is already selected by another client. Not applicable to
// direct-control objects, which have no SBO attribute.
func (s *Server) selectSBO(ref model.ObjectReference, conn *mms.ServerConn) string {
	s.selMu.Lock()
	defer s.selMu.Unlock()
	if s.selections == nil {
		s.selections = make(map[model.ObjectReference]*selection)
	}
	if sel, ok := s.selections[ref]; ok && sel.conn != conn && time.Now().Before(sel.expiry) {
		return "" // reserved by another client
	}
	s.selections[ref] = &selection{conn: conn, expiry: time.Now().Add(selectTimeout)}
	return string(ref)
}

// isSelectedBy reports whether ref is currently selected by conn.
func (s *Server) isSelectedBy(ref model.ObjectReference, conn *mms.ServerConn) bool {
	s.selMu.Lock()
	defer s.selMu.Unlock()
	sel, ok := s.selections[ref]
	return ok && sel.conn == conn && time.Now().Before(sel.expiry)
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
