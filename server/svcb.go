package server

import (
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Sampled-value control blocks (IEC 61850-7-2 clause 16, mapped by
// IEC 61850-8-1/9-2) are live: a client enables an MSVCB or a USVCB with
// SvEna and reserves a USVCB with Resv. The IEC 61850-9-2 mapping makes
// only those two writable, as libiec61850 does; the rest of a block is its
// configuration. A reserved USVCB belongs to the association that reserved
// it, and every other one is refused with temporarily-unavailable until
// it is released, by writing Resv false or by the association ending —
// which also disables the block, since the stream was that client's.
//
// The server does not publish the samples itself: which values are
// sampled, at what rate and from which clock is the application's. It
// hears of every change through OnSVControl and runs a publisher, for
// instance sv.NewLEPublisherFromModel, while the block is enabled.

// SVControlEvent describes a change of a sampled-value control block made
// by a client or by the end of its association.
type SVControlEvent struct {
	Device *model.LogicalDevice
	Node   *model.LogicalNode
	Block  *model.SVControl
	// Unicast is set for a USVCB (FC US).
	Unicast bool
	// Enabled is SvEna after the change.
	Enabled bool
	// Reserved is Resv after the change; always false for an MSVCB.
	Reserved bool
	// Conn is the association that holds the reservation, nil when none
	// does. A unicast stream goes to the block's DstAddress; an
	// application that addresses the reserving client instead (an R-SV
	// block with no fixed destination, say) finds it here.
	Conn *mms.ServerConn
}

// OnSVControl registers a handler called after a client changes SvEna or
// Resv of a sampled-value control block, and when a USVCB is released
// because its association ended. It runs outside the model lock, one call
// at a time and in the order the changes were made; it must not block.
// Registering a second handler replaces the first.
func (s *Server) OnSVControl(h func(SVControlEvent)) {
	s.svMu.Lock()
	s.svH = h
	s.svMu.Unlock()
}

// svcbState is the runtime state of one sampled-value control block.
type svcbState struct {
	ld      *model.LogicalDevice
	ln      *model.LogicalNode
	sc      *model.SVControl
	unicast bool
	svEna   *model.DataAttribute
	resv    *model.DataAttribute // nil for an MSVCB
	owner   *mms.ServerConn      // the reserving association
}

func (st *svcbState) event() SVControlEvent {
	ev := SVControlEvent{Device: st.ld, Node: st.ln, Block: st.sc, Unicast: st.unicast,
		Enabled: st.svEna.Value.Bool(), Conn: st.owner}
	if st.resv != nil {
		ev.Reserved = st.resv.Value.Bool()
	}
	return ev
}

// buildSVCBStates indexes the sampled-value control blocks
// materialiseControlBlocks put in the model, by domain + "\x00" +
// "LN$MS$name" (or US).
func buildSVCBStates(m *model.Model) map[string]*svcbState {
	out := make(map[string]*svcbState)
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, sc := range ln.SVControls {
				for _, do := range ln.Objects {
					if do.Name != sc.Name || (do.CDC != "MSVCB" && do.CDC != "USVCB") {
						continue
					}
					st := &svcbState{ld: ld, ln: ln, sc: sc, unicast: do.CDC == "USVCB"}
					for _, a := range do.Attributes {
						switch a.Name {
						case "SvEna":
							st.svEna = a
						case "Resv":
							st.resv = a
						}
					}
					fc := "MS"
					if st.unicast {
						fc = "US"
					}
					out[ld.Name+"\x00"+ln.Name+"$"+fc+"$"+sc.Name] = st
					break
				}
			}
		}
	}
	return out
}

// svcbKey reports whether item ("LN$MS$name[$attr]" or "LN$US$...")
// addresses a sampled-value control block, returning it and the attribute.
func (s *Server) svcbKey(domain, item string) (st *svcbState, attr string, ok bool) {
	parts := strings.Split(item, "$")
	if len(parts) < 3 || (parts[1] != "MS" && parts[1] != "US") {
		return nil, "", false
	}
	st = s.svcbs[domain+"\x00"+strings.Join(parts[:3], "$")]
	if st == nil {
		return nil, "", false
	}
	if len(parts) >= 4 {
		attr = parts[3]
	}
	return st, attr, true
}

// checkSVCBWrite decides whether conn may write attr of a sampled-value
// control block: 0xff allows it. Called with the model write lock held.
func (st *svcbState) checkWrite(attr string, v *mms.Value, conn *mms.ServerConn) byte {
	if st.owner != nil && st.owner != conn {
		return byte(mms.AccessTemporarilyUnavailable)
	}
	switch {
	case attr == "SvEna", attr == "Resv" && st.unicast:
		if v.Type() != mms.TypeBoolean {
			return byte(mms.AccessTypeInconsistent)
		}
		return 0xff
	case st.svEna.Value.Bool():
		return byte(mms.AccessTemporarilyUnavailable)
	}
	return byte(mms.AccessObjectAccessDenied)
}

// onWrite applies a stored write and returns the event to report, if the
// block's state changed. Called with the model write lock held.
func (st *svcbState) onWrite(attr string, old bool, conn *mms.ServerConn) (SVControlEvent, bool) {
	var now bool
	switch attr {
	case "SvEna":
		now = st.svEna.Value.Bool()
	case "Resv":
		now = st.resv.Value.Bool()
		if now {
			st.owner = conn
		} else {
			st.owner = nil
		}
	default:
		return SVControlEvent{}, false
	}
	if now == old {
		return SVControlEvent{}, false
	}
	return st.event(), true
}

// releaseSVCBs frees the USVCBs conn reserved and disables them, as its
// association has ended, and queues the changes. Called with the model
// write lock held.
func (s *Server) releaseSVCBs(conn *mms.ServerConn) {
	for _, st := range s.svcbs {
		if st.owner != conn {
			continue
		}
		st.owner = nil
		st.resv.Value = mms.NewBool(false)
		st.svEna.Value = mms.NewBool(false)
		s.queueSV(st.event())
	}
}

// queueSV queues sampled-value control block changes for flushSV, in the
// order they were made. Called with the model write lock held.
func (s *Server) queueSV(evs ...SVControlEvent) {
	if len(evs) == 0 {
		return
	}
	s.svMu.Lock()
	s.svQueue = append(s.svQueue, evs...)
	s.svMu.Unlock()
}

// flushSV delivers the queued changes to the OnSVControl handler, one
// call at a time. It must be called without the model lock.
func (s *Server) flushSV() {
	s.svDeliver.Lock()
	defer s.svDeliver.Unlock()
	for {
		s.svMu.Lock()
		q, h := s.svQueue, s.svH
		s.svQueue = nil
		s.svMu.Unlock()
		if len(q) == 0 {
			return
		}
		for _, ev := range q {
			if h != nil {
				h(ev)
			}
		}
	}
}
