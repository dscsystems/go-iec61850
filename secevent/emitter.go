package secevent

// Emitter is what a protocol endpoint holds to report events: a dispatcher
// plus the protocol and role it stamps on each event. A nil Emitter, or one
// without a dispatcher, reports nothing, so endpoints call it unguarded and
// test Enabled only before work done just for the event.
type Emitter struct {
	d        *Dispatcher
	protocol string
	role     string
}

// NewEmitter returns an emitter submitting to d, or nil when d is nil.
func NewEmitter(d *Dispatcher, protocol, role string) *Emitter {
	if d == nil {
		return nil
	}
	return &Emitter{d: d, protocol: protocol, role: role}
}

// Enabled reports whether events reach a dispatcher.
func (m *Emitter) Enabled() bool { return m != nil && m.d != nil }

// Dispatcher is the dispatcher m submits to.
func (m *Emitter) Dispatcher() *Dispatcher {
	if m == nil {
		return nil
	}
	return m.d
}

// Emit submits e, filling Protocol and Role when unset.
func (m *Emitter) Emit(e Event) {
	if !m.Enabled() {
		return
	}
	if e.Protocol == "" {
		e.Protocol = m.protocol
	}
	if e.Role == "" {
		e.Role = m.role
	}
	m.d.Submit(e)
}

// Reporter is implemented by connections and subscribers that let
// application code report events in their context: a control handler
// refusing for a reason of its own, a write handler, an application that
// knows a value is implausible.
type Reporter interface {
	// ReportCyberEvent submits e, filling the peer, session, protocol and
	// role of the reporter where e leaves them unset.
	ReportCyberEvent(e Event)
}

// Report submits e through r when r is a Reporter, and says whether it was.
// It suits handlers given a connection as an interface value.
func Report(r any, e Event) bool {
	rep, ok := r.(Reporter)
	if ok && rep != nil {
		rep.ReportCyberEvent(e)
	}
	return ok
}
