package secevent

import (
	"errors"
	"time"
)

// Policy configures the security events of an endpoint and, in later
// versions, the checks that produce them. The zero Policy reports nothing.
// The fields here cover delivery; detection thresholds and enforcement
// are added without changing these.
type Policy struct {
	// Sink receives the events. A *Dispatcher is used as it is, and the
	// endpoint does not close it, so one dispatcher can serve several
	// endpoints; any other sink gets a dispatcher of the endpoint's own,
	// closed with it.
	Sink Sink

	// QueueSize, AggregateWindow and MaxRaw configure the endpoint's own
	// dispatcher (see Options); they are unused with a shared *Dispatcher.
	QueueSize       int
	AggregateWindow time.Duration
	MaxRaw          int

	// RawDecrypted lets Raw carry an MMS PDU decrypted by E2E security.
	// Off by default: the plain PDU may hold what the encryption protects.
	RawDecrypted bool

	// AuditControl reports every control (cmd.received and the command
	// lifecycle), not only refusals. DefaultPolicy turns it on.
	AuditControl bool
}

// DefaultPolicy is report-only: it observes and never enforces. Set Sink
// before use.
func DefaultPolicy() Policy {
	return Policy{AuditControl: true}
}

// Valid checks the policy.
func (p Policy) Valid() error {
	if p.QueueSize < 0 {
		return errors.New("secevent: negative QueueSize")
	}
	if p.Sink == nil {
		return errors.New("secevent: policy without a Sink")
	}
	return nil
}

// Dispatcher returns the dispatcher the policy delivers through, and
// whether the caller owns it (and must close it). With no Sink it returns
// nil.
func (p Policy) Dispatcher() (d *Dispatcher, owned bool) {
	switch s := p.Sink.(type) {
	case nil:
		return nil, false
	case *Dispatcher:
		return s, false
	default:
		return NewDispatcher(s, Options{QueueSize: p.QueueSize, AggregateWindow: p.AggregateWindow, MaxRaw: p.MaxRaw}), true
	}
}
