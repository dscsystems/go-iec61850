package secevent

import (
	"fmt"
	"maps"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Sink receives events. Deliver is called from one goroutine at a time;
// it may block, which slows delivery but never the protocol.
type Sink interface {
	Deliver(Event)
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(Event)

// Deliver calls f.
func (f SinkFunc) Deliver(e Event) { f(e) }

// Options configures a Dispatcher. Zero fields take the defaults.
type Options struct {
	// QueueSize is how many events may wait for the sink (default 1024).
	// Beyond it events are dropped and counted (meta.events_dropped).
	QueueSize int
	// AggregateWindow folds repeats of one event (same kind, session and
	// subject) arriving within it into one, with Count (default 1 s;
	// negative to deliver every event).
	AggregateWindow time.Duration
	// MaxAggregateKeys bounds the aggregation state (default 4096).
	MaxAggregateKeys int
	// MaxRaw bounds the copy of a PDU or frame an event carries (default
	// 64 octets; negative for none).
	MaxRaw int
}

func (o Options) withDefaults() Options {
	if o.QueueSize <= 0 {
		o.QueueSize = 1024
	}
	if o.AggregateWindow == 0 {
		o.AggregateWindow = time.Second
	}
	if o.MaxAggregateKeys <= 0 {
		o.MaxAggregateKeys = 4096
	}
	if o.MaxRaw == 0 {
		o.MaxRaw = 64
	}
	return o
}

// Stats counts what a dispatcher handled.
type Stats struct {
	Submitted  uint64          // events submitted
	Delivered  uint64          // events handed to the sink (aggregates count once)
	Aggregated uint64          // events folded into an aggregate
	Dropped    uint64          // events lost because the queue was full
	SinkPanics uint64          // sink calls that panicked
	ByKind     map[Kind]uint64 // submitted events per kind, folded ones included
	ByCategory map[Category]uint64
}

// Dispatcher queues events for a sink on its own goroutine. Submit never
// blocks. A Dispatcher is itself a Sink, so one can be shared by several
// endpoints: pass it wherever a Sink is taken and close it after them.
type Dispatcher struct {
	sink Sink
	o    Options
	sync bool

	ch   chan Event
	quit chan struct{}
	done chan struct{}
	once sync.Once

	// admit orders submissions with Close: a Submit holds it shared from
	// its closed check to its enqueue, so once Close holds it every
	// admitted event is in the queue the worker drains.
	admit      sync.RWMutex
	closed     bool
	submitted  atomic.Uint64
	dropped    atomic.Uint64
	panics     atomic.Uint64
	delivered  atomic.Uint64
	aggregated atomic.Uint64

	// Owned by the delivery goroutine (or held under smu in sync mode).
	smu         sync.Mutex
	agg         map[aggKey]*aggEntry
	dropsSeen   uint64
	panicReport bool

	statMu     sync.Mutex
	byKind     map[Kind]uint64
	byCategory map[Category]uint64
}

type aggKey struct {
	kind    Kind
	session uint64
	subject string
}

type aggEntry struct {
	until   time.Time
	pending *Event // the last repeat, not yet delivered
	count   int
	first   time.Time
}

// NewDispatcher starts a dispatcher delivering to sink. A sink wrapped by
// SyncSink is called synchronously from Submit, for tests.
func NewDispatcher(sink Sink, o Options) *Dispatcher {
	d := &Dispatcher{
		o:          o.withDefaults(),
		agg:        map[aggKey]*aggEntry{},
		byKind:     map[Kind]uint64{},
		byCategory: map[Category]uint64{},
		quit:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	if s, ok := sink.(syncSink); ok {
		d.sink, d.sync = s.Sink, true
		close(d.done)
		return d
	}
	d.sink = sink
	d.ch = make(chan Event, d.o.QueueSize)
	go d.run()
	return d
}

// Deliver submits e; it makes a Dispatcher usable as a Sink.
func (d *Dispatcher) Deliver(e Event) { d.Submit(e) }

// Submit queues e for delivery, filling the fields its kind fixes. It never
// blocks: when the queue is full the event is counted as dropped.
func (d *Dispatcher) Submit(e Event) {
	if d == nil {
		return
	}
	d.admit.RLock()
	defer d.admit.RUnlock()
	if d.closed {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	info := e.Kind.Info()
	// A zero severity is the kind's default; an event may state another.
	if e.Severity == Info {
		e.Severity = info.Severity
	}
	if e.Category == "" {
		e.Category = info.Category
	}
	if e.Technique == "" {
		e.Technique = info.Technique
	}
	if e.Std62351 == "" {
		e.Std62351 = info.Std62351
	}
	if e.Action == "" {
		e.Action = Observed
	}
	if e.Count == 0 {
		e.Count = 1
	}
	if e.Raw != nil {
		n := len(e.Raw)
		if d.o.MaxRaw < 0 {
			n = 0
		} else if n > d.o.MaxRaw {
			n = d.o.MaxRaw
		}
		e.Raw = append([]byte(nil), e.Raw[:n]...)
	}
	// The caller may reuse what it pointed the event at once Submit
	// returns.
	e.detach()
	if len(e.OrIdent) > 64 {
		e.OrIdent = e.OrIdent[:64]
	}
	d.submitted.Add(1)
	d.statMu.Lock()
	d.byKind[e.Kind]++
	d.byCategory[e.Category]++
	d.statMu.Unlock()
	if d.sync {
		d.smu.Lock()
		d.handle(e)
		d.smu.Unlock()
		return
	}
	select {
	case d.ch <- e:
	default:
		d.dropped.Add(1)
	}
}

// Close delivers what is queued and pending aggregation, then stops.
// Events submitted afterwards are discarded.
func (d *Dispatcher) Close() error {
	if d == nil {
		return nil
	}
	d.once.Do(func() {
		d.admit.Lock()
		d.closed = true
		d.admit.Unlock()
		if d.sync {
			d.smu.Lock()
			d.flush(time.Time{})
			d.smu.Unlock()
			return
		}
		close(d.quit)
		<-d.done
	})
	return nil
}

// Stats returns a snapshot of the counters.
func (d *Dispatcher) Stats() Stats {
	if d == nil {
		return Stats{}
	}
	d.statMu.Lock()
	byKind := maps.Clone(d.byKind)
	byCat := maps.Clone(d.byCategory)
	d.statMu.Unlock()
	return Stats{
		Submitted:  d.submitted.Load(),
		Delivered:  d.delivered.Load(),
		Aggregated: d.aggregated.Load(),
		Dropped:    d.dropped.Load(),
		SinkPanics: d.panics.Load(),
		ByKind:     byKind,
		ByCategory: byCat,
	}
}

func (d *Dispatcher) run() {
	defer close(d.done)
	var tick <-chan time.Time
	if d.o.AggregateWindow > 0 {
		t := time.NewTicker(max(d.o.AggregateWindow/2, time.Millisecond))
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case e := <-d.ch:
			d.handle(e)
		case now := <-tick:
			d.flush(now)
			d.reportDrops(now)
		case <-d.quit:
			for {
				select {
				case e := <-d.ch:
					d.handle(e)
				default:
					d.flush(time.Time{})
					d.reportDrops(time.Now())
					return
				}
			}
		}
	}
}

// handle aggregates e or delivers it.
func (d *Dispatcher) handle(e Event) {
	d.reportDrops(e.Time)
	if d.o.AggregateWindow < 0 || e.Kind.Info().Always || e.Count > 1 {
		d.send(e)
		return
	}
	key := aggKey{kind: e.Kind, session: e.SessionID, subject: subject(e)}
	if a, ok := d.agg[key]; ok {
		if e.Time.Before(a.until) {
			a.count++
			ev := e
			a.pending = &ev
			d.aggregated.Add(1)
			return
		}
		d.release(key, a)
	}
	if len(d.agg) >= d.o.MaxAggregateKeys {
		d.flush(time.Time{})
	}
	d.agg[key] = &aggEntry{until: e.Time.Add(d.o.AggregateWindow), first: e.Time}
	d.send(e)
}

// release delivers what an aggregation entry holds back, and forgets it.
func (d *Dispatcher) release(key aggKey, a *aggEntry) {
	delete(d.agg, key)
	if a.pending == nil {
		return
	}
	ev := *a.pending
	ev.Count = a.count
	ev.FirstSeen = a.first
	d.send(ev)
}

// flush releases the entries whose window ended by now; all of them for the
// zero time.
func (d *Dispatcher) flush(now time.Time) {
	for key, a := range d.agg {
		if now.IsZero() || !now.Before(a.until) {
			d.release(key, a)
		}
	}
}

// reportDrops announces events lost since the last announcement.
func (d *Dispatcher) reportDrops(now time.Time) {
	n := d.dropped.Load()
	if n == d.dropsSeen {
		return
	}
	lost := n - d.dropsSeen
	d.dropsSeen = n
	info := KindMetaEventsDropped.Info()
	d.send(Event{Time: now, Kind: KindMetaEventsDropped, Category: info.Category, Severity: info.Severity,
		Std62351: info.Std62351, Action: Observed, Count: int(lost),
		Detail: strconv.FormatUint(lost, 10) + " events dropped: the sink is not keeping up"})
}

func (d *Dispatcher) send(e Event) {
	defer func() {
		if r := recover(); r != nil {
			d.panics.Add(1)
			if d.panicReport {
				return
			}
			d.panicReport = true
			info := KindMetaSinkPanic.Info()
			d.send(Event{Time: time.Now(), Kind: KindMetaSinkPanic, Category: info.Category,
				Severity: info.Severity, Std62351: info.Std62351, Action: Observed, Count: 1,
				Detail: fmt.Sprintf("sink panicked: %v", r)})
		}
	}()
	d.delivered.Add(1)
	d.sink.Deliver(e)
}

// subject is the part of an event that distinguishes one repeat from
// another occurrence: the object, stream or service it concerns, and the
// peer address for events outside a session.
func subject(e Event) string {
	s := e.ObjectRef
	if e.Stream != nil {
		s += "|" + e.Stream.ControlRef + "|" + strconv.Itoa(int(e.Stream.AppID)) + "|" + e.Stream.SrcMAC.String()
	}
	if e.Fields&HasService != 0 {
		s += "|s" + strconv.Itoa(e.Service)
	}
	if e.Stage != "" {
		s += "|" + e.Stage
	}
	if e.SessionID == 0 && e.Peer.RemoteAddr.IsValid() {
		s += "|" + e.Peer.RemoteAddr.Addr().String()
	}
	return s
}
