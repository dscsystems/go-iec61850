package secevent

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

type collect struct {
	mu sync.Mutex
	ev []Event
}

func (c *collect) Deliver(e Event) {
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
}

func (c *collect) events() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Event(nil), c.ev...)
}

func TestSubmitFillsKindFields(t *testing.T) {
	var c collect
	d := NewDispatcher(SyncSink(&c), Options{})
	d.Submit(Event{Kind: KindConnRejectedLimit, Raw: make([]byte, 100), OrIdent: strings.Repeat("x", 80)})
	d.Submit(Event{Kind: KindConnAccepted, Severity: Alert})
	d.Close()
	ev := c.events()
	if len(ev) != 2 {
		t.Fatalf("got %d events", len(ev))
	}
	e := ev[0]
	info := KindConnRejectedLimit.Info()
	if e.Severity != info.Severity || e.Category != CatConnection || e.Std62351 != ExtensionPrefix+string(KindConnRejectedLimit) ||
		e.Action != Observed || e.Count != 1 || e.Time.IsZero() || len(e.Raw) != 64 || len(e.OrIdent) != 64 {
		t.Fatalf("fields not filled: %+v", e)
	}
	if ev[1].Severity != Alert {
		t.Fatalf("stated severity overridden: %v", ev[1].Severity)
	}
}

func TestKindTableComplete(t *testing.T) {
	for _, k := range Kinds() {
		info := k.Info()
		if info.Category == "" || info.Std62351 == "" {
			t.Errorf("%s: incomplete %+v", k, info)
		}
		if !strings.Contains(string(k), ".") {
			t.Errorf("%s: no namespace", k)
		}
	}
	if Kind("x.unknown").Info().Category != CatMeta {
		t.Error("unknown kind not meta")
	}
	if Kind(E2EPrefix+"foo").Info().Category != CatAssociation {
		t.Error("e2e kind not association")
	}
}

func TestAggregation(t *testing.T) {
	var c collect
	d := NewDispatcher(SyncSink(&c), Options{AggregateWindow: time.Hour})
	t0 := time.Now()
	for i := range 5 {
		d.Submit(Event{Time: t0.Add(time.Duration(i) * time.Millisecond), Kind: KindAccessDenied, SessionID: 7, ObjectRef: "LD/LLN0"})
	}
	d.Submit(Event{Time: t0, Kind: KindAccessDenied, SessionID: 7, ObjectRef: "LD/other"})
	if n := len(c.events()); n != 2 {
		t.Fatalf("before close: %d events, want first of each subject", n)
	}
	d.Close()
	ev := c.events()
	if len(ev) != 3 {
		t.Fatalf("after close: %d events", len(ev))
	}
	last := ev[2]
	if last.Count != 4 || !last.FirstSeen.Equal(t0) || last.ObjectRef != "LD/LLN0" {
		t.Fatalf("aggregate %+v", last)
	}
	if s := d.Stats(); s.Submitted != 6 || s.Aggregated != 4 || s.Delivered != 3 || s.ByKind[KindAccessDenied] != 6 {
		t.Fatalf("stats %+v", s)
	}
}

func TestAggregationWindowEnds(t *testing.T) {
	var c collect
	d := NewDispatcher(SyncSink(&c), Options{AggregateWindow: 10 * time.Millisecond})
	t0 := time.Now()
	d.Submit(Event{Time: t0, Kind: KindAccessDenied})
	d.Submit(Event{Time: t0.Add(time.Millisecond), Kind: KindAccessDenied})
	d.Submit(Event{Time: t0.Add(20 * time.Millisecond), Kind: KindAccessDenied})
	ev := c.events()
	if len(ev) != 3 || ev[1].Count != 1 || ev[2].Count != 1 {
		t.Fatalf("got %+v", ev)
	}
	d.Close()
}

func TestAlwaysNotAggregated(t *testing.T) {
	var c collect
	d := NewDispatcher(SyncSink(&c), Options{AggregateWindow: time.Hour})
	var always Kind
	for _, k := range Kinds() {
		if k.Info().Always {
			always = k
			break
		}
	}
	if always == "" {
		t.Skip("no always-deliver kind")
	}
	for range 3 {
		d.Submit(Event{Kind: always})
	}
	if n := len(c.events()); n != 3 {
		t.Fatalf("%s: %d events, want 3", always, n)
	}
	d.Close()
}

func TestSubmitNeverBlocks(t *testing.T) {
	block := make(chan struct{})
	var once sync.Once
	var c collect
	d := NewDispatcher(SinkFunc(func(e Event) {
		once.Do(func() { <-block })
		c.Deliver(e)
	}), Options{QueueSize: 4, AggregateWindow: -1})
	done := make(chan struct{})
	go func() {
		for range 100 {
			d.Submit(Event{Kind: KindConnAccepted})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Submit blocked")
	}
	close(block)
	d.Close()
	s := d.Stats()
	var normal, announced uint64
	for _, e := range c.events() {
		if e.Kind == KindMetaEventsDropped {
			announced += uint64(e.Count)
		} else {
			normal++
		}
	}
	if s.Dropped == 0 || normal+s.Dropped != 100 || announced != s.Dropped {
		t.Fatalf("stats %+v, delivered %d, announced %d", s, normal, announced)
	}
}

func TestSinkPanicReportedOnce(t *testing.T) {
	var c collect
	d := NewDispatcher(SyncSink(SinkFunc(func(e Event) {
		if e.Kind == KindConnAccepted {
			panic("boom")
		}
		c.Deliver(e)
	})), Options{AggregateWindow: -1})
	for range 3 {
		d.Submit(Event{Kind: KindConnAccepted})
	}
	d.Close()
	ev := c.events()
	if len(ev) != 1 || ev[0].Kind != KindMetaSinkPanic || !strings.Contains(ev[0].Detail, "boom") {
		t.Fatalf("got %+v", ev)
	}
	if d.Stats().SinkPanics != 3 {
		t.Fatalf("panics %d", d.Stats().SinkPanics)
	}
}

func TestClosedDiscards(t *testing.T) {
	var c collect
	d := NewDispatcher(&c, Options{})
	d.Submit(Event{Kind: KindConnAccepted})
	d.Close()
	d.Submit(Event{Kind: KindConnAccepted})
	d.Close()
	if n := len(c.events()); n != 1 {
		t.Fatalf("%d events", n)
	}
	var nilD *Dispatcher
	nilD.Submit(Event{})
	nilD.Close()
	var nilE *Emitter
	nilE.Emit(Event{})
	if NewEmitter(nil, "mms", "server").Enabled() {
		t.Fatal("nil dispatcher enabled")
	}
}

func TestEmitterAndReport(t *testing.T) {
	var c collect
	d := NewDispatcher(SyncSink(&c), Options{AggregateWindow: -1})
	m := NewEmitter(d, "mms", "server")
	m.Emit(Event{Kind: KindConnAccepted})
	m.Emit(Event{Kind: KindConnAccepted, Protocol: "tls"})
	if Report(42, Event{}) {
		t.Fatal("int is no reporter")
	}
	if !Report(reporterFunc(func(e Event) { m.Emit(e) }), Event{Kind: KindRemoteRejected}) {
		t.Fatal("reporter not used")
	}
	ev := c.events()
	if len(ev) != 3 || ev[0].Protocol != "mms" || ev[0].Role != "server" || ev[1].Protocol != "tls" || ev[2].Kind != KindRemoteRejected {
		t.Fatalf("got %+v", ev)
	}
}

type reporterFunc func(Event)

func (f reporterFunc) ReportCyberEvent(e Event) { f(e) }

func TestJSON(t *testing.T) {
	e := Event{
		Time: time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC), Kind: KindAssocSetupFailed,
		Category: CatAssociation, Severity: Warning, Action: Disconnected, Protocol: "mms", Role: "server",
		SessionID: 3, Stage: "acse",
		Peer: PeerInfo{Network: "tcp", RemoteAddr: netip.MustParseAddrPort("192.0.2.1:50000"),
			MAC: net.HardwareAddr{2, 0, 0, 0, 0, 1}, MACSource: MACNeighbor},
		Fields: HasService | HasAccessError, Service: 4, AccessError: 0,
		Err: errors.New("bad"), Raw: []byte{0xa0, 0x01}, Std62351: "x-go-iec61850.assoc.setup_failed",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"time":"2026-11-21T10:00:00Z","kind":"assoc.setup_failed","category":"association","severity":"warning",` +
		`"action":"disconnected","protocol":"mms","role":"server","session":3,` +
		`"peer":{"network":"tcp","remote":"192.0.2.1:50000","mac":"02:00:00:00:00:01","mac_source":"neighbor"},` +
		`"stage":"acse","service":4,"access_error":0,"error":"bad","raw":"a001","iec62351_14":"x-go-iec61850.assoc.setup_failed"}`
	if string(b) != want {
		t.Fatalf("json\n got %s\nwant %s", b, want)
	}

	var buf bytes.Buffer
	s := JSONLinesSink(&buf)
	s.Deliver(Event{Kind: KindConnAccepted})
	s.Deliver(Event{Kind: KindConnClosed, Session: &SessionSummary{Reason: "released", Duration: time.Second}})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[1], `"session_summary":{"reason":"released","duration_ms":1000`) {
		t.Fatalf("lines %q", lines)
	}
}

func TestFilterMultiChannel(t *testing.T) {
	var a, b collect
	s := MultiSink(FilterSink(Warning, &a), nil, FilterSink(Info, &b, CatTLS))
	s.Deliver(Event{Severity: Notice, Category: CatTLS})
	s.Deliver(Event{Severity: Alert, Category: CatConnection})
	if len(a.events()) != 1 || len(b.events()) != 1 || a.events()[0].Severity != Alert || b.events()[0].Category != CatTLS {
		t.Fatalf("a %+v b %+v", a.events(), b.events())
	}
	ch := make(chan Event, 1)
	cs := ChannelSink(ch)
	cs.Deliver(Event{})
	cs.Deliver(Event{})
	if cs.Dropped() != 1 || len(ch) != 1 {
		t.Fatalf("dropped %d", cs.Dropped())
	}
}

func TestPolicyDispatcher(t *testing.T) {
	if d, _ := (Policy{}).Dispatcher(); d != nil {
		t.Fatal("dispatcher without sink")
	}
	shared := NewDispatcher(&collect{}, Options{})
	defer shared.Close()
	if d, owned := (Policy{Sink: shared}).Dispatcher(); d != shared || owned {
		t.Fatal("shared dispatcher not reused")
	}
	d, owned := (Policy{Sink: &collect{}}).Dispatcher()
	if d == nil || !owned {
		t.Fatal("no own dispatcher")
	}
	d.Close()
	if (Policy{}).Valid() == nil {
		t.Fatal("policy without sink valid")
	}
}

// A tiny positive window must not panic the ticker.
func TestTinyAggregateWindow(t *testing.T) {
	d := NewDispatcher(&collect{}, Options{AggregateWindow: time.Nanosecond})
	d.Submit(Event{Kind: KindConnAccepted})
	d.Close()
}

// Every admitted event is delivered or counted as dropped, even when
// submissions race with Close.
func TestSubmitCloseRace(t *testing.T) {
	for range 50 {
		var c collect
		d := NewDispatcher(&c, Options{AggregateWindow: -1, QueueSize: 8})
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 50 {
					d.Submit(Event{Kind: KindConnAccepted})
				}
			}()
		}
		d.Close()
		wg.Wait()
		s := d.Stats()
		var normal uint64
		for _, e := range c.events() {
			if e.Kind == KindConnAccepted {
				normal++
			}
		}
		if normal+s.Dropped != s.Submitted {
			t.Fatalf("delivered %d + dropped %d != submitted %d", normal, s.Dropped, s.Submitted)
		}
	}
}

// What an event points at is copied on Submit.
func TestSubmitDetaches(t *testing.T) {
	var c collect
	d := NewDispatcher(SyncSink(&c), Options{AggregateWindow: -1})
	mac := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	q := int32(7)
	st := &StreamInfo{SrcMAC: mac, ControlRef: "a"}
	acse := &ACSEPeer{CallingAEQualifier: &q}
	d.Submit(Event{Kind: KindGooseDuplicate, Stream: st, Peer: PeerInfo{MAC: mac, ACSE: acse}})
	mac[0], q, st.ControlRef = 9, 8, "b"
	e := c.events()[0]
	if e.Stream.ControlRef != "a" || e.Stream.SrcMAC[0] != 1 || e.Peer.MAC[0] != 1 || *e.Peer.ACSE.CallingAEQualifier != 7 {
		t.Fatalf("event shares caller data: %+v %+v", e.Stream, e.Peer)
	}
	d.Close()
}

type failOnce struct {
	failed bool
	buf    bytes.Buffer
}

func (w *failOnce) Write(b []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return 0, errors.New("transient")
	}
	return w.buf.Write(b)
}

// A failed write loses only its own line.
func TestJSONLinesRecovers(t *testing.T) {
	w := &failOnce{}
	s := JSONLinesSink(w)
	s.Deliver(Event{Kind: KindConnAccepted})
	s.Deliver(Event{Kind: KindConnClosed})
	if got := w.buf.String(); !strings.Contains(got, `"conn.closed"`) || strings.Count(got, "\n") != 1 {
		t.Fatalf("after a failed write: %q", got)
	}
}
