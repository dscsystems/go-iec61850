package server

import (
	"bytes"
	"sort"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Logs (IEC 61850-7-2 clause 14) are served as MMS journals (IEC 61850-8-1
// clause 17): a log named Name in logical node LN of device LD is the
// journal "LN$Name" in domain LD. A log control block writes into one log
// the members of its dataset that change, and periodically all of them
// when it has an integrity period. A client finds the logs with
// GetNameList (class journal) and reads them with ReadJournal.
//
// Everything here runs under the server's model lock: a log is written
// where the model changes, under the write lock, and read under the read
// lock, so an entry is never seen half-written and a log's control blocks
// always describe what it holds.

// defaultLogCapacity is how many entries a log keeps when the server sets
// no capacity: the oldest are discarded past it.
const defaultLogCapacity = 1024

// WithLogCapacity sets how many entries each log retains before the oldest
// are discarded. Zero keeps the library's default of 1024.
func WithLogCapacity(n int) Option {
	return func(s *Server) { s.logCapacity = n }
}

// journal is one log.
type journal struct {
	domain, name string
	entries      []*logEntry // oldest first
}

// logEntry is one log entry: the members that were logged together, with
// the reason each was logged when the control block asks for it.
type logEntry struct {
	id   []byte    // 8-octet EntryID, unique within the server
	time time.Time // UTC, at millisecond precision, as it goes on the wire
	vars []logVar
}

// logVar is one journal variable: a data reference and its value, or the
// reason code that follows the value it explains.
type logVar struct {
	tag   string
	value *mms.Value
}

// reasonCodeTag is the variable tag of the reason code that follows each
// logged value when the log control block asks for reasons.
const reasonCodeTag = "ReasonCode"

// lcbState is the runtime state of one log control block.
type lcbState struct {
	domain string
	item   string // "LN$LG$name"
	do     *model.DataObject
	lc     *model.LogControl
	j      *journal // nil when the block names no log
	// intgStop stops the integrity loop, nil when none runs.
	intgStop chan struct{}
}

// logManager holds a server's logs and the control blocks that write them.
type logManager struct {
	s        *Server
	capacity int
	journals map[string]*journal // by domain + "\x00" + name
	lcbs     map[string]*lcbState
}

// newLogManager creates the logs the model declares or its log control
// blocks write to, and starts the blocks the configuration enables.
func newLogManager(s *Server) *logManager {
	lm := &logManager{
		s:        s,
		capacity: s.logCapacity,
		journals: make(map[string]*journal),
		lcbs:     make(map[string]*lcbState),
	}
	if lm.capacity <= 0 {
		lm.capacity = defaultLogCapacity
	}
	for _, ld := range s.model.Devices {
		for _, ln := range ld.Nodes {
			for _, name := range ln.Logs {
				lm.journal(ld.Name, ln.Name+"$"+name)
			}
		}
	}
	for _, ld := range s.model.Devices {
		for _, ln := range ld.Nodes {
			for _, lc := range ln.LogControls {
				st := &lcbState{domain: ld.Name, item: ln.Name + "$LG$" + lc.Name, lc: lc, do: lcbObject(ln, lc.Name)}
				if st.do == nil {
					continue
				}
				if domain, name, ok := logTarget(ld, lc); ok {
					st.j = lm.journal(domain, name)
				}
				lm.lcbs[ld.Name+"\x00"+st.item] = st
				if st.enabled() {
					lm.startLocked(st)
				}
			}
		}
	}
	return lm
}

// lcbObject finds the materialised LCB object of a logical node.
func lcbObject(ln *model.LogicalNode, name string) *model.DataObject {
	for _, do := range ln.Objects {
		if do.Name == name && len(do.Attributes) > 0 && do.Attributes[0].FC == model.LG {
			return do
		}
	}
	return nil
}

// logTarget is the domain and journal name of the log an LCB writes to:
// its log name in the logical node the SCL places it in, LLN0 of the
// block's own device by default (IEC 61850-6). ok is false when the block
// names no log.
func logTarget(ld *model.LogicalDevice, lc *model.LogControl) (domain, name string, ok bool) {
	if lc.LogName == "" {
		return "", "", false
	}
	domain = ld.Name
	if lc.LogLDInst != "" {
		// The logical device name is the IED name followed by the
		// instance, so another instance of the same IED swaps the suffix.
		domain = strings.TrimSuffix(ld.Name, ld.Inst) + lc.LogLDInst
	}
	lnName := lc.LogLN
	if lnName == "" {
		lnName = "LLN0"
	}
	return domain, lnName + "$" + lc.LogName, true
}

// journal returns the named log, creating it empty.
func (lm *logManager) journal(domain, name string) *journal {
	key := domain + "\x00" + name
	if j := lm.journals[key]; j != nil {
		return j
	}
	j := &journal{domain: domain, name: name}
	lm.journals[key] = j
	return j
}

// names lists the logs of a domain, for GetNameList.
func (lm *logManager) names(domain string) []string {
	var out []string
	for _, j := range lm.journals {
		if j.domain == domain {
			out = append(out, j.name)
		}
	}
	sort.Strings(out)
	return out
}

func (st *lcbState) attr(name string) *mms.Value {
	if a := st.do.Attribute(name); a != nil {
		return a.Value
	}
	return nil
}

func (st *lcbState) setAttr(name string, v *mms.Value) {
	if a := st.do.Attribute(name); a != nil {
		a.Value = v
	}
}

func (st *lcbState) enabled() bool {
	v := st.attr("LogEna")
	return v != nil && v.Bool()
}

func (st *lcbState) trgOps() model.TrgOps {
	if v := st.attr("TrgOps"); v != nil {
		return model.TrgOpsFromValue(v)
	}
	return 0
}

func (st *lcbState) datSet() string {
	if v := st.attr("DatSet"); v != nil {
		return v.Text()
	}
	return ""
}

// onUpdate logs the changes of an update or a client write into every
// enabled block's log, one entry per block holding the members whose
// changes its TrgOps asks for. Called with the model write lock held.
func (lm *logManager) onUpdate(changes changeSet) {
	if lm == nil || len(changes) == 0 {
		return
	}
	const triggers = model.TrgDataChange | model.TrgQualityChange | model.TrgDataUpdate
	for _, st := range lm.lcbs {
		if st.j == nil || !st.enabled() {
			continue
		}
		want := st.trgOps() & triggers
		members, _ := lm.s.reports.resolveDataSet(st.datSet())
		var vars []logVar
		for _, m := range members {
			r := memberReason(changes, m) & want
			if r == 0 {
				continue
			}
			vars = lm.appendMember(vars, st, m, model.ReasonCode(r))
		}
		lm.appendLocked(st.j, vars)
	}
}

// logAllLocked logs every member of the block's dataset, for an integrity
// period.
func (lm *logManager) logAllLocked(st *lcbState, reason model.ReasonCode) {
	members, _ := lm.s.reports.resolveDataSet(st.datSet())
	var vars []logVar
	for _, m := range members {
		vars = lm.appendMember(vars, st, m, reason)
	}
	lm.appendLocked(st.j, vars)
}

// appendMember adds one member's value, and its reason when the block
// logs reasons, to an entry's variables.
func (lm *logManager) appendMember(vars []logVar, st *lcbState, m dsMember, reason model.ReasonCode) []logVar {
	v := lm.s.reports.itemValue(m.domain, m.item)
	if v == nil {
		return vars
	}
	vars = append(vars, logVar{tag: m.domain + "/" + m.item, value: v.Clone()})
	if st.lc.ReasonCode {
		vars = append(vars, logVar{tag: reasonCodeTag, value: reason.Value()})
	}
	return vars
}

// appendLocked adds an entry to a log, discards the oldest past its
// capacity, and brings the control blocks that describe it up to date.
func (lm *logManager) appendLocked(j *journal, vars []logVar) {
	if j == nil || len(vars) == 0 {
		return
	}
	j.entries = append(j.entries, &logEntry{
		id:   lm.s.reports.nextEntryID(),
		time: time.Now().UTC().Truncate(time.Millisecond),
		vars: vars,
	})
	if over := len(j.entries) - lm.capacity; over > 0 {
		j.entries = append([]*logEntry(nil), j.entries[over:]...)
	}
	lm.syncLocked(j)
}

// syncLocked sets the entry range of every block writing to j: the oldest
// and newest entry and their times (IEC 61850-8-1 OldEntrTm, NewEntrTm,
// OldEnt, NewEnt).
func (lm *logManager) syncLocked(j *journal) {
	if len(j.entries) == 0 {
		return
	}
	oldest, newest := j.entries[0], j.entries[len(j.entries)-1]
	for _, st := range lm.lcbs {
		if st.j != j {
			continue
		}
		st.setAttr("OldEntrTm", mms.NewBinaryTime(oldest.time))
		st.setAttr("NewEntrTm", mms.NewBinaryTime(newest.time))
		st.setAttr("OldEnt", mms.NewOctetString(oldest.id))
		st.setAttr("NewEnt", mms.NewOctetString(newest.id))
	}
}

// startLocked starts the integrity loop of an enabled block that has an
// integrity period and the trigger for it.
func (lm *logManager) startLocked(st *lcbState) {
	lm.stopLocked(st)
	pd := time.Duration(0)
	if v := st.attr("IntgPd"); v != nil {
		pd = time.Duration(v.Uint64()) * time.Millisecond
	}
	if pd <= 0 || st.trgOps()&model.TrgIntegrity == 0 || st.j == nil {
		return
	}
	stop := make(chan struct{})
	st.intgStop = stop
	go lm.integrityLoop(st, pd, stop)
}

func (lm *logManager) stopLocked(st *lcbState) {
	if st.intgStop != nil {
		close(st.intgStop)
		st.intgStop = nil
	}
}

func (lm *logManager) integrityLoop(st *lcbState, pd time.Duration, stop chan struct{}) {
	t := time.NewTicker(pd)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			lm.s.mu.Lock()
			if st.intgStop == stop {
				lm.logAllLocked(st, model.ReasonIntegrity)
			}
			lm.s.mu.Unlock()
		}
	}
}

// close stops every integrity loop.
func (lm *logManager) close() {
	lm.s.mu.Lock()
	defer lm.s.mu.Unlock()
	for _, st := range lm.lcbs {
		lm.stopLocked(st)
	}
}

// lcbKey reports whether item ("LN$LG$name[$attr]") addresses a log
// control block this server runs, returning its key and the attribute.
func (lm *logManager) lcbKey(domain, item string) (key, attr string, ok bool) {
	parts := strings.Split(item, "$")
	if len(parts) < 3 || parts[1] != "LG" {
		return "", "", false
	}
	key = domain + "\x00" + parts[0] + "$LG$" + parts[2]
	if lm.lcbs[key] == nil {
		return "", "", false
	}
	if len(parts) >= 4 {
		attr = parts[3]
	}
	return key, attr, true
}

// checkLCBWrite decides whether a client may write attr of a log control
// block, before anything is stored: 0xff allows it. LogEna, DatSet,
// TrgOps and IntgPd are the client's to set (IEC 61850-7-2 SetLCBValues);
// the configuration only while logging is off, so an entry is never logged
// under a configuration the log does not describe. The rest is the
// server's. Called with the model write lock held.
func (lm *logManager) checkLCBWrite(key, attr string, v *mms.Value) byte {
	st := lm.lcbs[key]
	switch attr {
	case "LogEna":
		if v.Bool() {
			if st.j == nil {
				return byte(mms.AccessTemporarilyUnavailable)
			}
			if _, ok := lm.s.reports.resolveDataSet(st.datSet()); !ok {
				return byte(mms.AccessTemporarilyUnavailable)
			}
		}
		return 0xff
	case "DatSet", "TrgOps", "IntgPd":
		if st.enabled() {
			return byte(mms.AccessTemporarilyUnavailable)
		}
		if attr == "DatSet" && v.Text() != "" {
			if _, ok := lm.s.reports.resolveDataSet(v.Text()); !ok {
				return byte(mms.AccessObjectValueInvalid)
			}
		}
		return 0xff
	}
	return byte(mms.AccessObjectAccessDenied)
}

// onLCBWrite applies a stored LCB write: enabling starts the integrity
// loop and disabling stops it. Called with the model write lock held.
func (lm *logManager) onLCBWrite(key, attr string) {
	st := lm.lcbs[key]
	if attr != "LogEna" {
		return
	}
	if st.enabled() {
		lm.startLocked(st)
	} else {
		lm.stopLocked(st)
	}
}

// journalQuery is a parsed ReadJournal request (ISO 9506-2).
type journalQuery struct {
	domain, name string
	startTime    *time.Time
	startEntry   []byte
	stopTime     *time.Time
	count        int // 0: no limit
	afterTime    *time.Time
	afterEntry   []byte
	variables    map[string]bool // nil: all
}

// parseJournalQuery decodes a ReadJournal-Request:
//
//	journalName [0] ObjectName,
//	rangeStartSpecification [1] CHOICE { startingTime [0], startingEntry [1] } OPTIONAL,
//	rangeStopSpecification [2] CHOICE { endingTime [0], numberOfEntries [1] } OPTIONAL,
//	listOfVariables [4] SEQUENCE OF VisibleString OPTIONAL,
//	entryToStartAfter [5] SEQUENCE { timeSpecification [0], entrySpecification [1] } OPTIONAL
//
// Earlier versions of this library's client sent entryToStartAfter as [3],
// which is accepted too rather than refusing them.
func parseJournalQuery(content []byte) (*journalQuery, error) {
	dec := asn1.NewDecoder(content)
	name, err := dec.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err
	}
	q := &journalQuery{}
	if q.domain, q.name, err = parseObjectName(name); err != nil {
		return nil, err
	}
	timeOf := func(b []byte) (*time.Time, error) {
		v, err := mms.NewBinaryTimeRaw(b)
		if err != nil {
			return nil, err
		}
		t := v.Time()
		return &t, nil
	}
	for dec.More() {
		tag, c, err := dec.ReadTLV()
		if err != nil {
			return nil, err
		}
		switch tag {
		case asn1.ContextConstructed(1), asn1.ContextConstructed(2):
			ct, cv, err := asn1.NewDecoder(c).ReadTLV()
			if err != nil {
				return nil, err
			}
			start := tag == asn1.ContextConstructed(1)
			switch {
			case ct == asn1.ContextPrimitive(0) && start:
				if q.startTime, err = timeOf(cv); err != nil {
					return nil, err
				}
			case ct == asn1.ContextPrimitive(0):
				if q.stopTime, err = timeOf(cv); err != nil {
					return nil, err
				}
			case ct == asn1.ContextPrimitive(1) && start:
				q.startEntry = append([]byte(nil), cv...)
			case ct == asn1.ContextPrimitive(1):
				n, err := asn1.DecodeInt(cv)
				if err != nil {
					return nil, err
				}
				q.count = int(n)
			}
		case asn1.ContextConstructed(4):
			q.variables = map[string]bool{}
			ld := asn1.NewDecoder(c)
			for ld.More() {
				_, s, err := ld.ReadTLV()
				if err != nil {
					return nil, err
				}
				q.variables[string(s)] = true
			}
		case asn1.ContextConstructed(5), asn1.ContextConstructed(3):
			ad := asn1.NewDecoder(c)
			for ad.More() {
				at, av, err := ad.ReadTLV()
				if err != nil {
					return nil, err
				}
				switch at {
				case asn1.ContextPrimitive(0):
					if q.afterTime, err = timeOf(av); err != nil {
						return nil, err
					}
				case asn1.ContextPrimitive(1):
					q.afterEntry = append([]byte(nil), av...)
				}
			}
		}
	}
	return q, nil
}

// selectEntries returns the entries of j the query asks for, in order.
func (q *journalQuery) selectEntries(j *journal) []*logEntry {
	from := 0
	indexOf := func(id []byte) int {
		for i, e := range j.entries {
			if bytes.Equal(e.id, id) {
				return i
			}
		}
		return -1
	}
	switch {
	case q.afterEntry != nil:
		// Continue after an entry the client has; an entry the log no
		// longer holds continues after its time instead.
		if i := indexOf(q.afterEntry); i >= 0 {
			from = i + 1
		} else if q.afterTime != nil {
			from = len(j.entries)
			for i, e := range j.entries {
				if e.time.After(*q.afterTime) {
					from = i
					break
				}
			}
		}
	case q.startEntry != nil:
		i := indexOf(q.startEntry)
		if i < 0 {
			return nil
		}
		from = i
	case q.startTime != nil:
		from = len(j.entries)
		for i, e := range j.entries {
			if !e.time.Before(*q.startTime) {
				from = i
				break
			}
		}
	}
	var out []*logEntry
	for _, e := range j.entries[from:] {
		if q.stopTime != nil && e.time.After(*q.stopTime) {
			break
		}
		if q.count > 0 && len(out) >= q.count {
			break
		}
		out = append(out, e)
	}
	return out
}

// journalEntryElement encodes one JournalEntry (ISO 9506-2):
//
//	SEQUENCE { entryIdentifier [0] OCTET STRING,
//	           originatingApplication [1] ApplicationReference,
//	           entryContent [2] SEQUENCE {
//	               occurrenceTime [0] TimeOfDay,
//	               data [2] SEQUENCE { listOfVariables [1] SEQUENCE OF
//	                   SEQUENCE { variableTag [0] VisibleString, valueSpecification [1] Data } } } }
//
// variables, when not nil, keeps only the named variables and the reason
// code that follows each.
func journalEntryElement(e *logEntry, variables map[string]bool) *asn1.Element {
	list := asn1.Cons(asn1.ContextConstructed(1))
	keep := true
	for _, v := range e.vars {
		if v.tag != reasonCodeTag {
			keep = variables == nil || variables[v.tag]
		}
		if !keep {
			continue
		}
		list.Add(asn1.Cons(asn1.TagSequence,
			asn1.Prim(asn1.ContextPrimitive(0), []byte(v.tag)),
			asn1.Cons(asn1.ContextConstructed(1), mms.DataElement(v.value)),
		))
	}
	return asn1.Cons(asn1.TagSequence,
		asn1.Prim(asn1.ContextPrimitive(0), e.id),
		asn1.Cons(asn1.ContextConstructed(1)), // originatingApplication: this server
		asn1.Cons(asn1.ContextConstructed(2),
			asn1.Prim(asn1.ContextPrimitive(0), mms.NewBinaryTime(e.time).Bytes()),
			asn1.Cons(asn1.ContextConstructed(2), list),
		),
	)
}

// readJournal answers ReadJournal with as many of the selected entries as
// fit the association's maximum PDU (maxPDU octets, 0 for no limit), and
// moreFollows when the client has to continue after the last one.
func (h *handler) readJournal(content []byte, maxPDU int) (*asn1.Element, error) {
	q, err := parseJournalQuery(content)
	if err != nil {
		return nil, err
	}
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	j := h.s.logs.journals[q.domain+"\x00"+q.name]
	if j == nil {
		return nil, mms.AccessObjectNonExistent
	}
	// The envelope is what surrounds the entries: the confirmed
	// response's tag, length and invokeID, the service and list tags and
	// lengths, and moreFollows.
	const envelope = 24
	budget := maxPDU - envelope
	list := asn1.Cons(asn1.ContextConstructed(0)) // listOfJournalEntry [0]
	more, used := false, 0
	for i, e := range q.selectEntries(j) {
		el := journalEntryElement(e, q.variables)
		// Always at least one entry, or a client could never progress.
		if maxPDU > 0 && i > 0 && used+el.Size() > budget {
			more = true
			break
		}
		used += el.Size()
		list.Add(el)
	}
	return asn1.Cons(asn1.ContextConstructed(svcReadJournal), list,
		asn1.BoolElem(asn1.ContextPrimitive(1), more)), nil
}
