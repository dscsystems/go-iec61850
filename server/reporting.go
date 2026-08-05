package server

import (
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// reportManager drives report control blocks: enabling, general
// interrogation, data-change reports on Update, and integrity reports.
type reportManager struct {
	s   *Server
	reg map[string]*rcbState
}

func newReportManager(s *Server) *reportManager {
	return &reportManager{s: s, reg: materialiseRCBs(s.model)}
}

// onRCBWrite reacts to a client write of an RCB attribute. It is called
// with the server model lock held.
func (rm *reportManager) onRCBWrite(domain, item, attr string, v *mms.Value, conn *mms.ServerConn) {
	key, _, ok := rcbKey(domain, item)
	if !ok {
		return
	}
	rs := rm.reg[key]
	if rs == nil {
		return
	}
	switch attr {
	case "RptEna":
		if v.Bool() {
			rm.enable(rs, conn)
		} else {
			rm.disable(rs)
		}
	case "GI":
		if v.Bool() {
			rm.sendReport(rs, conn, rm.allIndices(rs), model.ReasonGI)
		}
	case "EntryID":
		// Buffered resync: remember the requested EntryID; on the next
		// enable, delivery resumes after it.
		rs.mu.Lock()
		rs.resyncID = append([]byte(nil), v.Bytes()...)
		rs.mu.Unlock()
	case "PurgeBuf":
		if v.Bool() {
			rs.mu.Lock()
			rs.buffer = nil
			rs.bufOverflow = false
			rs.mu.Unlock()
		}
	}
}

func (rm *reportManager) enable(rs *rcbState, conn *mms.ServerConn) {
	rs.mu.Lock()
	rs.enabled = true
	rs.conn = conn
	rs.seqNum = 0
	if rs.intgStop != nil {
		close(rs.intgStop)
		rs.intgStop = nil
	}
	// Flush any buffered reports (BRCB), respecting a resync point.
	flush := rm.pendingLocked(rs)
	intg := rm.intgPd(rs)
	if intg > 0 {
		stop := make(chan struct{})
		rs.intgStop = stop
		go rm.integrityLoop(rs, conn, intg, stop)
	}
	rs.mu.Unlock()

	for _, e := range flush {
		if err := conn.SendUnconfirmed(e.elem); err != nil {
			rm.s.log.Debug("server: buffered report send failed", "rcb", rs.item, "err", err)
			break
		}
	}
}

// pendingLocked returns the buffered entries to deliver on enable and
// marks them sent. If a resync EntryID was set, only entries after it are
// returned; if that EntryID is not in the buffer, all entries are sent
// (the report will carry BufOvfl). rs.mu must be held.
func (rm *reportManager) pendingLocked(rs *rcbState) []bufEntry {
	if len(rs.buffer) == 0 {
		rs.resyncID = nil
		return nil
	}
	start := 0
	if len(rs.resyncID) == 8 {
		found := false
		for i, e := range rs.buffer {
			if bytesEqual(e.id, rs.resyncID) {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			rs.bufOverflow = true // resync point purged
		}
	}
	rs.resyncID = nil
	out := append([]bufEntry(nil), rs.buffer[start:]...)
	return out
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (rm *reportManager) disable(rs *rcbState) {
	rs.mu.Lock()
	rs.enabled = false
	rs.conn = nil
	if rs.intgStop != nil {
		close(rs.intgStop)
		rs.intgStop = nil
	}
	rs.mu.Unlock()
}

// disableConn disables all RCBs bound to a closing connection.
func (rm *reportManager) disableConn(conn *mms.ServerConn) {
	for _, rs := range rm.reg {
		rs.mu.Lock()
		if rs.conn == conn {
			rs.enabled = false
			rs.conn = nil
			if rs.intgStop != nil {
				close(rs.intgStop)
				rs.intgStop = nil
			}
		}
		rs.mu.Unlock()
	}
}

func (rm *reportManager) integrityLoop(rs *rcbState, conn *mms.ServerConn, pd time.Duration, stop chan struct{}) {
	t := time.NewTicker(pd)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			rm.s.mu.RLock()
			rm.sendReport(rs, conn, rm.allIndices(rs), model.ReasonIntegrity)
			rm.s.mu.RUnlock()
		}
	}
}

// onUpdate is called after an Update transaction with the set of changed
// leaf references. It emits data-change reports for enabled RCBs whose
// dataset includes any changed member. Called with the model lock held.
func (rm *reportManager) onUpdate(changed map[model.ObjectReference]bool) {
	if len(changed) == 0 {
		return
	}
	for _, rs := range rm.reg {
		rs.mu.Lock()
		enabled, conn, buffered := rs.enabled, rs.conn, rs.rc.Buffered
		rs.mu.Unlock()
		// Unbuffered RCBs only report while enabled; buffered RCBs always
		// capture events so they can be delivered on a later enable.
		if !buffered && (!enabled || conn == nil) {
			continue
		}
		members := rm.members(rs)
		var included []int
		for i, m := range members {
			ref, _ := model.FromMMS(m.domain, m.item)
			if changed[ref] || changed[ref.Parent()] || changed[ref.Parent().Parent()] {
				included = append(included, i)
			}
		}
		if len(included) > 0 {
			rm.sendReport(rs, conn, included, model.ReasonDataChange)
		}
	}
}

// supportedOptFlds are the report fields this server can actually produce.
// Segmentation is absent: reports are sent whole, so SubSeqNum and
// MoreFollows are never emitted.
const supportedOptFlds = model.OptSeqNum | model.OptTimeOfEntry |
	model.OptReasonCode | model.OptDataSetName | model.OptDataRef |
	model.OptBufOvfl | model.OptEntryID | model.OptConfRev

// effectiveOptFlds reduces a client's requested OptFlds to what the report
// will really carry. The value is echoed as the report's second field and
// is what tells a client which optional fields follow, so a bit set there
// without its field shifts every value after it: the flags have to
// describe the report as built, not as asked for. BufOvfl and EntryID
// belong to buffered reports only.
func effectiveOptFlds(opt model.OptFlds, buffered bool) model.OptFlds {
	opt &= supportedOptFlds
	if !buffered {
		opt &^= model.OptBufOvfl | model.OptEntryID
	}
	return opt
}

func (rm *reportManager) allIndices(rs *rcbState) []int {
	n := len(rm.members(rs))
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// sendReport encodes a report for the included members. Unbuffered
// reports are transmitted immediately on conn. Buffered reports are always
// appended to the RCB buffer (assigned an EntryID) and, when a subscriber
// is enabled, also transmitted.
func (rm *reportManager) sendReport(rs *rcbState, conn *mms.ServerConn, included []int, reason model.ReasonCode) {
	if len(included) == 0 {
		return
	}
	members := rm.members(rs)
	buffered := rs.rc.Buffered
	opt := effectiveOptFlds(model.OptFldsFromValue(rm.attrValue(rs, "OptFlds")), buffered)

	rs.mu.Lock()
	seq := rs.seqNum
	rs.seqNum++
	var entryID []byte
	bufOvfl := false
	if buffered {
		rs.entryCounter++
		entryID = makeEntryID(rs.entryCounter)
		bufOvfl = rs.bufOverflow
		rs.bufOverflow = false
	}
	rs.mu.Unlock()

	results := asn1.Cons(asn1.ContextConstructed(0)) // listOfAccessResult [0]
	add := func(v *mms.Value) { results.Add(mms.DataElement(v)) }

	add(rm.attrValue(rs, "RptID"))
	add(opt.Value())
	if opt&model.OptSeqNum != 0 {
		add(mms.NewUint32(seq))
	}
	if opt&model.OptTimeOfEntry != 0 {
		add(mms.NewBinaryTime(time.Now()))
	}
	if opt&model.OptDataSetName != 0 {
		add(rm.attrValue(rs, "DatSet"))
	}
	if opt&model.OptBufOvfl != 0 {
		add(mms.NewBool(bufOvfl))
	}
	if opt&model.OptEntryID != 0 {
		add(mms.NewOctetString(entryID))
	}
	if opt&model.OptConfRev != 0 {
		add(rm.attrValue(rs, "ConfRev"))
	}

	// Inclusion bitstring: one bit per dataset member.
	inclusion := mms.NewBitString(len(members))
	for _, idx := range included {
		if idx < len(members) {
			inclusion.SetBit(idx, true)
		}
	}
	add(inclusion)

	// Data references, one per included member, precede the values
	// (IEC 61850-8-1): "LDName/LNName$FC$DataName", the MMS form of the
	// member's reference.
	if opt&model.OptDataRef != 0 {
		for _, idx := range included {
			if idx >= len(members) {
				continue
			}
			add(mms.NewVisibleString(members[idx].domain + "/" + members[idx].item))
		}
	}

	// Member values, in dataset order, only for included members.
	for _, idx := range included {
		if idx >= len(members) {
			continue
		}
		v := rm.itemValue(members[idx].domain, members[idx].item)
		if v == nil {
			v = mms.NewBool(false)
		}
		add(v)
	}
	// Reason codes per included member.
	if opt&model.OptReasonCode != 0 {
		for range included {
			add(reason.Value())
		}
	}

	// InformationReport [0] { variableListName [1] { vmd-specific "RPT" }, listOfAccessResult [0] }
	report := asn1.Cons(asn1.ContextConstructed(0),
		asn1.Cons(asn1.ContextConstructed(1), asn1.Prim(asn1.ContextPrimitive(0), []byte("RPT"))),
		results,
	)

	if buffered {
		rs.mu.Lock()
		rs.buffer = append(rs.buffer, bufEntry{id: entryID, elem: report})
		if len(rs.buffer) > maxBufferedReports {
			rs.buffer = rs.buffer[1:]
			rs.bufOverflow = true
		}
		// Reflect the latest EntryID/TimeofEntry into the model.
		if a := rs.do.Attribute("EntryID"); a != nil {
			a.Value = mms.NewOctetString(entryID)
		}
		if a := rs.do.Attribute("TimeofEntry"); a != nil {
			a.Value = mms.NewBinaryTime(time.Now())
		}
		rs.mu.Unlock()
	}

	if conn == nil {
		return // buffered while no subscriber; will flush on enable
	}
	if err := conn.SendUnconfirmed(report); err != nil {
		rm.s.log.Debug("server: report send failed", "rcb", rs.item, "err", err)
	}
}

// makeEntryID encodes a monotonic counter as an 8-octet EntryID.
func makeEntryID(n uint64) []byte {
	return []byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	}
}

// members returns the dataset members of the RCB.
func (rm *reportManager) members(rs *rcbState) []dsMember {
	if rs.rc.DataSet == "" {
		return nil
	}
	return (&handler{s: rm.s}).datasetMembers(rs.domain, rs.ln.Name+"$"+rs.rc.DataSet)
}

func (rm *reportManager) attrValue(rs *rcbState, name string) *mms.Value {
	if a := rs.do.Attribute(name); a != nil && a.Value != nil {
		return a.Value.Clone()
	}
	return mms.NewBool(false)
}

func (rm *reportManager) intgPd(rs *rcbState) time.Duration {
	v := rm.attrValue(rs, "IntgPd")
	return time.Duration(v.Uint64()) * time.Millisecond
}

// itemValue resolves a dataset member item to its current value.
func (rm *reportManager) itemValue(domain, item string) *mms.Value {
	ld := rm.s.model.Device(domain)
	if ld == nil {
		return nil
	}
	ln, rest := splitLN(ld, item)
	if ln == nil {
		return nil
	}
	v, _ := resolveRead(ln, rest)
	return v
}
