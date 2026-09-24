package server

import (
	"bytes"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// reportManager drives report control blocks (IEC 61850-7-2 clause 17,
// mapped by IEC 61850-8-1): reservation, enabling, general interrogation,
// triggered and integrity reports, buffer time, and the report buffer of
// buffered control blocks.
//
// Lock order: the server model lock, then an rcbState's mu. Every entry
// point either is called with the model lock held or takes it first.
type reportManager struct {
	s   *Server
	reg map[string]*rcbState
}

func newReportManager(s *Server) *reportManager {
	return &reportManager{s: s, reg: materialiseRCBs(s.model, s.reportBufSize)}
}

// rcbSettings are the attributes a client configures. IEC 61850-7-2 lets
// them change only while the block is disabled.
var rcbSettings = map[string]bool{
	"RptID": true, "DatSet": true, "OptFlds": true, "BufTm": true,
	"TrgOps": true, "IntgPd": true, "PurgeBuf": true, "EntryID": true,
	"ResvTms": true,
}

// rcbReadOnly are the attributes the server maintains.
var rcbReadOnly = map[string]bool{
	"ConfRev": true, "SqNum": true, "TimeofEntry": true, "Owner": true,
}

// checkRCBWrite decides whether a client may write attr of a report
// control block, before anything is stored. It returns 0xff to allow the
// write or the DataAccessError that refuses it. Called with the model lock
// held.
func (rm *reportManager) checkRCBWrite(domain, item, attr string, v *mms.Value, conn *mms.ServerConn) byte {
	key, _, _ := rcbKey(domain, item)
	rs := rm.reg[key]
	if rs == nil {
		return byte(mms.AccessObjectNonExistent)
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	// A block another client holds is not this one's to change.
	if rs.owner != nil && rs.owner != conn {
		return byte(mms.AccessTemporarilyUnavailable)
	}
	switch {
	case rcbReadOnly[attr]:
		return byte(mms.AccessObjectAccessDenied)
	case attr == "RptEna":
		if v.Bool() {
			if rs.enabled {
				return byte(mms.AccessTemporarilyUnavailable)
			}
			// A block without a dataset has nothing to report.
			if _, ok := rm.resolveDataSet(rs.attrText("DatSet")); !ok {
				return byte(mms.AccessTemporarilyUnavailable)
			}
		}
	case attr == "GI":
		// Interrogation is a service of an enabled block.
		if v.Bool() && !rs.enabled {
			return byte(mms.AccessTemporarilyUnavailable)
		}
	case attr == "Resv":
		if !v.Bool() && rs.enabled {
			return byte(mms.AccessTemporarilyUnavailable)
		}
	case rcbSettings[attr]:
		if rs.enabled {
			return byte(mms.AccessTemporarilyUnavailable)
		}
		switch attr {
		case "DatSet":
			if ref := v.Text(); ref != "" {
				if _, ok := rm.resolveDataSet(ref); !ok {
					return byte(mms.AccessObjectValueInvalid)
				}
			}
		case "EntryID":
			// Resynchronisation needs an entry the buffer still holds;
			// all zeros asks for everything it holds.
			id := v.Bytes()
			if len(id) != 8 || (!isZeroEntryID(id) && rs.bufferIndex(id) < 0) {
				return byte(mms.AccessObjectValueInvalid)
			}
		}
	}
	return 0xff
}

// onRCBWrite applies the effect of a stored RCB write. Called with the
// model lock held, after checkRCBWrite allowed it.
func (rm *reportManager) onRCBWrite(domain, item, attr string, v *mms.Value, conn *mms.ServerConn) {
	key, _, _ := rcbKey(domain, item)
	rs := rm.reg[key]
	if rs == nil {
		return
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if attr == "Resv" {
		if v.Bool() {
			rs.owner = conn
		} else {
			rs.owner = nil
		}
		rs.syncResvLocked()
		return
	}
	// Writing a block reserves it for the writer (IEC 61850-7-2 implicit
	// reservation), so a second client cannot reconfigure or take it.
	if rs.owner == nil {
		rs.owner = conn
		rs.syncResvLocked()
	}
	switch attr {
	case "RptEna":
		if v.Bool() {
			rm.enableLocked(rs, conn)
		} else {
			rm.disableLocked(rs)
		}
	case "GI":
		if v.Bool() && rs.trgOps()&model.TrgGI != 0 {
			rm.reportAllLocked(rs, model.ReasonGI)
		}
		// GI is a trigger, not a state: it reads FALSE once performed.
		rs.setAttr("GI", mms.NewBool(false))
	case "PurgeBuf":
		if v.Bool() {
			rs.purgeLocked()
		}
		rs.setAttr("PurgeBuf", mms.NewBool(false))
	case "EntryID":
		rs.resyncID = append([]byte(nil), v.Bytes()...)
	case "DatSet":
		// A different dataset is a different configuration: ConfRev
		// counts it, and buffered reports of the old one are void.
		if a := rs.do.Attribute("ConfRev"); a != nil && a.Value != nil {
			a.Value = mms.NewUint32(uint32(a.Value.Uint64()) + 1)
		}
		rs.purgeLocked()
	}
}

// syncResvLocked reflects the reservation into the URCB's Resv.
func (rs *rcbState) syncResvLocked() {
	if a := rs.do.Attribute("Resv"); a != nil {
		a.Value = mms.NewBool(rs.owner != nil)
	}
}

func (rm *reportManager) enableLocked(rs *rcbState, conn *mms.ServerConn) {
	rs.enabled = true
	rs.conn = conn
	rs.owner = conn
	rs.syncResvLocked()
	rs.setSqNumLocked(0)
	rs.stopIntegrityLocked()

	if rs.rc.Buffered {
		// Delivery resumes after the resync point, from the oldest entry
		// for all zeros, and otherwise where it left off: entries already
		// sent are not sent again.
		if id := rs.resyncID; id != nil {
			rs.resyncID = nil
			switch i := rs.bufferIndex(id); {
			case isZeroEntryID(id):
				rs.next = 0
			case i >= 0:
				rs.next = i + 1
			default:
				// Purged between the EntryID write and the enable.
				rs.next = 0
				rs.bufOverflow = true
			}
		}
		rm.transmitBufferedLocked(rs)
	}

	if pd := time.Duration(rs.attrUint("IntgPd")) * time.Millisecond; pd > 0 && rs.trgOps()&model.TrgIntegrity != 0 {
		stop := make(chan struct{})
		rs.intgStop = stop
		go rm.integrityLoop(rs, pd, stop)
	}
}

func (rm *reportManager) disableLocked(rs *rcbState) {
	// Events already collected in a buffer-time window are reported, not
	// lost with the subscription.
	rm.flushPendingLocked(rs)
	rs.enabled = false
	rs.conn = nil
	rs.stopIntegrityLocked()
	// A buffered block keeps buffering for whoever enables it next; the
	// reservation of an unbuffered block lasts until released.
	if rs.rc.Buffered {
		rs.owner = nil
	}
}

func (rs *rcbState) stopIntegrityLocked() {
	if rs.intgStop != nil {
		close(rs.intgStop)
		rs.intgStop = nil
	}
}

func (rs *rcbState) purgeLocked() {
	rs.buffer = nil
	rs.next = 0
	rs.bufOverflow = false
	rs.resyncID = nil
}

// disableConn releases every block a closing connection had enabled or
// reserved.
func (rm *reportManager) disableConn(conn *mms.ServerConn) {
	rm.s.mu.RLock()
	defer rm.s.mu.RUnlock()
	for _, rs := range rm.reg {
		rs.mu.Lock()
		if rs.conn == conn {
			rm.disableLocked(rs)
		}
		if rs.owner == conn {
			rs.owner = nil
			rs.syncResvLocked()
		}
		rs.mu.Unlock()
	}
}

func (rm *reportManager) integrityLoop(rs *rcbState, pd time.Duration, stop chan struct{}) {
	t := time.NewTicker(pd)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			rm.s.mu.RLock()
			rs.mu.Lock()
			if rs.intgStop == stop {
				rm.reportAllLocked(rs, model.ReasonIntegrity)
			}
			rs.mu.Unlock()
			rm.s.mu.RUnlock()
		}
	}
}

// reportAllLocked reports every dataset member for a general
// interrogation or an integrity period. Events waiting in a buffer-time
// window go first, so the report reflects them in order.
func (rm *reportManager) reportAllLocked(rs *rcbState, reason model.ReasonCode) {
	rm.flushPendingLocked(rs)
	members, _ := rm.resolveDataSet(rs.attrText("DatSet"))
	e := &reportEntry{}
	for i, m := range members {
		v := rm.itemValue(m.domain, m.item)
		if v == nil {
			continue
		}
		e.members = append(e.members, i)
		e.values = append(e.values, v.Clone())
		e.reasons = append(e.reasons, reason)
	}
	if len(e.members) > 0 {
		rm.emitLocked(rs, e)
	}
}

// onUpdate reports the changes of an update or a client write to every
// block whose dataset they touch. A member is included for the reasons
// its written attributes raised that the block's TrgOps asks for. Called
// with the model lock held.
func (rm *reportManager) onUpdate(changes changeSet) {
	if len(changes) == 0 {
		return
	}
	const triggers = model.TrgDataChange | model.TrgQualityChange | model.TrgDataUpdate
	for _, rs := range rm.reg {
		rs.mu.Lock()
		// Unbuffered blocks only report while enabled; buffered blocks
		// capture events for delivery on a later enable.
		if !rs.rc.Buffered && !rs.enabled {
			rs.mu.Unlock()
			continue
		}
		want := rs.trgOps() & triggers
		members, _ := rm.resolveDataSet(rs.attrText("DatSet"))
		e := &reportEntry{}
		for i, m := range members {
			r := memberReason(changes, m) & want
			if r == 0 {
				continue
			}
			v := rm.itemValue(m.domain, m.item)
			if v == nil {
				continue
			}
			e.members = append(e.members, i)
			e.values = append(e.values, v.Clone())
			e.reasons = append(e.reasons, model.ReasonCode(r))
		}
		if len(e.members) > 0 {
			rm.eventLocked(rs, e)
		}
		rs.mu.Unlock()
	}
}

// memberReason is the trigger reasons the changes raised for a dataset
// member. A member may name any level of the tree — commonly a data
// object with an FC — and a change to anything below it under the same
// functional constraint is a change of the member. TrgOps and ReasonCode
// share their bit positions, so the result is also the reason code.
func memberReason(changes changeSet, m dsMember) model.TrgOps {
	ref, fc := model.FromMMS(m.domain, m.item)
	below := string(ref) + "."
	var r model.TrgOps
	for c, t := range changes {
		if c.fc != fc {
			continue
		}
		if c.ref == ref || strings.HasPrefix(string(c.ref), below) ||
			strings.HasPrefix(string(ref), string(c.ref)+".") {
			r |= t
		}
	}
	return r
}

// eventLocked takes a triggered report entry through the buffer time
// (BufTm): with none it is reported at once; otherwise events collect in
// one report until the window closes. A member that changes again inside
// the window closes it first, so its earlier value is reported rather
// than overwritten (IEC 61850-7-2).
func (rm *reportManager) eventLocked(rs *rcbState, e *reportEntry) {
	bufTm := time.Duration(rs.attrUint("BufTm")) * time.Millisecond
	if bufTm <= 0 {
		rm.emitLocked(rs, e)
		return
	}
	if rs.pending != nil && overlaps(rs.pending.members, e.members) {
		rm.flushPendingLocked(rs)
	}
	if rs.pending == nil {
		p := &reportEntry{}
		rs.pending = p
		rs.pendTimer = time.AfterFunc(bufTm, func() {
			rm.s.mu.RLock()
			defer rm.s.mu.RUnlock()
			rs.mu.Lock()
			defer rs.mu.Unlock()
			if rs.pending == p {
				rm.flushPendingLocked(rs)
			}
		})
	}
	rs.pending.merge(e)
}

func (rm *reportManager) flushPendingLocked(rs *rcbState) {
	p := rs.pending
	if p == nil {
		return
	}
	rs.pending = nil
	if rs.pendTimer != nil {
		rs.pendTimer.Stop()
		rs.pendTimer = nil
	}
	if len(p.members) > 0 {
		rm.emitLocked(rs, p)
	}
}

// merge adds e's members to p, keeping dataset order.
func (p *reportEntry) merge(e *reportEntry) {
	for k, idx := range e.members {
		at := len(p.members)
		for j, m := range p.members {
			if m > idx {
				at = j
				break
			}
		}
		p.members = append(p.members[:at], append([]int{idx}, p.members[at:]...)...)
		p.values = append(p.values[:at], append([]*mms.Value{e.values[k]}, p.values[at:]...)...)
		p.reasons = append(p.reasons[:at], append([]model.ReasonCode{e.reasons[k]}, p.reasons[at:]...)...)
	}
}

func overlaps(a, b []int) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// emitLocked commits a report: an unbuffered block sends it if enabled; a
// buffered block numbers it, keeps it in the buffer — discarding the
// oldest past the buffer depth — and sends it if enabled.
func (rm *reportManager) emitLocked(rs *rcbState, e *reportEntry) {
	e.time = time.Now()
	if !rs.rc.Buffered {
		if rs.enabled {
			rm.transmitLocked(rs, e)
		}
		return
	}
	rs.entryCounter++
	e.id = makeEntryID(rs.entryCounter)
	rs.buffer = append(rs.buffer, e)
	for len(rs.buffer) > rs.maxBuffer {
		rs.buffer = rs.buffer[1:]
		if rs.next > 0 {
			rs.next-- // the discarded entry had been sent
		} else {
			rs.bufOverflow = true // it had not: the client will miss it
		}
	}
	rs.setAttr("EntryID", mms.NewOctetString(e.id))
	rs.setAttr("TimeofEntry", mms.NewBinaryTime(e.time))
	if rs.enabled {
		rm.transmitBufferedLocked(rs)
	}
}

// transmitBufferedLocked sends the buffered entries not yet sent.
func (rm *reportManager) transmitBufferedLocked(rs *rcbState) {
	for rs.next < len(rs.buffer) {
		rm.transmitLocked(rs, rs.buffer[rs.next])
		rs.next++
	}
}

// supportedOptFlds are the report fields a client may ask for. The
// segmentation bit is not among them: the server sets it on the reports it
// has to segment.
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

// transmitLocked sends one report with the next sequence number,
// segmented to the association's maximum PDU size when it does not fit.
func (rm *reportManager) transmitLocked(rs *rcbState, e *reportEntry) {
	conn := rs.conn
	if conn == nil {
		return
	}
	seq := rs.sqNum
	rs.setSqNumLocked(seq + 1)
	bufOvfl := rs.bufOverflow
	rs.bufOverflow = false

	for _, pdu := range rm.reportPDUs(rs, e, seq, bufOvfl, conn.MaxPDU) {
		if err := conn.SendUnconfirmed(pdu); err != nil {
			rm.s.log.Debug("server: report send failed", "rcb", rs.item, "err", err)
			if rs.rc.Buffered {
				rs.bufOverflow = true
			}
			return
		}
	}
}

// setSqNumLocked sets the sequence number the next report carries,
// wrapping at the width of the block's SqNum: INT8U for an unbuffered
// block, INT16U for a buffered one (IEC 61850-7-2).
func (rs *rcbState) setSqNumLocked(n uint32) {
	if rs.rc.Buffered {
		rs.sqNum = n & 0xffff
		rs.setAttr("SqNum", mms.NewUint16(uint16(rs.sqNum)))
	} else {
		rs.sqNum = n & 0xff
		rs.setAttr("SqNum", mms.NewUint8(uint8(rs.sqNum)))
	}
}

// reportPDUs builds the InformationReport(s) for e (IEC 61850-8-1): one
// when it fits in maxPDU octets, otherwise segments that each carry a
// run of the included members, SubSeqNum counting from zero and
// MoreSegmentsFollow set on all but the last. A single member too large
// for any PDU is sent in a segment of its own.
func (rm *reportManager) reportPDUs(rs *rcbState, e *reportEntry, seq uint32, bufOvfl bool, maxPDU int) []*asn1.Element {
	opt := effectiveOptFlds(model.OptFldsFromValue(rs.attr("OptFlds")), rs.rc.Buffered)
	members, _ := rm.resolveDataSet(rs.attrText("DatSet"))
	build := func(from, to int, segmented bool, subSeq int, more bool) *asn1.Element {
		return rm.reportElement(rs, e, members, opt, seq, bufOvfl, from, to, segmented, subSeq, more)
	}
	// The unconfirmed PDU adds its own tag and length to the report.
	fits := func(el *asn1.Element) bool { return maxPDU <= 0 || el.Size()+4 <= maxPDU }

	n := len(e.members)
	if whole := build(0, n, false, 0, false); fits(whole) {
		return []*asn1.Element{whole}
	}
	var out []*asn1.Element
	for from, subSeq := 0, 0; from < n; subSeq++ {
		to := from + 1
		for to < n && fits(build(from, to+1, true, subSeq, true)) {
			to++
		}
		out = append(out, build(from, to, true, subSeq, to < n))
		from = to
	}
	return out
}

// reportElement encodes the report of e's members [from, to).
func (rm *reportManager) reportElement(rs *rcbState, e *reportEntry, members []dsMember, opt model.OptFlds,
	seq uint32, bufOvfl bool, from, to int, segmented bool, subSeq int, more bool) *asn1.Element {
	if segmented {
		opt |= model.OptSegmentation
	}
	results := asn1.Cons(asn1.ContextConstructed(0)) // listOfAccessResult [0]
	add := func(v *mms.Value) { results.Add(mms.DataElement(v)) }

	add(rs.rptIDOf(rs.attr("RptID")))
	add(opt.Value())
	if opt&model.OptSeqNum != 0 {
		if rs.rc.Buffered {
			add(mms.NewUint16(uint16(seq)))
		} else {
			add(mms.NewUint8(uint8(seq)))
		}
	}
	if opt&model.OptTimeOfEntry != 0 {
		add(mms.NewBinaryTime(e.time))
	}
	if opt&model.OptDataSetName != 0 {
		add(mms.NewVisibleString(rs.attrText("DatSet")))
	}
	if opt&model.OptBufOvfl != 0 {
		add(mms.NewBool(bufOvfl))
	}
	if opt&model.OptEntryID != 0 {
		add(mms.NewOctetString(e.id))
	}
	if opt&model.OptConfRev != 0 {
		add(mms.NewUint32(uint32(rs.attrUint("ConfRev"))))
	}
	if segmented {
		add(mms.NewUint16(uint16(subSeq)))
		add(mms.NewBool(more))
	}

	// Inclusion bitstring: one bit per dataset member.
	inclusion := mms.NewBitString(len(members))
	for _, idx := range e.members[from:to] {
		inclusion.SetBit(idx, true)
	}
	add(inclusion)
	// Data references precede the values: "LDName/LNName$FC$DataName",
	// the MMS form of the member's reference.
	if opt&model.OptDataRef != 0 {
		for _, idx := range e.members[from:to] {
			if idx < len(members) {
				add(mms.NewVisibleString(members[idx].domain + "/" + members[idx].item))
			}
		}
	}
	for _, v := range e.values[from:to] {
		add(v)
	}
	if opt&model.OptReasonCode != 0 {
		for _, r := range e.reasons[from:to] {
			add(r.Value())
		}
	}

	// InformationReport [0] { variableListName [1] { vmd-specific "RPT" }, listOfAccessResult [0] }
	return asn1.Cons(asn1.ContextConstructed(0),
		asn1.Cons(asn1.ContextConstructed(1), asn1.Prim(asn1.ContextPrimitive(0), []byte("RPT"))),
		results,
	)
}

// makeEntryID encodes a monotonic counter as an 8-octet EntryID.
func makeEntryID(n uint64) []byte {
	return []byte{
		byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
		byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
	}
}

func isZeroEntryID(id []byte) bool {
	return len(id) == 8 && bytes.Equal(id, make([]byte, 8))
}

// bufferIndex is the position of the entry with EntryID id, or -1.
func (rs *rcbState) bufferIndex(id []byte) int {
	for i, e := range rs.buffer {
		if bytes.Equal(e.id, id) {
			return i
		}
	}
	return -1
}

func (rs *rcbState) attr(name string) *mms.Value {
	if a := rs.do.Attribute(name); a != nil {
		return a.Value
	}
	return nil
}

func (rs *rcbState) attrText(name string) string {
	if v := rs.attr(name); v != nil {
		return v.Text()
	}
	return ""
}

func (rs *rcbState) attrUint(name string) uint64 {
	if v := rs.attr(name); v != nil {
		return v.Uint64()
	}
	return 0
}

func (rs *rcbState) setAttr(name string, v *mms.Value) {
	if a := rs.do.Attribute(name); a != nil {
		a.Value = v
	}
}

func (rs *rcbState) trgOps() model.TrgOps {
	if v := rs.attr("TrgOps"); v != nil {
		return model.TrgOpsFromValue(v)
	}
	return 0
}

// resolveDataSet resolves a DatSet value ("LD/LN$DataSet") to its members,
// reporting whether the dataset exists.
func (rm *reportManager) resolveDataSet(ref string) ([]dsMember, bool) {
	domain, list, ok := strings.Cut(ref, "/")
	if !ok {
		return nil, false
	}
	lnName, dsName, ok := strings.Cut(list, "$")
	if !ok {
		return nil, false
	}
	ld := rm.s.model.Device(domain)
	if ld == nil {
		return nil, false
	}
	ln := ld.Node(lnName)
	if ln == nil || ln.DataSet(dsName) == nil {
		return nil, false
	}
	return (&handler{s: rm.s}).datasetMembers(domain, list), true
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
