package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// rcbState is the runtime state of one report control block.
type rcbState struct {
	domain string
	item   string // "LN$RP$name01"
	ln     *model.LogicalNode
	do     *model.DataObject // the materialised RCB object
	rc     *model.ReportControl
	// maxBuffer is how many reports the buffer retains (BRCB only),
	// resolved once from the control block and the server default.
	maxBuffer int

	mu      sync.Mutex
	enabled bool
	conn    *mms.ServerConn // subscriber while enabled
	// owner is the client holding the block (IEC 61850-7-2): reserved
	// explicitly through Resv, or implicitly by the first client to write
	// it. Nobody else may change it until the owner lets go or leaves.
	owner    *mms.ServerConn
	sqNum    uint32
	intgStop chan struct{}

	// pending holds the events of an open buffer-time window (BufTm).
	pending   *reportEntry
	pendTimer *time.Timer

	// Buffered-report state (BRCB only).
	buffer       []*reportEntry // retained reports, oldest first
	next         int            // index in buffer of the next to transmit
	entryCounter uint64         // monotonic EntryID source
	resyncID     []byte         // client-requested resync point (EntryID write)
	bufOverflow  bool           // entries were discarded before transmission
}

// reportEntry is one report's content, captured when its events happen.
// Everything that depends on the moment of transmission — the sequence
// number, segmentation, BufOvfl — is added when it is sent, so a buffered
// report is numbered in the order the client receives it.
type reportEntry struct {
	id      []byte       // 8-octet EntryID (BRCB)
	time    time.Time    // TimeOfEntry
	members []int        // included dataset member indices, ascending
	values  []*mms.Value // one per member, as it was at the event
	reasons []model.ReasonCode
}

// defaultBufferedReports is the buffer depth of a control block that
// configures none, and of a server that sets no default.
const defaultBufferedReports = 256

// bufferDepth resolves how many reports one control block retains: its own
// MaxQueueSize, else the server's default, else the library's.
func bufferDepth(rc *model.ReportControl, serverDefault int) int {
	switch {
	case rc.MaxQueueSize > 0:
		return rc.MaxQueueSize
	case serverDefault > 0:
		return serverDefault
	}
	return defaultBufferedReports
}

// materialiseRCBs expands each logical node's report control blocks into
// browsable/writable data objects (FC RP for unbuffered, BR for buffered)
// carrying the standard control-block attributes, and returns the runtime
// registry keyed by "domain\x00LN$FC$name". bufDefault is the buffer depth
// for buffered blocks that do not set their own.
func materialiseRCBs(m *model.Model, bufDefault int) map[string]*rcbState {
	reg := make(map[string]*rcbState)
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, rc := range ln.ReportControls {
				fc := model.RP
				if rc.Buffered {
					fc = model.BR
				}
				for _, instName := range rcbInstanceNames(rc) {
					do := buildRCBObject(ld, ln, rc, fc, instName)
					ln.Objects = append(ln.Objects, do)
					item := ln.Name + "$" + fc.String() + "$" + instName
					reg[ld.Name+"\x00"+item] = &rcbState{
						domain: ld.Name, item: item, ln: ln, do: do, rc: rc,
						maxBuffer: bufferDepth(rc, bufDefault),
					}
				}
			}
		}
	}
	return reg
}

// rcbInstanceNames names the instances of a control block (IEC 61850-6):
// an indexed block, the default, has RptEnabled max instances named
// Name01..NameNN; an unindexed block is the single instance Name.
func rcbInstanceNames(rc *model.ReportControl) []string {
	if rc.NotIndexed {
		return []string{rc.Name}
	}
	n := rc.RptEnabled
	if n < 1 {
		n = 1
	}
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s%02d", rc.Name, i+1)
	}
	return names
}

// buildRCBObject materialises the standard URCB/BRCB attributes as a data
// object named after the control block instance.
func buildRCBObject(ld *model.LogicalDevice, ln *model.LogicalNode, rc *model.ReportControl, fc model.FC, instName string) *model.DataObject {
	dsRef := ""
	if rc.DataSet != "" {
		dsRef = ld.Name + "/" + ln.Name + "$" + rc.DataSet
	}
	optFlds := rc.OptFlds
	if optFlds == 0 {
		optFlds = model.OptFldsDefault
	}
	trgOps := rc.TrgOps
	if trgOps == 0 {
		trgOps = model.TrgDataChange | model.TrgQualityChange | model.TrgGI
	}
	attr := func(name string, v *mms.Value) *model.DataAttribute {
		return &model.DataAttribute{Name: name, FC: fc, Kind: v.Type(), Value: v}
	}
	// An empty RptID is kept empty: it means "use the control block's
	// reference", which is resolved when a report is sent (rptIDOf).
	if rc.Buffered {
		// BRCB layout (IEC 61850-8-1): buffered reports carry EntryID and
		// TimeofEntry, so those option bits are always set.
		optFlds |= model.OptEntryID | model.OptTimeOfEntry | model.OptBufOvfl
		return &model.DataObject{Name: instName, Attributes: []*model.DataAttribute{
			attr("RptID", mms.NewVisibleString(rc.RptID)),
			attr("RptEna", mms.NewBool(false)),
			attr("DatSet", mms.NewVisibleString(dsRef)),
			attr("ConfRev", mms.NewUint32(rc.ConfRev)),
			attr("OptFlds", optFlds.Value()),
			attr("BufTm", mms.NewUint32(rc.BufTime)),
			attr("SqNum", mms.NewUint16(0)),
			attr("TrgOps", trgOps.Value()),
			attr("IntgPd", mms.NewUint32(rc.IntgPd)),
			attr("GI", mms.NewBool(false)),
			attr("PurgeBuf", mms.NewBool(false)),
			attr("EntryID", mms.NewOctetString(make([]byte, 8))),
			attr("TimeofEntry", mms.NewBinaryTime(time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC))),
			attr("ResvTms", mms.NewInt16(0)),
		}}
	}
	return &model.DataObject{Name: instName, Attributes: []*model.DataAttribute{
		attr("RptID", mms.NewVisibleString(rc.RptID)),
		attr("RptEna", mms.NewBool(false)),
		attr("Resv", mms.NewBool(false)),
		attr("DatSet", mms.NewVisibleString(dsRef)),
		attr("ConfRev", mms.NewUint32(rc.ConfRev)),
		attr("OptFlds", optFlds.Value()),
		attr("BufTm", mms.NewUint32(rc.BufTime)),
		attr("SqNum", mms.NewUint8(0)),
		attr("TrgOps", trgOps.Value()),
		attr("IntgPd", mms.NewUint32(rc.IntgPd)),
		attr("GI", mms.NewBool(false)),
	}}
}

// rptIDOf is the RptID a report carries: the RptID attribute, or when that
// is empty the control block instance's own reference (IEC 61850-7-2),
// which tells instances of one block apart.
func (rs *rcbState) rptIDOf(attr *mms.Value) *mms.Value {
	if attr != nil && attr.Text() != "" {
		return attr
	}
	return mms.NewVisibleString(rs.domain + "/" + rs.item)
}

// rcbKey reports whether item ("LN$FC$name[$attr]") addresses a report
// control block, returning the RCB key prefix and the attribute name.
func rcbKey(domain, item string) (key, attr string, ok bool) {
	parts := strings.Split(item, "$")
	if len(parts) < 3 {
		return "", "", false
	}
	if parts[1] != "RP" && parts[1] != "BR" {
		return "", "", false
	}
	base := parts[0] + "$" + parts[1] + "$" + parts[2]
	if len(parts) >= 4 {
		attr = parts[3]
	}
	return domain + "\x00" + base, attr, true
}
