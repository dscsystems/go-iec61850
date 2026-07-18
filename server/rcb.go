package server

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// rcbState is the runtime state of one report control block.
type rcbState struct {
	domain string
	item   string // "LN$RP$name"
	ln     *model.LogicalNode
	do     *model.DataObject // the materialised RCB object
	rc     *model.ReportControl

	mu       sync.Mutex
	enabled  bool
	conn     *mms.ServerConn
	seqNum   uint32
	intgStop chan struct{}

	// Buffered-report state (BRCB only).
	buffer       []bufEntry // pending buffered reports, oldest first
	entryCounter uint64     // monotonic EntryID source
	resyncID     []byte     // client-requested resync point (EntryID write)
	bufOverflow  bool       // set when the buffer discarded unsent entries
}

// bufEntry is one buffered report retained for delivery and resync.
type bufEntry struct {
	id   []byte        // 8-octet EntryID
	elem *asn1.Element // pre-built informationReport element
}

// maxBufferedReports bounds a BRCB's buffer.
const maxBufferedReports = 256

// materialiseRCBs expands each logical node's report control blocks into
// browsable/writable data objects (FC RP for unbuffered, BR for buffered)
// carrying the standard control-block attributes, and returns the runtime
// registry keyed by "domain\x00LN$FC$name".
func materialiseRCBs(m *model.Model) map[string]*rcbState {
	reg := make(map[string]*rcbState)
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, rc := range ln.ReportControls {
				fc := model.RP
				if rc.Buffered {
					fc = model.BR
				}
				// Report controls are indexed by default (IEC 61850-6):
				// RptEnabled max="N" yields instances Name01..NameNN.
				n := rc.RptEnabled
				if n < 1 {
					n = 1
				}
				for i := 1; i <= n; i++ {
					instName := fmt.Sprintf("%s%02d", rc.Name, i)
					do := buildRCBObject(ld, ln, rc, fc, instName)
					ln.Objects = append(ln.Objects, do)
					item := ln.Name + "$" + fc.String() + "$" + instName
					reg[ld.Name+"\x00"+item] = &rcbState{
						domain: ld.Name, item: item, ln: ln, do: do, rc: rc,
					}
				}
			}
		}
	}
	return reg
}

// buildRCBObject materialises the standard URCB/BRCB attributes as a data
// object named after the control block.
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
	if rc.Buffered {
		// BRCB layout (IEC 61850-8-1): buffered reports carry EntryID and
		// TimeofEntry, so those option bits are always set.
		optFlds |= model.OptEntryID | model.OptTimeOfEntry | model.OptBufOvfl
		return &model.DataObject{Name: instName, Attributes: []*model.DataAttribute{
			attr("RptID", mms.NewVisibleString(rcbRptID(rc, ld, ln))),
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
			attr("TimeofEntry", mms.NewBinaryTime(time.Unix(0, 0))),
			attr("ResvTms", mms.NewInt16(0)),
		}}
	}
	return &model.DataObject{Name: instName, Attributes: []*model.DataAttribute{
		attr("RptID", mms.NewVisibleString(rcbRptID(rc, ld, ln))),
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

func rcbRptID(rc *model.ReportControl, ld *model.LogicalDevice, ln *model.LogicalNode) string {
	if rc.RptID != "" {
		return rc.RptID
	}
	return ld.Name + "/" + ln.Name + "$" + fcTag(rc) + "$" + rc.Name
}

func fcTag(rc *model.ReportControl) string {
	if rc.Buffered {
		return "BR"
	}
	return "RP"
}

// isRCBItem reports whether item ("LN$FC$name[$attr]") addresses a report
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
