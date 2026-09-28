package server

import (
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"time"
)

// The GOOSE, sampled-value and log control blocks of IEC 61850-8-1 are
// MMS objects like the report and setting-group ones: a client browsing the
// server expects to find them, and the SCL loader already carries their
// configuration. Only the report blocks and the setting-group block were
// materialised, so a client that enumerated control blocks found a server
// with GOOSE configuration but no GoCB to show for it.
//
// These attributes are the read-only configuration of each block, plus the
// writable ones a client is allowed to change. They are not a publishing
// interface: this library has no server-side GOOSE or SV publisher, so
// writing GoCB.DstMAC does not start a publisher.

// materialiseControlBlocks adds the GOOSE, sampled-value and log control
// blocks of each logical node to it as browsable data objects, under the
// functional constraints IEC 61850-8-1 assigns them: GO and GS for the
// GOOSE variants, MS and US for multicast and unicast sampled values, and
// LG for logs.
func materialiseControlBlocks(m *model.Model) {
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, gc := range ln.GSEControls {
				ln.Objects = append(ln.Objects, buildGoCBObject(gc))
			}
			for _, sc := range ln.SVControls {
				ln.Objects = append(ln.Objects, buildSVCBObject(sc))
			}
			for _, lc := range ln.LogControls {
				ln.Objects = append(ln.Objects, buildLCBObject(ld, ln, lc))
			}
		}
	}
}

// cbAttr builds a read-only control-block attribute.
func cbAttr(fc model.FC, name string, v *mms.Value) *model.DataAttribute {
	return &model.DataAttribute{Name: name, FC: fc, Kind: v.Type(), Value: v}
}

// gseFC is the constraint a GOOSE control block is served under: GS for
// the legacy GSSE variant, GO for plain and routable GOOSE.
func gseFC(gc *model.GSEControl) model.FC {
	if gc.Type == model.GSSE {
		return model.GS
	}
	return model.GO
}

// buildGoCBObject materialises a GoCB or GsCB (IEC 61850-8-1): the dataset
// reference, configuration revision, the GOOSE identity and the multicast
// address, plus the control and status attributes.
func buildGoCBObject(gc *model.GSEControl) *model.DataObject {
	fc := gseFC(gc)
	trgOps := model.TrgGI
	do := &model.DataObject{Name: gc.Name, CDC: "GOCB"}
	add := func(name string, v *mms.Value) {
		do.Attributes = append(do.Attributes, cbAttr(fc, name, v))
	}
	add("DatSet", mms.NewVisibleString(gc.DataSet))
	add("ConfRev", mms.NewUint32(gc.ConfRev))
	add("GoID", mms.NewVisibleString(gc.GoID))
	add("GoCBRef", mms.NewVisibleString(gc.GoID))
	add("DstMAC", mms.NewOctetString(macBytes(gc.DstMAC)))
	add("APPID", mms.NewUint16(gc.AppID))
	add("VLANID", mms.NewUint16(gc.VLANID))
	add("VLAN-PRIORITY", mms.NewUint8(uint8(gc.VLANPri)))
	add("MinTime", mms.NewUint32(gc.MinTime))
	add("MaxTime", mms.NewUint32(gc.MaxTime))
	if gc.FixedOffs > 0 {
		add("FixedOffs", mms.NewUint32(gc.FixedOffs))
	}
	add("TrgOps", trgOps.Value())
	// The state of the block. It does not change: this library does not
	// publish GOOSE from a server, so the block is idle and the counters
	// stay at zero. They exist so a client that reads them gets a defined
	// answer rather than object-non-existent.
	add("GoCBRef-state", mms.NewUint32(0))
	add("StNum", mms.NewUint32(0))
	add("SqNum", mms.NewUint32(0))
	add("LastApplError", idleLastApplError())
	add("NdsCom", mms.NewBool(false))
	add("Test", mms.NewBool(false))
	return do
}

// buildSVCBObject materialises an MSVCB or USVCB (IEC 61850-8-1 and 9-2).
// SmvOpts selects which optional ASDU fields the block carries, so their
// presence follows the configuration rather than being fixed.
func buildSVCBObject(sc *model.SVControl) *model.DataObject {
	// A block is unicast when it is not multicast, or when the document
	// says so through the R-SV profile.
	fc := model.MS
	if !sc.Multicast || sc.Protocol == "R-SV" {
		fc = model.US
	}
	do := &model.DataObject{Name: sc.Name, CDC: "MSVCB"}
	add := func(name string, v *mms.Value) {
		do.Attributes = append(do.Attributes, cbAttr(fc, name, v))
	}
	add("DatSet", mms.NewVisibleString(sc.DataSet))
	add("ConfRev", mms.NewUint32(sc.ConfRev))
	add("SvID", mms.NewVisibleString(sc.SvID))
	add("DstMAC", mms.NewOctetString(macBytes(sc.DstMAC)))
	add("APPID", mms.NewUint16(sc.AppID))
	add("VLANID", mms.NewUint16(sc.VLANID))
	add("VLAN-PRIORITY", mms.NewUint8(uint8(sc.VLANPri)))
	add("SmpRate", mms.NewUint32(sc.SmpRate))
	add("NoOfASDU", mms.NewUint32(sc.NoASDU))
	add("SmpMod", mms.NewVisibleString(sc.SmpMod.String()))
	// The optional-field set, as the SmvOptFlds bit string of IEC 61850-8-1:
	// one bit per optional ASDU field, in the order the standard lists them.
	opts := sc.Opts
	optFlds := mms.NewBitString(10)
	set := func(i int, on bool) { optFlds.SetBit(i, on) }
	set(0, opts.RefreshTime)
	set(1, opts.SampleSynchronized)
	set(2, opts.SampleRate)
	set(3, opts.DataSet)
	set(4, opts.Security)
	set(5, opts.Timestamp)
	set(6, opts.SynchSourceID)
	add("SmvOptFlds", optFlds)
	add("TrgOps", model.TrgGI.Value())
	add("SmpCnt", mms.NewUint16(0))
	add("LastApplError", idleLastApplError())
	return do
}

// buildLCBObject materialises an LCB (IEC 61850-8-1, clause 8).
func buildLCBObject(ld *model.LogicalDevice, ln *model.LogicalNode, lc *model.LogControl) *model.DataObject {
	fc := model.LG
	dsRef := ""
	if lc.DataSet != "" {
		dsRef = ld.Name + "/" + ln.Name + "$" + lc.DataSet
	}
	logRef := lc.LogName
	if logRef == "" {
		logRef = ld.Name + "/" + ln.Name + "$" + lc.Name
	}
	trgOps := lc.TrgOps
	if trgOps == 0 {
		trgOps = model.TrgDataChange | model.TrgGI
	}
	do := &model.DataObject{Name: lc.Name, CDC: "LCB"}
	add := func(name string, v *mms.Value) {
		do.Attributes = append(do.Attributes, cbAttr(fc, name, v))
	}
	add("LogEna", mms.NewBool(lc.LogEna))
	add("LogRef", mms.NewVisibleString(logRef))
	add("DatSet", mms.NewVisibleString(dsRef))
	add("TrgOps", trgOps.Value())
	add("IntgPd", mms.NewUint32(lc.IntgPd))
	add("BufTime", mms.NewUint32(lc.BufTime))
	add("LogID", mms.NewVisibleString(lc.LogName))
	add("OldestEntry", mms.NewBinaryTime(zeroBinaryTime()))
	add("EntryID", mms.NewOctetString(make([]byte, 8)))
	add("PurgeBuf", mms.NewBool(false))
	if lc.ReasonCode {
		add("ReasonCode", mms.NewBool(true))
	}
	return do
}

// idleLastApplError is the LastApplError structure of a control block that
// has not refused anything, with no control object behind it.
func idleLastApplError() *mms.Value {
	return lastApplErrorValue("", "", &ControlCtx{}, model.AddCauseNone)
}

// zeroBinaryTime is the OldestEntry a log control block reports while it
// holds nothing: the epoch of MMS binary time, as the report control block
// TimeofEntry does.
func zeroBinaryTime() time.Time { return time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC) }

// macBytes renders a MAC address for an octet-string attribute.
func macBytes(m [6]byte) []byte {
	out := make([]byte, 6)
	copy(out, m[:])
	return out
}
