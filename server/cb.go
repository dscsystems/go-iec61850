package server

import (
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// The GOOSE, sampled-value and log control blocks of IEC 61850-8-1 are
// MMS objects like the report and setting-group ones: a client browsing the
// server expects to find them, and the SCL loader already carries their
// configuration. Only the report blocks and the setting-group block were
// materialised, so a client that enumerated control blocks found a server
// with GOOSE configuration but no GoCB to show for it.
//
// Each block has the components IEC 61850-8-1 gives its MMS structure, in
// the standard's order and under the standard's names, since a client
// addresses them by name ("gcb01$GoEna"). Nothing is added that the
// structure does not define: a component a client does not expect is
// harmless to it, but one it looks for under the standard's name and does
// not find is not. The GOOSE blocks are read-only: this library has no
// server-side GOOSE publisher, so their enable flags read false and writing
// them is refused. The SV blocks take SvEna and, for a USVCB, Resv
// (svcb.go); the application publishes. An LCB is live: it writes the server's logs
// (journal.go), and a client sets LogEna, DatSet, TrgOps and IntgPd.

// materialiseControlBlocks adds the GOOSE, sampled-value and log control
// blocks of each logical node to it as browsable data objects, under the
// functional constraints IEC 61850-8-1 assigns them: GO and GS for the
// GOOSE variants, MS and US for multicast and unicast sampled values, and
// LG for logs.
func materialiseControlBlocks(m *model.Model) {
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, gc := range ln.GSEControls {
				ln.Objects = append(ln.Objects, buildGoCBObject(ld, ln, gc))
			}
			for _, sc := range ln.SVControls {
				ln.Objects = append(ln.Objects, buildSVCBObject(ld, ln, sc))
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

// cbDataSetRef is the DatSet a control block serves: the object reference
// of a dataset in the block's own logical node, as the report control
// blocks carry it, or empty when the block names none.
func cbDataSetRef(ld *model.LogicalDevice, ln *model.LogicalNode, name string) string {
	if name == "" {
		return ""
	}
	return ld.Name + "/" + ln.Name + "$" + name
}

// dstAddress builds the DstAddress structure of IEC 61850-8-1, the
// PHYCOMADDR of a GOOSE or sampled-value block: the destination MAC, the
// VLAN priority and identifier, and the APPID.
func dstAddress(fc model.FC, mac [6]byte, pri uint8, vid, appID uint16) *model.DataAttribute {
	return &model.DataAttribute{Name: "DstAddress", FC: fc, Kind: mms.TypeStructure,
		Children: []*model.DataAttribute{
			cbAttr(fc, "Addr", mms.NewOctetString(macBytes(mac))),
			cbAttr(fc, "PRIORITY", mms.NewUint8(pri)),
			cbAttr(fc, "VID", mms.NewUint16(vid)),
			cbAttr(fc, "APPID", mms.NewUint16(appID)),
		}}
}

// buildGoCBObject materialises a GoCB (FC GO) or a GsCB (FC GS) as
// IEC 61850-8-1 defines them.
func buildGoCBObject(ld *model.LogicalDevice, ln *model.LogicalNode, gc *model.GSEControl) *model.DataObject {
	if gc.Type == model.GSSE {
		return buildGsCBObject(gc)
	}
	const fc = model.GO
	do := &model.DataObject{Name: gc.Name, CDC: "GOCB"}
	add := func(a *model.DataAttribute) { do.Attributes = append(do.Attributes, a) }
	add(cbAttr(fc, "GoEna", mms.NewBool(false)))
	add(cbAttr(fc, "GoID", mms.NewVisibleString(gc.GoID)))
	add(cbAttr(fc, "DatSet", mms.NewVisibleString(cbDataSetRef(ld, ln, gc.DataSet))))
	add(cbAttr(fc, "ConfRev", mms.NewUint32(gc.ConfRev)))
	add(cbAttr(fc, "NdsCom", mms.NewBool(false)))
	add(dstAddress(fc, gc.DstMAC, gc.VLANPri, gc.VLANID, gc.AppID))
	add(cbAttr(fc, "MinTime", mms.NewUint32(gc.MinTime)))
	add(cbAttr(fc, "MaxTime", mms.NewUint32(gc.MaxTime)))
	add(cbAttr(fc, "FixedOffs", mms.NewBool(gc.FixedOffs)))
	return do
}

// buildGsCBObject materialises the GSSE control block (FC GS). GSSE was
// withdrawn in Edition 2 and this library does not implement it, so only
// the enable flag and the identity are served; the label lists of the
// full structure have nothing behind them to report.
func buildGsCBObject(gc *model.GSEControl) *model.DataObject {
	const fc = model.GS
	return &model.DataObject{Name: gc.Name, CDC: "GSCB", Attributes: []*model.DataAttribute{
		cbAttr(fc, "GsEna", mms.NewBool(false)),
		cbAttr(fc, "GsID", mms.NewVisibleString(gc.GoID)),
	}}
}

// buildSVCBObject materialises an MSVCB (FC MS) or a USVCB (FC US) as
// IEC 61850-8-1 defines them. OptFlds selects which optional ASDU fields
// the block carries, so their presence follows the configuration rather
// than being fixed.
func buildSVCBObject(ld *model.LogicalDevice, ln *model.LogicalNode, sc *model.SVControl) *model.DataObject {
	// A block is unicast when it is not multicast, or when the document
	// says so through the R-SV profile.
	unicast := !sc.Multicast || sc.Protocol == "R-SV"
	fc, cdc, idName := model.MS, "MSVCB", "MsvID"
	if unicast {
		fc, cdc, idName = model.US, "USVCB", "UsvID"
	}
	do := &model.DataObject{Name: sc.Name, CDC: cdc}
	add := func(a *model.DataAttribute) { do.Attributes = append(do.Attributes, a) }
	add(cbAttr(fc, "SvEna", mms.NewBool(false)))
	if unicast {
		// A unicast block is reserved by the client it sends to.
		add(cbAttr(fc, "Resv", mms.NewBool(false)))
	}
	add(cbAttr(fc, idName, mms.NewVisibleString(sc.SvID)))
	add(cbAttr(fc, "DatSet", mms.NewVisibleString(cbDataSetRef(ld, ln, sc.DataSet))))
	add(cbAttr(fc, "ConfRev", mms.NewUint32(sc.ConfRev)))
	add(cbAttr(fc, "SmpRate", mms.NewUint16(uint16(sc.SmpRate))))
	// OptFlds is the SmvOpts bit string: one bit per optional ASDU field,
	// in the order the standard lists them.
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
	add(cbAttr(fc, "OptFlds", optFlds))
	// SmpMod is an ENUMERATED, which MMS carries as an integer: 0 samples
	// per nominal period, 1 per second, 2 seconds per sample.
	add(cbAttr(fc, "SmpMod", mms.NewInt8(int8(sc.SmpMod))))
	add(dstAddress(fc, sc.DstMAC, sc.VLANPri, sc.VLANID, sc.AppID))
	add(cbAttr(fc, "noASDU", mms.NewUint16(uint16(sc.NoASDU))))
	return do
}

// buildLCBObject materialises an LCB (FC LG) as IEC 61850-8-1 defines it.
// While the log holds nothing the entry range reads as empty: the epoch for
// the times and the all-zero EntryID, which is what an empty buffered
// report control block reports too. The log manager keeps the range
// current as entries arrive.
func buildLCBObject(ld *model.LogicalDevice, ln *model.LogicalNode, lc *model.LogControl) *model.DataObject {
	const fc = model.LG
	trgOps := lc.TrgOps
	if trgOps == 0 {
		trgOps = model.TrgDataChange | model.TrgGI
	}
	do := &model.DataObject{Name: lc.Name, CDC: "LCB"}
	add := func(name string, v *mms.Value) {
		do.Attributes = append(do.Attributes, cbAttr(fc, name, v))
	}
	add("LogEna", mms.NewBool(lc.LogEna))
	add("LogRef", mms.NewVisibleString(logRef(ld, lc)))
	add("DatSet", mms.NewVisibleString(cbDataSetRef(ld, ln, lc.DataSet)))
	add("OldEntrTm", mms.NewBinaryTime(zeroBinaryTime()))
	add("NewEntrTm", mms.NewBinaryTime(zeroBinaryTime()))
	add("OldEnt", mms.NewOctetString(make([]byte, 8)))
	add("NewEnt", mms.NewOctetString(make([]byte, 8)))
	add("TrgOps", trgOps.Value())
	add("IntgPd", mms.NewUint32(lc.IntgPd))
	return do
}

// logRef is the reference of the log an LCB writes to, "LD/LN$Log", or
// empty when the block names no log. See logTarget.
func logRef(ld *model.LogicalDevice, lc *model.LogControl) string {
	domain, name, ok := logTarget(ld, lc)
	if !ok {
		return ""
	}
	return domain + "/" + name
}

// zeroBinaryTime is the entry time a log control block reports while it
// holds nothing: the epoch of MMS binary time, as the report control block
// TimeofEntry does.
func zeroBinaryTime() time.Time { return time.Date(1984, 1, 1, 0, 0, 0, 0, time.UTC) }

// macBytes renders a MAC address for an octet-string attribute.
func macBytes(m [6]byte) []byte {
	out := make([]byte, 6)
	copy(out, m[:])
	return out
}
