package client

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// RCB holds the configuration of a report control block. Fields read from
// the server are populated by GetRCB; fields set before EnableReporting
// are written to the server.
type RCB struct {
	Ref      model.ObjectReference // "LD/LN.RP.name" or "LD/LN.BR.name"
	Buffered bool

	RptID   string
	DataSet string // MMS notation, e.g. "LD/LN$DataSet"
	ConfRev uint32
	OptFlds model.OptFlds
	TrgOps  model.TrgOps
	BufTm   uint32        // ms, integrity/dchg buffering
	IntgPd  time.Duration // integrity period

	// ResyncEntryID, when set on a buffered RCB before EnableReporting,
	// requests delivery of buffered reports after this EntryID.
	ResyncEntryID []byte

	domain string
	item   string // "LN$RP$name"
}

// rcbRefToMMS converts "LD/LN.RP.name" to domain "LD" and item
// "LN$RP$name".
func rcbRefToMMS(ref model.ObjectReference) (domain, item string) {
	domain = ref.LD()
	return domain, strings.Join(ref.Path(), "$")
}

// GetRCB reads a report control block's current configuration.
func (c *Client) GetRCB(ctx context.Context, ref model.ObjectReference) (*RCB, error) {
	domain, item := rcbRefToMMS(ref)
	rcb := &RCB{Ref: ref, domain: domain, item: item, Buffered: strings.Contains(item, "$BR$")}

	read := func(attr string) (*mms.Value, error) {
		vals, err := c.mc.Read(ctx, domain, item+"$"+attr)
		if err != nil {
			return nil, err
		}
		if len(vals) == 0 {
			return nil, fmt.Errorf("client: RCB attribute %s missing", attr)
		}
		if code, isErr := vals[0].AccessError(); isErr {
			return nil, code
		}
		return vals[0], nil
	}

	if v, err := read("RptID"); err == nil {
		rcb.RptID = v.Text()
	}
	if v, err := read("DatSet"); err == nil {
		rcb.DataSet = v.Text()
	}
	if v, err := read("ConfRev"); err == nil {
		rcb.ConfRev = uint32(v.Uint64())
	}
	if v, err := read("OptFlds"); err == nil {
		rcb.OptFlds = model.OptFldsFromValue(v)
	}
	if v, err := read("TrgOps"); err == nil {
		rcb.TrgOps = model.TrgOpsFromValue(v)
	}
	if v, err := read("IntgPd"); err == nil {
		rcb.IntgPd = time.Duration(v.Uint64()) * time.Millisecond
	}
	return rcb, nil
}

// Report is one decoded report delivered to a subscriber.
type Report struct {
	RptID       string
	SeqNum      uint32
	DataSet     string
	ConfRev     uint32
	EntryID     []byte
	BufOvfl     bool
	SubSeqNum   uint32
	MoreFollows bool
	TimeOfEntry time.Time
	Entries     []ReportEntry
}

// ReportEntry is one included dataset member in a report.
type ReportEntry struct {
	Index  int                   // position in the dataset
	Ref    model.ObjectReference // resolved from the dataset, if known
	FC     model.FC
	Reason model.ReasonCode
	Value  *mms.Value
}

// ReportSubscription is an active report subscription.
type ReportSubscription struct {
	c      *Client
	rcb    *RCB
	once   sync.Once
	closed bool
}

// EnableReporting configures and enables the report control block, then
// delivers decoded reports to cb until the subscription is disabled. The
// RCB's OptFlds, TrgOps and IntgPd are written to the server if non-zero.
//
// The callback runs on the connection's reader goroutine and must not
// block; hand heavy work to another goroutine.
func (c *Client) EnableReporting(ctx context.Context, rcb *RCB, cb func(*Report)) (*ReportSubscription, error) {
	// Learn the dataset members so report entries can be labelled.
	members, _ := c.datasetMembersForRCB(ctx, rcb)

	// Reserve the RCB (unbuffered) and push configuration.
	if rcb.OptFlds != 0 {
		if err := c.writeRCB(ctx, rcb, "OptFlds", rcb.OptFlds.Value()); err != nil {
			return nil, err
		}
	}
	if rcb.TrgOps != 0 {
		if err := c.writeRCB(ctx, rcb, "TrgOps", rcb.TrgOps.Value()); err != nil {
			return nil, err
		}
	}
	if rcb.IntgPd > 0 {
		if err := c.writeRCB(ctx, rcb, "IntgPd", mms.NewUint32(uint32(rcb.IntgPd.Milliseconds()))); err != nil {
			return nil, err
		}
	}

	// For buffered RCBs, a resync EntryID requests redelivery of buffered
	// reports after that point; it must be written before enabling.
	if rcb.Buffered && len(rcb.ResyncEntryID) > 0 {
		if err := c.writeRCB(ctx, rcb, "EntryID", mms.NewOctetString(rcb.ResyncEntryID)); err != nil {
			return nil, err
		}
	}

	// Register the report handler before enabling.
	c.mc.OnInformationReport(func(ir *mms.InformationReport) {
		rep := decodeReport(ir, rcb, members)
		if rep != nil && rep.RptID == rcb.RptID {
			cb(rep)
		}
	})

	if err := c.writeRCB(ctx, rcb, "RptEna", mms.NewBool(true)); err != nil {
		return nil, err
	}
	return &ReportSubscription{c: c, rcb: rcb}, nil
}

// TriggerGI requests a general interrogation: the server sends a report
// containing all dataset members.
func (c *Client) TriggerGI(ctx context.Context, rcb *RCB) error {
	return c.writeRCB(ctx, rcb, "GI", mms.NewBool(true))
}

// Disable turns the report control block off.
func (s *ReportSubscription) Disable(ctx context.Context) error {
	var err error
	s.once.Do(func() {
		err = s.c.writeRCB(ctx, s.rcb, "RptEna", mms.NewBool(false))
		s.closed = true
	})
	return err
}

func (c *Client) writeRCB(ctx context.Context, rcb *RCB, attr string, v *mms.Value) error {
	results, err := c.mc.Write(ctx, rcb.domain, []string{rcb.item + "$" + attr}, []*mms.Value{v})
	if err != nil {
		return err
	}
	if len(results) > 0 && results[0] != nil {
		return fmt.Errorf("client: RCB write %s: %w", attr, results[0])
	}
	return nil
}

func (c *Client) datasetMembersForRCB(ctx context.Context, rcb *RCB) ([]mms.VarRef, error) {
	ds := rcb.DataSet
	if ds == "" {
		if v, err := c.mc.Read(ctx, rcb.domain, rcb.item+"$DatSet"); err == nil && len(v) > 0 {
			ds = v[0].Text()
		}
	}
	// DatSet is "LD/LN$Name"; convert to (domain, "LN$Name").
	_, list, ok := strings.Cut(ds, "/")
	if !ok {
		return nil, fmt.Errorf("client: RCB dataset reference %q", ds)
	}
	return c.mc.GetNamedVariableListAttributes(ctx, rcb.domain, list)
}

// decodeReport interprets a flat InformationReport value list per the
// IEC 61850-8-1 report format, driven by the OptFlds present in the
// report itself (field 1).
func decodeReport(ir *mms.InformationReport, rcb *RCB, members []mms.VarRef) *Report {
	v := ir.Values
	if len(v) < 3 {
		return nil
	}
	i := 0
	next := func() *mms.Value {
		if i < len(v) {
			val := v[i]
			i++
			return val
		}
		return nil
	}

	rep := &Report{}
	rep.RptID = next().Text()
	opt := model.OptFldsFromValue(next())

	if opt&model.OptSeqNum != 0 {
		rep.SeqNum = uint32(next().Uint64())
	}
	if opt&model.OptTimeOfEntry != 0 {
		rep.TimeOfEntry = next().Time()
	}
	if opt&model.OptDataSetName != 0 {
		rep.DataSet = next().Text()
	}
	if opt&model.OptBufOvfl != 0 {
		rep.BufOvfl = next().Bool()
	}
	if opt&model.OptEntryID != 0 {
		rep.EntryID = append([]byte(nil), next().Bytes()...)
	}
	if opt&model.OptConfRev != 0 {
		rep.ConfRev = uint32(next().Uint64())
	}
	if opt&model.OptSegmentation != 0 {
		rep.SubSeqNum = uint32(next().Uint64())
		rep.MoreFollows = next().Bool()
	}

	inclusion := next()
	if inclusion == nil {
		return rep
	}
	// Collect indices of included members.
	var included []int
	for b := 0; b < inclusion.BitLen(); b++ {
		if inclusion.Bit(b) {
			included = append(included, b)
		}
	}

	// Optional data-reference strings precede the values.
	if opt&model.OptDataRef != 0 {
		for range included {
			next() // skip data-reference; positions are known from members
		}
	}
	// Values, one per included member.
	entries := make([]ReportEntry, 0, len(included))
	for _, idx := range included {
		e := ReportEntry{Index: idx, Value: next()}
		if idx < len(members) {
			e.Ref, e.FC = model.FromMMS(members[idx].Domain, members[idx].Item)
		}
		entries = append(entries, e)
	}
	// Reason codes, one per included member.
	if opt&model.OptReasonCode != 0 {
		for k := range entries {
			entries[k].Reason = model.ReasonFromValue(next())
		}
	}
	rep.Entries = entries
	return rep
}
