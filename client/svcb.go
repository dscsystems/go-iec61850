package client

import (
	"context"
	"fmt"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// ReserveUSVCB reserves the unicast sampled-value control block at ref
// ("LD/LLN0.usvcb01") for this association, or releases it when on is
// false (IEC 61850-7-2 SetUSVCBValues, Resv). While it holds the block no
// other client may change it; the server releases it and stops the stream
// when this association ends.
func (c *Client) ReserveUSVCB(ctx context.Context, ref model.ObjectReference, on bool) error {
	return c.Write(ctx, ref+".Resv", model.US, mms.NewBool(on))
}

// EnableSVCB starts or stops the stream of the sampled-value control
// block at ref: SvEna of an MSVCB (unicast false, FC MS) or of a USVCB
// (unicast true, FC US), which is to be reserved first with ReserveUSVCB
// for the stream to be this client's alone.
func (c *Client) EnableSVCB(ctx context.Context, ref model.ObjectReference, unicast, on bool) error {
	fc := model.MS
	if unicast {
		fc = model.US
	}
	return c.Write(ctx, ref+".SvEna", fc, mms.NewBool(on))
}

// SVCB is a sampled-value control block as a client reads it
// (IEC 61850-7-2 GetMSVCBValues and GetUSVCBValues).
type SVCB struct {
	Ref     model.ObjectReference // "LD/LN.name"
	Unicast bool                  // a USVCB (FC US), else an MSVCB (FC MS)

	SvEna bool
	Resv  bool   // a USVCB's reservation; false for an MSVCB
	SvID  string // MsvID or UsvID
	// DataSet is the data set reference in MMS notation, "LD/LN$name".
	DataSet    string
	ConfRev    uint32
	SmpRate    uint32
	OptFlds    model.SVOpts
	SmpMod     model.SmpMod
	DstAddress PhyComAddr
	NoASDU     uint32
}

// PhyComAddr is the destination of a GOOSE or sampled-value stream.
type PhyComAddr struct {
	Addr     [6]byte
	Priority uint8
	VID      uint16
	AppID    uint16
}

// GetSVCB reads the sampled-value control block at ref ("LD/LLN0.msvcb01")
// in one request. Whether it is an MSVCB or a USVCB is found as
// libiec61850 does: the block is looked up under FC MS, then US. A
// component the server does not serve is left at its zero value.
func (c *Client) GetSVCB(ctx context.Context, ref model.ObjectReference) (*SVCB, error) {
	cb := &SVCB{Ref: ref}
	domain, item := ref.ToMMS(model.MS)
	vals, err := c.mc.Read(ctx, domain, item+"$SvEna")
	if err != nil {
		return nil, err
	}
	if _, isErr := vals[0].AccessError(); isErr {
		cb.Unicast = true
		domain, item = ref.ToMMS(model.US)
	}
	names := []string{"SvEna", "MsvID", "DatSet", "ConfRev", "SmpRate", "OptFlds", "SmpMod", "DstAddress", "noASDU"}
	if cb.Unicast {
		names = []string{"SvEna", "Resv", "UsvID", "DatSet", "ConfRev", "SmpRate", "OptFlds", "SmpMod", "DstAddress", "noASDU"}
	}
	items := make([]string, len(names))
	for i, n := range names {
		items[i] = item + "$" + n
	}
	vals, err = c.mc.Read(ctx, domain, items...)
	if err != nil {
		return nil, err
	}
	if len(vals) != len(names) {
		return nil, fmt.Errorf("client: %d results for %d components of %s", len(vals), len(names), ref)
	}
	if code, isErr := vals[0].AccessError(); isErr {
		return nil, code // the block itself is not there
	}
	for i, v := range vals {
		if _, isErr := v.AccessError(); isErr {
			continue
		}
		switch names[i] {
		case "SvEna":
			cb.SvEna = v.Bool()
		case "Resv":
			cb.Resv = v.Bool()
		case "MsvID", "UsvID":
			cb.SvID = v.Text()
		case "DatSet":
			cb.DataSet = v.Text()
		case "ConfRev":
			cb.ConfRev = uint32(v.Uint64())
		case "SmpRate":
			cb.SmpRate = uint32(v.Uint64())
		case "OptFlds":
			bit := func(i int) bool { return i < v.BitLen() && v.Bit(i) }
			cb.OptFlds = model.SVOpts{
				RefreshTime: bit(0), SampleSynchronized: bit(1), SampleRate: bit(2),
				DataSet: bit(3), Security: bit(4), Timestamp: bit(5), SynchSourceID: bit(6),
			}
		case "SmpMod":
			cb.SmpMod = model.SmpMod(v.Int64())
		case "DstAddress":
			cb.DstAddress = phyComAddrOf(v)
		case "noASDU":
			cb.NoASDU = uint32(v.Uint64())
		}
	}
	return cb, nil
}

// phyComAddrOf decodes a PHYCOMADDR structure: Addr, PRIORITY, VID, APPID.
func phyComAddrOf(v *mms.Value) PhyComAddr {
	var a PhyComAddr
	f := v.Children()
	if len(f) < 4 {
		return a
	}
	copy(a.Addr[:], f[0].Bytes())
	a.Priority = uint8(f[1].Uint64())
	a.VID = uint16(f[2].Uint64())
	a.AppID = uint16(f[3].Uint64())
	return a
}
