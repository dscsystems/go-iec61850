package client

import (
	"context"

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
