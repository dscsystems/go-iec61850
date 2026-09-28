package goose

import (
	"fmt"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/model"
)

// RetransFromSCL builds the retransmission schedule a GOOSE control block's
// MinTime and MaxTime ask for (IEC 61850-8-1, clause 11).
//
// The receiver backs off from MinTime to MaxTime over the life of one
// state: the first transmission is followed by a retransmission after
// MinTime, and the interval then doubles until it reaches MaxTime, which
// it holds. A device that changes state often is therefore heard from
// quickly after each change and then rarely, and a device whose state
// changes rarely is not flooded. This is what makes 100 ms GOOSE
// configurable: MaxTime of 100 ms gives a publisher that never waits longer
// than 100 ms to be heard, which is what a 100 ms protection function needs.
//
// A block that configures neither gets DefaultRetrans. MinTime or MaxTime
// that is not positive is ignored, since a zero interval would mean
// retransmitting as fast as the link allows.
func RetransFromSCL(minTime, maxTime uint32) []time.Duration {
	minMS, maxMS := int(minTime), int(maxTime)
	if minMS <= 0 && maxMS <= 0 {
		return DefaultRetrans
	}
	if minMS <= 0 {
		// Without a minimum, the doubling starts at a value that reaches
		// the maximum in a sensible number of steps.
		minMS = maxMS / 64
		if minMS <= 0 {
			minMS = 1
		}
	}
	if maxMS < minMS {
		maxMS = minMS
	}
	var out []time.Duration
	for d := minMS; d < maxMS; d *= 2 {
		out = append(out, time.Duration(d)*time.Millisecond)
		if len(out) >= maxRetransSteps {
			break
		}
	}
	return append(out, time.Duration(maxMS)*time.Millisecond)
}

// maxRetransSteps bounds the schedule so a MaxTime far above MinTime
// cannot produce an unbounded number of entries.
const maxRetransSteps = 16

// NewPublisherFromModel returns a publisher for one GOOSE control block of
// a model, taking the multicast address, APPID, VLAN, identity,
// configuration revision and retransmission timing from its configuration.
// It is the SCL equivalent of NewPublisher, and it is what gives a server
// configured from a CID the 100 ms GOOSE its MaxTime asks for.
func NewPublisherFromModel(iface ethernet.Interface, gc *model.GSEControl, srcMAC [6]byte) (*Publisher, error) {
	if gc == nil {
		return nil, fmt.Errorf("goose: nil GOOSE control block")
	}
	ref := gc.Name
	if ref == "" {
		ref = gc.GoID
	}
	cfg := PublisherConfig{
		DstMAC:  gc.DstMAC,
		AppID:   gc.AppID,
		GoCbRef: ref,
		DatSet:  gc.DataSet,
		GoID:    gc.GoID,
		ConfRev: gc.ConfRev,
		SrcMAC:  srcMAC,
		Retrans: RetransFromSCL(gc.MinTime, gc.MaxTime),
	}
	if gc.VLANID != 0 || gc.VLANPri != 0 {
		cfg.VLAN = &ethernet.VLANTag{VID: gc.VLANID, Priority: gc.VLANPri}
	}
	return NewPublisher(iface, cfg)
}
