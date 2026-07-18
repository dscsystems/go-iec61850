package sv

import (
	"context"
	"errors"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
)

// LEConfig configures a 9-2LE publisher.
type LEConfig struct {
	AppID   uint16
	SvID    string
	ConfRev uint32
	DstMAC  [6]byte
	SrcMAC  [6]byte
	VLAN    *ethernet.VLANTag
	// SamplesPerCycle is the number of samples per power cycle (80 for
	// protection, 256 for metering in the 9-2LE profile).
	SamplesPerCycle int
	// NominalHz is the power system frequency (50 or 60).
	NominalHz int
}

// DefaultMAC returns the 9-2LE multicast destination MAC for the given
// low-order APPID-derived selector (01:0C:CD:04:xx:xx).
func DefaultMAC(sel uint16) [6]byte {
	return [6]byte{0x01, 0x0c, 0xcd, 0x04, byte(sel >> 8), byte(sel)}
}

// LEPublisher emits one ASDU per frame (noASDU = 1) at the configured
// sample rate.
type LEPublisher struct {
	iface ethernet.Interface
	cfg   LEConfig
	rate  int // samples per second
}

// NewLEPublisher returns a 9-2LE publisher over iface.
func NewLEPublisher(iface ethernet.Interface, cfg LEConfig) (*LEPublisher, error) {
	if iface == nil {
		return nil, errors.New("sv: nil interface")
	}
	if cfg.SamplesPerCycle <= 0 {
		cfg.SamplesPerCycle = 80
	}
	if cfg.NominalHz <= 0 {
		cfg.NominalHz = 50
	}
	if cfg.SvID == "" {
		return nil, errors.New("sv: LEConfig.SvID is required")
	}
	return &LEPublisher{iface: iface, cfg: cfg, rate: cfg.SamplesPerCycle * cfg.NominalHz}, nil
}

// SampleRate returns the number of samples emitted per second.
func (p *LEPublisher) SampleRate() int { return p.rate }

// Run drives the sample clock until ctx is cancelled, calling fill to
// populate each sample. smpCnt wraps at SamplesPerCycle*NominalHz (once
// per second per the 9-2LE convention). fill must not block.
func (p *LEPublisher) Run(ctx context.Context, fill func(smpCnt uint16, out *LESample)) error {
	interval := time.Second / time.Duration(p.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var smpCnt uint16
	var sample LESample
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			sample = LESample{SmpCnt: smpCnt, SmpSynch: SmpSynchGlobal}
			fill(smpCnt, &sample)
			if err := p.emit(&sample); err != nil {
				return err
			}
			smpCnt++
			if int(smpCnt) >= p.rate {
				smpCnt = 0
			}
		}
	}
}

func (p *LEPublisher) emit(s *LESample) error {
	pdu := &PDU{AppID: p.cfg.AppID, ASDUs: []*ASDU{{
		SvID:     p.cfg.SvID,
		SmpCnt:   s.SmpCnt,
		ConfRev:  p.cfg.ConfRev,
		SmpSynch: s.SmpSynch,
		Sample:   EncodeLESample(s),
	}}}
	return p.iface.WriteFrame(&ethernet.Frame{
		Dst:       p.cfg.DstMAC,
		Src:       p.cfg.SrcMAC,
		EtherType: ethernet.EtherTypeSV,
		VLAN:      p.cfg.VLAN,
		Payload:   pdu.Marshal(),
	})
}
