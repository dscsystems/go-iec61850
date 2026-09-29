package sv

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/mms"
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
	// NoASDU is the number of consecutive samples sent in one frame: 1 for
	// the 9-2LE protection stream, 8 for the metering one. Zero means 1.
	NoASDU int
	// SmpMod is the sample mode to declare in smpMod [8] when Opts.SmpMod
	// is set, and the unit smpRate [6] is expressed in when Opts.SampleRate
	// is: samples per period (the default) or per second. Leaving smpMod
	// out, the default, is what an Edition 1 receiver expects, and it
	// reads smpRate as samples per period. SecPerSmp cannot express a rate
	// of one sample per second or faster and is refused.
	SmpMod SmpMod
	// DatSet is the dataset name to declare when Opts.DataSet is set.
	DatSet string
	// TimeQuality is the quality of the publisher's clock, stamped on
	// refrTm when Opts.RefreshTime is set. Nil stamps
	// mms.DefaultTimeQuality. A merging unit whose time source is lost has
	// to say so here: SmpSynch tells a receiver the samples are not
	// synchronised, and this tells it the reference time is not either.
	TimeQuality *mms.TimeQuality
	// GmIdentity is the initial grandmaster clock identity declared in
	// gmIdentity [9] when Opts.SynchSourceID is set. SetGmIdentity changes
	// it while the publisher runs.
	GmIdentity [8]byte
	// Opts selects the optional ASDU fields to include. The zero value
	// includes none beyond the mandatory ones, which is the 9-2LE
	// profile; set it to publish the refresh time, sample rate, dataset
	// name or a reference timestamp alongside the sample.
	Opts SVOpts
}

// SVOpts selects the optional fields of a sampled-value ASDU
// (IEC 61850-9-2 and the SmvOpts element of IEC 61850-6).
type SVOpts struct {
	// SampleRate includes smpRate [6].
	SampleRate bool
	// RefreshTime includes the reference timestamp refrTm [4].
	RefreshTime bool
	// DataSet includes the dataset name datSet [1].
	DataSet bool
	// SmpMod declares the sample mode in smpMod [8].
	SmpMod bool
	// SynchSourceID includes the grandmaster identity gmIdentity [9]
	// (IEC 61850-9-2 Amendment 1).
	SynchSourceID bool
}

// DefaultMAC returns the 9-2LE multicast destination MAC for the given
// low-order APPID-derived selector (01:0C:CD:04:xx:xx).
func DefaultMAC(sel uint16) [6]byte {
	return [6]byte{0x01, 0x0c, 0xcd, 0x04, byte(sel >> 8), byte(sel)}
}

// LEPublisher emits NoASDU samples per frame at the configured sample
// rate.
type LEPublisher struct {
	iface ethernet.Interface
	cfg   LEConfig
	rate  int // samples per second
	gmID  atomic.Pointer[[8]byte]
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
	if cfg.NoASDU <= 0 {
		cfg.NoASDU = 1
	}
	if cfg.SvID == "" {
		return nil, errors.New("sv: LEConfig.SvID is required")
	}
	if cfg.SmpMod != SmpPerPeriod && cfg.SmpMod != SmpPerSec {
		return nil, fmt.Errorf("sv: sample mode %v cannot express a rate of %d samples per second",
			cfg.SmpMod, cfg.SamplesPerCycle*cfg.NominalHz)
	}
	p := &LEPublisher{iface: iface, cfg: cfg, rate: cfg.SamplesPerCycle * cfg.NominalHz}
	if p.smpRate() > 0xffff {
		return nil, fmt.Errorf("sv: smpRate %d does not fit its 16 bits", p.smpRate())
	}
	if cfg.NoASDU > p.rate {
		return nil, fmt.Errorf("sv: %d ASDUs per frame at %d samples per second", cfg.NoASDU, p.rate)
	}
	p.SetGmIdentity(cfg.GmIdentity)
	return p, nil
}

// SampleRate returns the number of samples emitted per second.
func (p *LEPublisher) SampleRate() int { return p.rate }

// SetGmIdentity changes the grandmaster identity declared in gmIdentity
// [9], for instance when the PTP best master clock algorithm selects a
// new grandmaster. It takes effect with the next frame and is safe to
// call while Run is running.
func (p *LEPublisher) SetGmIdentity(id [8]byte) { p.gmID.Store(&id) }

// smpRate is the value of smpRate [6] in the unit the sample mode names.
func (p *LEPublisher) smpRate() int {
	if p.cfg.SmpMod == SmpPerSec {
		return p.rate
	}
	return p.cfg.SamplesPerCycle
}

// Run drives the sample clock until ctx is cancelled, calling fill to
// populate each sample. smpCnt wraps at SamplesPerCycle*NominalHz (once
// per second per the 9-2LE convention). fill must not block. With NoASDU
// above 1, each frame carries the last NoASDU samples, the oldest first.
func (p *LEPublisher) Run(ctx context.Context, fill func(smpCnt uint16, out *LESample)) error {
	interval := time.Second / time.Duration(p.rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var smpCnt uint16
	samples := make([]LESample, p.cfg.NoASDU)
	n := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s := &samples[n]
			*s = LESample{SmpCnt: smpCnt, SmpSynch: SmpSynchGlobal}
			fill(smpCnt, s)
			if n++; n == len(samples) {
				if err := p.emit(samples); err != nil {
					return err
				}
				n = 0
			}
			smpCnt++
			if int(smpCnt) >= p.rate {
				smpCnt = 0
			}
		}
	}
}

func (p *LEPublisher) emit(samples []LESample) error {
	pdu := &PDU{AppID: p.cfg.AppID, ASDUs: make([]*ASDU, len(samples))}
	for i := range samples {
		pdu.ASDUs[i] = p.asdu(&samples[i])
	}
	return p.iface.WriteFrame(&ethernet.Frame{
		Dst:       p.cfg.DstMAC,
		Src:       p.cfg.SrcMAC,
		EtherType: ethernet.EtherTypeSV,
		VLAN:      p.cfg.VLAN,
		Payload:   pdu.Marshal(),
	})
}

// asdu builds the ASDU for one sample, including the optional fields the
// configuration asks for.
func (p *LEPublisher) asdu(s *LESample) *ASDU {
	a := &ASDU{
		SvID:     p.cfg.SvID,
		SmpCnt:   s.SmpCnt,
		ConfRev:  p.cfg.ConfRev,
		SmpSynch: s.SmpSynch,
		Sample:   EncodeLESample(s),
	}
	if p.cfg.Opts.SampleRate {
		a.SmpRate = uint16(p.smpRate())
	}
	if p.cfg.Opts.RefreshTime {
		a.RefrTm = time.Now()
		a.RefrTmQuality = p.cfg.TimeQuality
	}
	if p.cfg.Opts.DataSet && p.cfg.DatSet != "" {
		a.DatSet = p.cfg.DatSet
	}
	if p.cfg.Opts.SmpMod {
		a.SmpMod = p.cfg.SmpMod
		a.HasSmpMod = true
	}
	if p.cfg.Opts.SynchSourceID {
		if id := p.gmID.Load(); id != nil {
			a.GmIdentity = *id
		}
		a.HasGmIdentity = true
	}
	return a
}
