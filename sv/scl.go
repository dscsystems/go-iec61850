package sv

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/model"
)

// NewLEPublisherFromModel returns a 9-2LE publisher for one sampled-value
// control block of a model, taking the multicast address, APPID, VLAN,
// svID, configuration revision, sample rate and ASDUs per frame from its
// configuration. It is the SCL equivalent of NewLEPublisher.
//
// The optional ASDU fields follow the block's SmvOpts: sampleRate emits
// smpRate [6], and with it smpMod [8], since a rate is only readable
// together with its unit; refreshTime emits refrTm [4], dataSet the
// datSet [1] reference, and synchSourceId gmIdentity [9], whose value the
// caller supplies with SetGmIdentity. smpSynch [5] is always present, as
// Edition 2 requires, so sampleSynchronized needs nothing further.
//
// ld and ln are the logical device and node the block belongs to; datSet
// goes on the wire as a full reference, "LD/LLN0$PhsMeas1". nominalHz is
// the power system frequency, needed to turn a per-second rate into
// samples per cycle; zero means 50.
//
// A unicast block (a USVCB, IEC 61850-9-2 unicast SV) is published to its
// DstAddress like a multicast one; the frame format is the same. Its
// destination must then be an individual MAC address, not a group one,
// unless the block is R-SV, whose frames iface — an rsession.Session
// opened with the block's DstIP as Remote — carries over UDP instead.
// Publish it while the server reports it enabled (server.OnSVControl).
//
// A block this publisher cannot honour is refused rather than published
// differently from its configuration: SmvOpts security (the
// frames would go out unsigned), the SecPerSmp mode, and a per-second rate
// that is not a whole number of samples per cycle. SmvOpts timestamp is
// not implemented and is ignored.
func NewLEPublisherFromModel(iface ethernet.Interface, ld *model.LogicalDevice, ln *model.LogicalNode,
	sc *model.SVControl, srcMAC [6]byte, nominalHz int) (*LEPublisher, error) {
	if sc == nil {
		return nil, fmt.Errorf("sv: nil sampled-value control block")
	}
	if ld == nil || ln == nil {
		return nil, fmt.Errorf("sv: control block %s: the logical device and node are required "+
			"to build its reference", sc.Name)
	}
	if !sc.Multicast && sc.Protocol != "R-SV" && sc.DstMAC[0]&1 != 0 {
		return nil, fmt.Errorf("sv: control block %s is unicast, but its destination %x is a group address",
			sc.Name, sc.DstMAC[:])
	}
	if sc.Opts.Security {
		return nil, fmt.Errorf("sv: control block %s asks for SmvOpts security, "+
			"and IEC 62351-6 signing is not implemented", sc.Name)
	}
	if nominalHz <= 0 {
		nominalHz = 50
	}
	cfg := LEConfig{
		AppID:     sc.AppID,
		SvID:      sc.SvID,
		ConfRev:   sc.ConfRev,
		DstMAC:    sc.DstMAC,
		SrcMAC:    srcMAC,
		NominalHz: nominalHz,
		NoASDU:    int(sc.NoASDU),
		Opts: SVOpts{
			SampleRate:    sc.Opts.SampleRate,
			SmpMod:        sc.Opts.SampleRate,
			RefreshTime:   sc.Opts.RefreshTime,
			DataSet:       sc.Opts.DataSet,
			SynchSourceID: sc.Opts.SynchSourceID,
		},
	}
	if sc.DataSet != "" {
		cfg.DatSet = ld.Name + "/" + ln.Name + "$" + sc.DataSet
	}
	switch sc.SmpMod {
	case model.SmpPerPeriod:
		cfg.SmpMod = SmpPerPeriod
		cfg.SamplesPerCycle = int(sc.SmpRate)
	case model.SmpPerSec:
		cfg.SmpMod = SmpPerSec
		if sc.SmpRate == 0 || int(sc.SmpRate)%nominalHz != 0 {
			return nil, fmt.Errorf("sv: control block %s: %d samples per second is not a whole "+
				"number of samples per %d Hz cycle", sc.Name, sc.SmpRate, nominalHz)
		}
		cfg.SamplesPerCycle = int(sc.SmpRate) / nominalHz
	default:
		return nil, fmt.Errorf("sv: control block %s: sample mode %v is not supported", sc.Name, sc.SmpMod)
	}
	if sc.VLANID != 0 || sc.VLANPri != 0 {
		cfg.VLAN = &ethernet.VLANTag{VID: sc.VLANID, Priority: sc.VLANPri}
	}
	return NewLEPublisher(iface, cfg)
}
