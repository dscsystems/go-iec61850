package client_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/sv"
)

// TestSVCBInteropWithLibiecServer reads libiec61850's 9-2LE example MSVCB
// with GetSVCB, enables it with EnableSVCB and receives the stream it
// starts. The example listens on port 102 and publishes on a raw socket,
// so the test runs where both are allowed: interop/run.sh runs it in an
// unprivileged network namespace (unshare -rn), publishing on its lo.
// Set IEC61850_C_SV_SERVER to the sv_9_2LE_example binary.
func TestSVCBInteropWithLibiecServer(t *testing.T) {
	bin := os.Getenv("IEC61850_C_SV_SERVER")
	if bin == "" {
		t.Skip("set IEC61850_C_SV_SERVER")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "lo")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	var c *client.Client
	var err error
	for i := 0; i < 50; i++ {
		if c, err = client.Dial(ctx, "127.0.0.1:102", client.WithTimeout(2*time.Second)); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	const ref = model.ObjectReference("TEMPLATEMUnn/LLN0.MSVCB01")
	cb, err := c.GetSVCB(ctx, ref)
	if err != nil {
		t.Fatalf("GetSVCB: %v", err)
	}
	t.Logf("%+v", cb)
	// The SCL omits SampledValueControl@multicast, whose IEC 61850-6
	// default is true, but libiec61850's model generator defaults it to
	// false: the example serves MSVCB01 as a USVCB (FC US), and GetSVCB
	// reports it as the server serves it.
	if !cb.Unicast {
		t.Error("MSVCB01 read as an MSVCB; libiec61850 serves it under FC US")
	}
	want := client.PhyComAddr{Addr: [6]byte{1, 0x0c, 0xcd, 4, 0, 1}, Priority: 4, VID: 1, AppID: 0x1001}
	if cb.SvEna || cb.Resv || cb.SvID != "xxxxMUnn01" || cb.DataSet != "TEMPLATEMUnn/LLN0$PhsMeas1" ||
		cb.ConfRev != 1 || cb.SmpRate != 80 || cb.SmpMod != model.SmpPerPeriod || cb.DstAddress != want ||
		!cb.OptFlds.SampleSynchronized || cb.OptFlds.RefreshTime {
		t.Errorf("MSVCB01 = %+v", cb)
	}

	eth, err := ethernet.Open("lo", ethernet.EtherTypeSV)
	if err != nil {
		t.Fatalf("raw socket on lo: %v", err)
	}
	defer eth.Close()
	got := make(chan uint16, 1)
	stop, err := sv.NewSubscriber(eth).SubscribeLE(sv.Filter{SvID: "xxxxMUnn01"}, func(s *sv.LESample) {
		select {
		case got <- s.SmpCnt:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	if err := c.ReserveUSVCB(ctx, ref, true); err != nil {
		t.Fatalf("ReserveUSVCB: %v", err)
	}
	if err := c.EnableSVCB(ctx, ref, cb.Unicast, true); err != nil {
		t.Fatalf("EnableSVCB: %v", err)
	}
	if cb, err := c.GetSVCB(ctx, ref); err != nil || !cb.SvEna || !cb.Resv {
		t.Errorf("SvEna after enabling: %+v, %v", cb, err)
	}
	select {
	case n := <-got:
		t.Logf("received smpCnt %d", n)
	case <-time.After(5 * time.Second):
		t.Error("no sample from the enabled MSVCB")
	}
	if err := c.EnableSVCB(ctx, ref, cb.Unicast, false); err != nil {
		t.Errorf("disable: %v", err)
	}
}
