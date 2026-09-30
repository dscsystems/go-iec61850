package sv

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/rsession"
)

// A unicast block (a USVCB) is published to its individual DstAddress, in
// the same frame format as a multicast one.
func TestUnicastPublisherFromModel(t *testing.T) {
	ld := &model.LogicalDevice{Name: "MU01LD0"}
	ln := &model.LogicalNode{Name: "LLN0"}
	sc := &model.SVControl{
		Name: "USVCB01", SvID: "MU01U", ConfRev: 1, SmpRate: 80, SmpMod: model.SmpPerPeriod,
		DstMAC: [6]byte{0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e}, AppID: 0x4002,
	}
	capture := &frameCapture{}
	p, err := NewLEPublisherFromModel(capture, ld, ln, sc, [6]byte{0x02, 0, 0, 0, 0, 1}, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.emit([]LESample{{SmpCnt: 7}}); err != nil {
		t.Fatal(err)
	}
	if len(capture.frames) != 1 || capture.frames[0].Dst != sc.DstMAC {
		t.Fatalf("frames %+v, want one to %x", capture.frames, sc.DstMAC)
	}
	pdu, err := Parse(capture.frames[0].Payload)
	if err != nil || pdu.AppID != 0x4002 || len(pdu.ASDUs) != 1 || pdu.ASDUs[0].SvID != "MU01U" || pdu.ASDUs[0].SmpCnt != 7 {
		t.Fatalf("frame = %+v, %v", pdu, err)
	}
}

// A unicast R-SV block goes to its DstIP through an rsession.Session: the
// layer-2 address plays no part, so a group MAC in the document is no
// reason to refuse it.
func TestUnicastRSVPublisherFromModel(t *testing.T) {
	recv, err := rsession.Open(rsession.Config{Listen: "127.0.0.1:0", AllowUnsecured: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recv.Close()
	send, err := rsession.Open(rsession.Config{Remote: recv.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer send.Close()

	sc := &model.SVControl{
		Name: "USVCB02", SvID: "MU01R", ConfRev: 1, SmpRate: 80, SmpMod: model.SmpPerPeriod,
		Protocol: "R-SV", DstMAC: [6]byte{1, 0x0c, 0xcd, 4, 0, 2}, AppID: 0x4003,
	}
	p, err := NewLEPublisherFromModel(send, &model.LogicalDevice{Name: "MU01LD0"},
		&model.LogicalNode{Name: "LLN0"}, sc, [6]byte{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go p.Run(ctx, func(uint16, *LESample) {})
	go func() { <-ctx.Done(); recv.Close() }() // ends ReadFrame if nothing comes
	f, err := recv.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := Parse(f.Payload)
	if err != nil || pdu.AppID != 0x4003 || pdu.ASDUs[0].SvID != "MU01R" {
		t.Fatalf("received %+v, %v", pdu, err)
	}
}
