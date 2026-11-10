package cotp

import (
	"bytes"
	"net"
	"testing"

	"github.com/dscsystems/go-iec61850/internal/osi/tpkt"
)

// The CC answers with the CR's calling and called selectors in their own
// roles, not swapped.
func TestAcceptEchoesSelectorsInTheirRoles(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go Accept(b)
	cr := []byte{0, tpduCR, 0, 0, 0, 1, 0,
		paramTPDUSize, 1, 10,
		paramSrcTSAP, 1, 0xAA,
		paramDstTSAP, 1, 0xBB}
	cr[0] = byte(len(cr) - 1)
	if err := tpkt.WritePacket(a, cr); err != nil {
		t.Fatal(err)
	}
	cc, err := tpkt.ReadPacket(a)
	if err != nil {
		t.Fatal(err)
	}
	_, typ, body, err := parseHeader(cc)
	if err != nil || typ != tpduCC {
		t.Fatalf("type %#x, err %v", typ, err)
	}
	got := map[byte][]byte{}
	for p := body[5:]; len(p) >= 2; p = p[2+int(p[1]):] {
		got[p[0]] = p[2 : 2+int(p[1])]
	}
	if !bytes.Equal(got[paramSrcTSAP], []byte{0xAA}) || !bytes.Equal(got[paramDstTSAP], []byte{0xBB}) {
		t.Errorf("CC calling %x called %x, want aa and bb", got[paramSrcTSAP], got[paramDstTSAP])
	}
}
