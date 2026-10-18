package cotp

import (
	"bytes"
	"io"
	"testing"

	"github.com/dscsystems/go-iec61850/internal/osi/tpkt"
)

// fuzzRW reads the fuzz input and discards what is written.
type fuzzRW struct{ io.Reader }

func (fuzzRW) Write(p []byte) (int, error) { return len(p), nil }
func (fuzzRW) Close() error                { return nil }

// frames splits data into TPKT frames, so the fuzzer explores TPDUs rather
// than TPKT headers.
func frames(tpdus ...[]byte) []byte {
	var b bytes.Buffer
	for _, t := range tpdus {
		tpkt.WritePacket(&b, t)
	}
	return b.Bytes()
}

// The responder: a CR, then data TPDUs. Neither may panic.
func FuzzAccept(f *testing.F) {
	cr := []byte{0x11, 0xe0, 0, 0, 0, 1, 0, 0xc0, 1, 0x0a, 0xc1, 2, 0, 1, 0xc2, 2, 0, 1}
	f.Add(cr, []byte{0x02, 0xf0, 0x80, 1, 2, 3})
	f.Add(cr, []byte{0x02, 0xf0, 0x00, 1})
	f.Fuzz(func(t *testing.T, crTPDU, dt []byte) {
		c, err := Accept(fuzzRW{bytes.NewReader(frames(crTPDU, dt, dt))})
		if err != nil {
			return
		}
		c.SetMaxTSDU(1 << 16)
		for i := 0; i < 4; i++ {
			if _, err := c.Receive(); err != nil {
				return
			}
		}
	})
}

// The initiator: the CC it receives.
func FuzzConnect(f *testing.F) {
	f.Add([]byte{0x0d, 0xd0, 0, 1, 0, 2, 0, 0xc0, 1, 0x0a, 0xc2, 2, 0, 1})
	f.Fuzz(func(t *testing.T, cc []byte) {
		Connect(fuzzRW{bytes.NewReader(frames(cc))}, Options{})
	})
}
