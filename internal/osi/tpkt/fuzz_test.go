package tpkt

import (
	"bytes"
	"testing"
)

// ReadPacket faces the network directly: any input must give a packet or
// an error, never a panic, and a packet read must re-frame to its input.
func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{3, 0, 0, 7, 2, 0xf0, 0x80})
	f.Add([]byte{3, 0, 0, 3})
	f.Add([]byte{3, 0, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ReadPacket(bytes.NewReader(data))
		if err != nil {
			return
		}
		var b bytes.Buffer
		if err := WritePacket(&b, p); err != nil {
			t.Fatalf("re-frame %d bytes: %v", len(p), err)
		}
		if !bytes.Equal(b.Bytes()[4:], p) {
			t.Fatal("re-framed payload differs")
		}
	})
}
