package tpkt

import (
	"errors"
	"testing"
)

// The length field is 16 bits: a frame that does not fit is refused
// rather than written with a wrapped length.
func TestWritePacketLimit(t *testing.T) {
	var w countingWriter
	if err := WritePacket(&w, make([]byte, MaxPacket-headerLen+1)); err == nil {
		t.Error("oversized packet written")
	}
	if err := WritePacket(&w, make([]byte, MaxPacket-headerLen)); err != nil {
		t.Errorf("largest packet: %v", err)
	}
	if w.writes != 1 {
		t.Errorf("%d writes for one frame, want 1", w.writes)
	}
}

type countingWriter struct{ writes int }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	if len(p) > 0xffff {
		return 0, errors.New("too long")
	}
	return len(p), nil
}
