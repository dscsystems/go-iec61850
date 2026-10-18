package session

import (
	"errors"
	"testing"
)

type oneShot struct{ data []byte }

func (o *oneShot) Send([]byte) error { return nil }
func (o *oneShot) Receive() ([]byte, error) {
	if o.data == nil {
		return nil, errors.New("eof")
	}
	d := o.data
	o.data = nil
	return d, nil
}

// SPDUs from the peer: connect-like SPDUs, data and the rest of Receive's
// cases must give a result or an error, never a panic.
func FuzzSPDU(f *testing.F) {
	f.Add(buildConnect(siConnect, []byte{0, 1}, []byte{0, 1}, []byte{0x31, 0}))
	f.Add([]byte{0x01, 0x00, 0x01, 0x00, 0x61, 0x00})
	f.Add([]byte{0x19, 0x00})
	f.Fuzz(func(t *testing.T, spdu []byte) {
		parseConnectLike(spdu)
		stripDataPrefix(spdu)
		Receive(&oneShot{data: append([]byte{}, spdu...)})
		ReceiveData(&oneShot{data: append([]byte{}, spdu...)})
	})
}
