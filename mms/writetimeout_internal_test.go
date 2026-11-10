package mms

import (
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/internal/osi/cotp"
)

// A write to a client that does not read times out, ends the association and
// does not hold the caller indefinitely.
func TestServerWriteTimeout(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	acc := make(chan error, 1)
	go func() { _, err := cotp.Accept(b); acc <- err }()
	ct, err := cotp.Connect(a, cotp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-acc; err != nil {
		t.Fatal(err)
	}
	sc := &ServerConn{fr: &framing{cotp: ct}, raw: a, writeTimeout: 100 * time.Millisecond}
	start := time.Now()
	if err := sc.send(make([]byte, 64)); err == nil {
		t.Fatal("write to a client that never reads succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("write took %v to give up", d)
	}
	if _, err := a.Write([]byte{0}); err == nil {
		t.Error("transport still open after the timed-out write")
	}
}
