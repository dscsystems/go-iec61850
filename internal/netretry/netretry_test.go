package netretry

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestTemporary(t *testing.T) {
	emfile := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"closed", net.ErrClosed, false},
		{"wrapped closed", fmt.Errorf("x: %w", net.ErrClosed), false},
		{"EMFILE", emfile, true},
		{"timeout", os.ErrDeadlineExceeded, true},
		{"plain", errors.New("boom"), false},
	}
	for _, c := range cases {
		if got := Temporary(c.err); got != c.want {
			t.Errorf("%s: Temporary = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBackoff(t *testing.T) {
	var b Backoff
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000}
	for i, w := range want {
		if got := b.Next(); got != w*time.Millisecond {
			t.Fatalf("step %d: %v, want %v", i, got, w*time.Millisecond)
		}
	}
	b.Reset()
	if got := b.Next(); got != 5*time.Millisecond {
		t.Fatalf("after Reset: %v", got)
	}
}
