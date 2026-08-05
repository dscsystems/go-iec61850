package mms

import "testing"

func TestStateValuesMatchLibiec61850(t *testing.T) {
	for _, tc := range []struct {
		s    State
		n    uint8
		name string
	}{
		{StateClosed, 0, "closed"},
		{StateConnecting, 1, "connecting"},
		{StateConnected, 2, "connected"},
		{StateClosing, 3, "closing"},
	} {
		if uint8(tc.s) != tc.n {
			t.Errorf("%s = %d, want %d", tc.name, uint8(tc.s), tc.n)
		}
		if tc.s.String() != tc.name {
			t.Errorf("String() = %q, want %q", tc.s.String(), tc.name)
		}
	}
	if got := State(9).String(); got != "State(9)" {
		t.Errorf("unknown state String() = %q", got)
	}
}

// A Conn that was never dialled reports closed rather than a zero value
// that reads as connected.
func TestZeroConnIsClosed(t *testing.T) {
	var c Conn
	if got := c.State(); got != StateClosed {
		t.Errorf("zero Conn state = %s, want closed", got)
	}
	if err := c.Err(); err != nil {
		t.Errorf("zero Conn Err = %v, want nil (no cause recorded)", err)
	}
	// It has no reader to wait for, so waiting must not block forever.
	select {
	case <-c.Done():
	default:
		t.Error("zero Conn Done() blocks; it must be already closed")
	}
}
