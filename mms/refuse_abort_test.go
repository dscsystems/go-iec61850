package mms

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// A Triangle MicroWorks SCADA Data Gateway (5.0.2) answers an association
// it does not authenticate with a session REFUSE whose CPR carries an
// A-ABORT (abort-source provider, abort-diagnostic authentication-failure)
// instead of an AARE. Captured from the device.
const (
	tmwCC     = "0300001611d00001000400c0010ac1020001c2020001"
	tmwRefuse = "0300003602f0800c2d322b023028a5123007800100810251013007800100810251018a0100610f300d020101a0086406800101810105"
)

func TestRefusalCarryingAbort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		for _, reply := range []string{tmwCC, tmwRefuse} {
			if readTPKT(c) != nil {
				return
			}
			b, _ := hex.DecodeString(reply)
			c.Write(b)
		}
		io.Copy(io.Discard, c)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = Dial(ctx, ln.Addr().String(), Options{Password: "test"})
	var ae *AbortedError
	if !errors.As(err, &ae) || ae.Diagnostic != 5 || ae.Source != 1 {
		t.Fatalf("got %v, want an AbortedError with diagnostic 5", err)
	}
	if !errors.Is(err, ErrAuthenticationFailed) {
		t.Errorf("%v does not match ErrAuthenticationFailed", err)
	}
	if want := "mms: association aborted by the server: authentication failure"; err.Error() != want {
		t.Errorf("message %q, want %q", err.Error(), want)
	}
}

// readTPKT reads one RFC 1006 packet.
func readTPKT(c net.Conn) error {
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, int(h[2])<<8|int(h[3])-4))
	return err
}
