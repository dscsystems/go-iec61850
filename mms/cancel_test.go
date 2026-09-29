package mms

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/internal/osi/acse"
	"github.com/dscsystems/go-iec61850/internal/osi/presentation"
)

// slowHandler defers Status until its context ends, so a Cancel can catch
// it running.
type slowHandler struct{ started chan struct{} }

func (h slowHandler) Handle(req *Request) (*asn1.Element, error) {
	if req.Service == svcStatus {
		return req.Defer(func(ctx context.Context) (*asn1.Element, error) {
			close(h.started)
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}
	return nil, &ServiceError{Rejected: true, Class: 1, Code: 1}
}

func serve(t *testing.T, h Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, err := AcceptConn(raw)
				if err != nil {
					raw.Close()
					return
				}
				defer sc.Close()
				sc.Serve(h)
			}()
		}
	}()
	return ln.Addr().String()
}

func TestCancel(t *testing.T) {
	h := slowHandler{started: make(chan struct{})}
	addr := serve(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	o, err := c.Start(asn1.BoolElem(asn1.ContextPrimitive(svcStatus), false))
	if err != nil {
		t.Fatal(err)
	}
	<-h.started
	if err := o.Cancel(ctx); err != nil {
		t.Fatalf("Cancel of a running request: %v", err)
	}
	_, err = o.Wait(ctx)
	var se *ServiceError
	if !errors.As(err, &se) || se.Class != 5 || se.Code != 3 {
		t.Errorf("cancelled request answered %v, want service-preempt/cancel", err)
	}

	// Nothing to cancel: the server says it does not know the request.
	if err := c.Cancel(ctx, 999); !errors.As(err, &se) || se.Class != 10 || se.Code != 1 {
		t.Errorf("Cancel of an unknown request: %v, want cancel/invoke-id-unknown", err)
	}
	// The association is still usable.
	if _, err := c.call(ctx, asn1.Prim(asn1.ContextPrimitive(svcIdentify), nil)); err == nil {
		t.Error("the handler rejects Identify; the call should fail with a reject")
	}
}

// Conclude-RequestPDU and -ResponsePDU are [11] and [12] IMPLICIT NULL:
// primitive. The constructed form earlier versions sent is still accepted.
func TestConcludeEncoding(t *testing.T) {
	if got := asn1.Prim(tagConcludeRequest, nil).Encode(); !bytes.Equal(got, []byte{0x8b, 0x00}) {
		t.Errorf("conclude request % x, want 8b 00", got)
	}
	if got := asn1.Prim(tagConcludeResponse, nil).Encode(); !bytes.Equal(got, []byte{0x8c, 0x00}) {
		t.Errorf("conclude response % x, want 8c 00", got)
	}
	// Both forms end the association at a live server.
	addr := serve(t, slowHandler{started: make(chan struct{})})
	for _, pdu := range [][]byte{{0x8b, 0x00}, {0xab, 0x00}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := Dial(ctx, addr, Options{})
		if err != nil {
			t.Fatal(err)
		}
		c.writeMu.Lock()
		c.fr.sendMMS(pdu)
		c.writeMu.Unlock()
		select {
		case <-c.Done():
		case <-ctx.Done():
			t.Errorf("conclude % x did not release the association", pdu)
		}
		cancel()
		c.Close()
	}
}

// The ACSE abort and rejection APDUs round-trip through the presentation
// PDUs that carry them.
func TestAbortAndRejectAPDUs(t *testing.T) {
	aru := presentation.WrapAbort(1, acse.ABRT(acse.AbortSourceUser))
	// As libiec61850 frames it: A0 { 61 { 30 { 02 01 01  A0 { 64 03 80 01 00 } } } }.
	want := []byte{0xa0, 0x0e, 0x61, 0x0c, 0x30, 0x0a, 0x02, 0x01, 0x01, 0xa0, 0x05, 0x64, 0x03, 0x80, 0x01, 0x00}
	if !bytes.Equal(aru, want) {
		t.Errorf("ARU % x, want % x", aru, want)
	}
	abrt, err := presentation.UnwrapAbort(aru)
	if err != nil {
		t.Fatal(err)
	}
	if src, err := acse.ParseABRT(abrt); err != nil || src != acse.AbortSourceUser {
		t.Errorf("abort source %d, %v", src, err)
	}

	aare := acse.AARERejectFor(nil, acse.DiagAuthenticationFailure)
	cpr := presentation.BuildCPR([]byte{0, 0, 0, 1}, nil, aare)
	back, err := presentation.ParseCPRUserData(cpr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := acse.ParseAARE(back)
	if err != nil || res.Accepted || res.Diagnostic != acse.DiagAuthenticationFailure {
		t.Errorf("AARE %+v, %v", res, err)
	}
}
