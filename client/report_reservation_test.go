package client_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Unlike the Go server's implicit reservation, a peer can require Resv=true
// before accepting any configuration or RptEna write (as the Rust server does).
type explicitReservationPeer struct{ reserved bool }

func (h *explicitReservationPeer) Handle(req *mms.Request) (*asn1.Element, error) {
	if req.Service != 5 {
		return nil, &mms.ServiceError{Rejected: true, Class: 1, Code: 1}
	}
	d := asn1.NewDecoder(req.Content)
	variables, err := d.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err
	}
	data, err := d.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err
	}
	entry, err := asn1.NewDecoder(variables).Expect(asn1.TagSequence)
	if err != nil {
		return nil, err
	}
	spec, err := asn1.NewDecoder(entry).Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err
	}
	name, err := asn1.NewDecoder(spec).Expect(asn1.ContextConstructed(1))
	if err != nil {
		return nil, err
	}
	nd := asn1.NewDecoder(name)
	if _, err = nd.Expect(asn1.TagVisibleString); err != nil {
		return nil, err
	}
	item, err := nd.Expect(asn1.TagVisibleString)
	if err != nil {
		return nil, err
	}
	value, err := mms.DecodeData(asn1.NewDecoder(data))
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(string(item), "$Resv") {
		h.reserved = value.Bool()
	} else if !h.reserved {
		return asn1.Cons(asn1.ContextConstructed(5), asn1.UintElem(asn1.ContextPrimitive(0), uint64(mms.AccessObjectAccessDenied))), nil
	}
	return asn1.Cons(asn1.ContextConstructed(5), asn1.Prim(asn1.ContextPrimitive(1), nil)), nil
}

func TestEnableReportingReservesBeforeConfiguration(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		sc, err := mms.AcceptConn(raw)
		if err != nil {
			raw.Close()
			return
		}
		defer sc.Close()
		_ = sc.Serve(&explicitReservationPeer{})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rcb, err := c.GetRCB(ctx, "IEDLD0/LLN0.RP.urcb")
	if err != nil {
		t.Fatal(err)
	}
	rcb.OptFlds = model.OptFldsDefault
	sub, err := c.EnableReporting(ctx, rcb, func(*client.Report) {})
	if err != nil {
		t.Fatalf("peer requires explicit reservation: %v", err)
	}
	if err := sub.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	c.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
