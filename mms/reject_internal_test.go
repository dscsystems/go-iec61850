package mms

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

// A request the server cannot decode is answered with a RejectPDU (ISO
// 9506-2), not silence, so the client learns of it at once.
func TestMalformedRequestIsRejected(t *testing.T) {
	addr := serve(t, slowHandler{started: make(chan struct{})})
	cases := []struct {
		name     string
		pdu      []byte
		id       uint32 // the invokeID the reject names; 0 for none
		category uint8
		code     uint8
	}{
		{"unknown PDU type", asn1.Cons(asn1.ContextConstructed(20)).Encode(), 0, rejectPDUError, rejectUnknownPDUType},
		{"invokeID not an integer", asn1.Cons(tagConfirmedRequest,
			asn1.Prim(asn1.TagOctetString, []byte{1})).Encode(), 0, rejectConfirmedRequest, rejectInvalidInvokeID},
		{"no service", asn1.Cons(tagConfirmedRequest,
			asn1.UintElem(asn1.TagInteger, 77)).Encode(), 77, rejectConfirmedRequest, rejectUnrecognizedService},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := Dial(ctx, addr, Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ch := make(chan result, 1)
			c.mu.Lock()
			c.pending[tc.id] = ch
			c.mu.Unlock()
			c.send(ctx, func() error { return c.fr.sendMMS(tc.pdu) })
			select {
			case r := <-ch:
				se, ok := r.err.(*ServiceError)
				if !ok || !se.Rejected || se.Class != tc.category || se.Code != tc.code {
					t.Fatalf("got %v, want reject %d/%d", r.err, tc.category, tc.code)
				}
			case <-ctx.Done():
				t.Fatal("no RejectPDU")
			}
		})
	}
}

// pagingHandler answers every GetNameList with the same page and
// moreFollows set, as a buggy or hostile server might.
type pagingHandler struct{}

func (pagingHandler) Handle(req *Request) (*asn1.Element, error) {
	return asn1.Cons(asn1.ContextConstructed(svcGetNameList),
		asn1.Cons(asn1.ContextConstructed(0), asn1.Prim(asn1.TagVisibleString, []byte("LD0"))),
		asn1.Prim(asn1.ContextPrimitive(1), []byte{0xff}),
	), nil
}

// A continuation that never advances ends with an error instead of
// looping and allocating for ever.
func TestContinuationMustAdvance(t *testing.T) {
	addr := serve(t, pagingHandler{})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.GetNameList(ctx, 9, ""); err != errNoProgress {
		t.Fatalf("GetNameList = %v, want errNoProgress", err)
	}
}
