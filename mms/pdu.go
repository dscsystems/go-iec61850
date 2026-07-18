package mms

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// MMSpdu CHOICE tags (ISO 9506-2), context class.
var (
	tagConfirmedRequest  = asn1.ContextConstructed(0)
	tagConfirmedResponse = asn1.ContextConstructed(1)
	tagConfirmedError    = asn1.ContextConstructed(2)
	tagUnconfirmed       = asn1.ContextConstructed(3)
	tagRejectPDU         = asn1.ContextConstructed(4)
	tagInitiateRequest   = asn1.ContextConstructed(8)
	tagInitiateResponse  = asn1.ContextConstructed(9)
	tagInitiateError     = asn1.ContextConstructed(10)
	tagConcludeRequest   = asn1.ContextConstructed(11)
	tagConcludeResponse  = asn1.ContextConstructed(12)
	tagConcludeError     = asn1.ContextConstructed(13)
)

// Confirmed service CHOICE tags used within ConfirmedRequest/Response
// (ISO 9506-2 ConfirmedServiceRequest).
const (
	svcStatus              = 0
	svcGetNameList         = 1
	svcIdentify            = 2
	svcRead                = 4
	svcWrite               = 5
	svcGetVariableAccess   = 6
	svcDefineNamedVarList  = 11
	svcGetNamedVarListAttr = 12
	svcDeleteNamedVarList  = 13
	svcFileOpen            = 72
	svcFileRead            = 73
	svcFileClose           = 74
	svcFileDelete          = 76
	svcFileDirectory       = 77
)

// Unconfirmed service CHOICE tags.
const (
	unconfInformationReport = 0
)

// InitiateRequest holds the negotiable parameters of an MMS association.
type InitiateRequest struct {
	LocalDetail        int32
	MaxServOutstanding int // both calling and called
	NestingLevel       int
	Services           ServiceSupport
}

// ServiceSupport is the negotiated service bitmap; only presence matters
// to most peers, so it is kept as raw bits.
type ServiceSupport struct {
	Bits asn1.BitString
}

// DefaultInitiate returns typical client initiate parameters.
func DefaultInitiate() InitiateRequest {
	return InitiateRequest{
		LocalDetail:        65000,
		MaxServOutstanding: 10,
		NestingLevel:       5,
		Services:           defaultServiceSupport(),
	}
}

func defaultServiceSupport() ServiceSupport {
	// 85-bit CBB bit string; enable the services a client uses. We set a
	// broad set matching libiec61850 clients: status, getNameList,
	// identify, read, write, getVariableAccessAttributes, definN/deleteVL,
	// getNVL, fileServices, informationReport.
	bs := asn1.NewBitString(85)
	for _, bit := range []int{0, 1, 2, 4, 5, 6, 11, 12, 13, 14, 15, 16, 18, 19, 72, 73, 74, 76, 77, 79} {
		bs.SetBit(bit, true)
	}
	return ServiceSupport{Bits: bs}
}

// EncodeInitiateRequest builds an MMS InitiateRequestPDU.
func EncodeInitiateRequest(req InitiateRequest) []byte {
	detail := asn1.Cons(asn1.ContextConstructed(4), // InitRequestDetail
		asn1.IntElem(asn1.ContextPrimitive(0), 1), // proposedVersionNumber
		asn1.BitStringElem(asn1.ContextPrimitive(1), parameterCBB()),
		asn1.BitStringElem(asn1.ContextPrimitive(2), req.Services.Bits),
	)
	pdu := asn1.Cons(tagInitiateRequest,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(req.LocalDetail)),
		asn1.IntElem(asn1.ContextPrimitive(1), int64(req.MaxServOutstanding)),
		asn1.IntElem(asn1.ContextPrimitive(2), int64(req.MaxServOutstanding)),
		asn1.IntElem(asn1.ContextPrimitive(3), int64(req.NestingLevel)),
		detail,
	)
	return pdu.Encode()
}

// EncodeInitiateResponse builds an MMS InitiateResponsePDU mirroring req.
func EncodeInitiateResponse(req InitiateRequest) []byte {
	detail := asn1.Cons(asn1.ContextConstructed(4),
		asn1.IntElem(asn1.ContextPrimitive(0), 1),
		asn1.BitStringElem(asn1.ContextPrimitive(1), parameterCBB()),
		asn1.BitStringElem(asn1.ContextPrimitive(2), req.Services.Bits),
	)
	pdu := asn1.Cons(tagInitiateResponse,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(req.LocalDetail)),
		asn1.IntElem(asn1.ContextPrimitive(1), int64(req.MaxServOutstanding)),
		asn1.IntElem(asn1.ContextPrimitive(2), int64(req.MaxServOutstanding)),
		asn1.IntElem(asn1.ContextPrimitive(3), int64(req.NestingLevel)),
		detail,
	)
	return pdu.Encode()
}

// parameterCBB is the parameter-support bit string (proposed): indexed
// bits str1(0) str2(1) vnam(2) valt(3) vadr(4) vsca(7) tpy(8) vlis(9)...
func parameterCBB() asn1.BitString {
	bs := asn1.NewBitString(11)
	bs.SetBit(2, true) // vnam
	bs.SetBit(3, true) // valt
	bs.SetBit(4, true) // vadr
	bs.SetBit(5, true) // valt/tpy per stack; keep broad
	bs.SetBit(6, true)
	return bs
}

// ParseInitiateResponse decodes an InitiateResponsePDU, returning the
// negotiated parameters.
func ParseInitiateResponse(pdu []byte) (InitiateRequest, error) {
	dec := asn1.NewDecoder(pdu)
	content, err := dec.Expect(tagInitiateResponse)
	if err != nil {
		// Some servers return InitiateError; surface it.
		if d2 := asn1.NewDecoder(pdu); d2.PeekIs(tagInitiateError) {
			return InitiateRequest{}, fmt.Errorf("mms: association rejected (InitiateError)")
		}
		return InitiateRequest{}, err
	}
	return parseInitiateBody(content)
}

// ParseInitiateRequest decodes an InitiateRequestPDU (server side).
func ParseInitiateRequest(pdu []byte) (InitiateRequest, error) {
	dec := asn1.NewDecoder(pdu)
	content, err := dec.Expect(tagInitiateRequest)
	if err != nil {
		return InitiateRequest{}, err
	}
	return parseInitiateBody(content)
}

func parseInitiateBody(content []byte) (InitiateRequest, error) {
	var req InitiateRequest
	dec := asn1.NewDecoder(content)
	if c, ok, _ := dec.Optional(asn1.ContextPrimitive(0)); ok {
		n, _ := asn1.DecodeInt(c)
		req.LocalDetail = int32(n)
	}
	if c, ok, _ := dec.Optional(asn1.ContextPrimitive(1)); ok {
		n, _ := asn1.DecodeInt(c)
		req.MaxServOutstanding = int(n)
	}
	if c, ok, _ := dec.Optional(asn1.ContextPrimitive(2)); ok {
		n, _ := asn1.DecodeInt(c)
		if int(n) < req.MaxServOutstanding || req.MaxServOutstanding == 0 {
			req.MaxServOutstanding = int(n)
		}
	}
	if c, ok, _ := dec.Optional(asn1.ContextPrimitive(3)); ok {
		n, _ := asn1.DecodeInt(c)
		req.NestingLevel = int(n)
	}
	if c, ok, _ := dec.Optional(asn1.ContextConstructed(4)); ok {
		detail := asn1.NewDecoder(c)
		for detail.More() {
			tag, dc, err := detail.ReadTLV()
			if err != nil {
				break
			}
			if tag == asn1.ContextPrimitive(2) {
				if bs, err := asn1.DecodeBitString(dc); err == nil {
					req.Services = ServiceSupport{Bits: bs}
				}
			}
		}
	}
	if req.LocalDetail == 0 {
		req.LocalDetail = 65000
	}
	if req.MaxServOutstanding == 0 {
		req.MaxServOutstanding = 1
	}
	return req, nil
}
