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
	MaxServOutstanding int // both calling and called, unless the fields below are set
	NestingLevel       int
	Services           ServiceSupport

	// MaxServOutstandingCalling and MaxServOutstandingCalled preserve the two
	// values separately. MaxServOutstanding collapses them to the smaller,
	// which is the right thing for a client deciding how many requests to have
	// in flight, but loses information a proxy needs to reproduce the peer's
	// advertisement. When either is non-zero it is encoded in place of the
	// collapsed value.
	MaxServOutstandingCalling int
	MaxServOutstandingCalled  int

	// ParameterCBBRaw, when non-nil, is emitted verbatim as the
	// proposedParameterCBB bit string, including its leading unused-bits
	// octet. It is populated by the parsers.
	ParameterCBBRaw []byte
}

// ServiceSupport is the negotiated service bitmap; only presence matters
// to most peers, so it is kept as raw bits.
type ServiceSupport struct {
	Bits asn1.BitString

	// Raw, when non-nil, is emitted verbatim as the servicesSupported bit
	// string content, including its leading unused-bits octet, instead of
	// re-encoding Bits. Clients gate feature use on this bitmap, so a proxy
	// standing in for a device has to reproduce the device's octets exactly
	// rather than a reconstruction that happens to set the same flags.
	Raw []byte
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

// ServiceSupportOptions bit positions (ISO 9506-2), for building the
// servicesSupported bit string of an Initiate.
const (
	ServiceStatus                         = 0
	ServiceGetNameList                    = 1
	ServiceIdentify                       = 2
	ServiceRead                           = 4
	ServiceWrite                          = 5
	ServiceGetVariableAccessAttributes    = 6
	ServiceDefineNamedVariableList        = 11
	ServiceGetNamedVariableListAttributes = 12
	ServiceDeleteNamedVariableList        = 13
	ServiceReadJournal                    = 65
	ServiceFileOpen                       = 72
	ServiceFileRead                       = 73
	ServiceFileClose                      = 74
	ServiceFileDelete                     = 76
	ServiceFileDirectory                  = 77
	ServiceInformationReport              = 79
	ServiceConclude                       = 83
	ServiceCancel                         = 84

	serviceSupportBits = 85
)

// NewServiceSupport returns a servicesSupported bitmap with the given
// ServiceSupportOptions bits set.
func NewServiceSupport(services ...int) ServiceSupport {
	bs := asn1.NewBitString(serviceSupportBits)
	for _, bit := range services {
		bs.SetBit(bit, true)
	}
	return ServiceSupport{Bits: bs}
}

// Has reports whether the bitmap advertises service (a
// ServiceSupportOptions bit position).
func (s ServiceSupport) Has(service int) bool {
	if s.Bits.Length == 0 && s.Raw != nil {
		if bs, err := asn1.DecodeBitString(s.Raw); err == nil {
			return bs.Bit(service)
		}
		return false
	}
	return s.Bits.Bit(service)
}

// defaultServiceSupport is what this client issues or receives: it is an
// honest statement, not a wish list, so a server gating on it sees the
// services the client can actually take part in.
func defaultServiceSupport() ServiceSupport {
	return NewServiceSupport(
		ServiceGetNameList, ServiceIdentify, ServiceRead, ServiceWrite,
		ServiceGetVariableAccessAttributes,
		ServiceDefineNamedVariableList, ServiceGetNamedVariableListAttributes,
		ServiceDeleteNamedVariableList,
		ServiceReadJournal,
		ServiceFileOpen, ServiceFileRead, ServiceFileClose, ServiceFileDirectory,
		ServiceInformationReport, ServiceConclude,
	)
}

// EncodeInitiateRequest builds an MMS InitiateRequestPDU.
func EncodeInitiateRequest(req InitiateRequest) []byte {
	return encodeInitiate(tagInitiateRequest, req)
}

// EncodeInitiateResponse builds an MMS InitiateResponsePDU mirroring req.
func EncodeInitiateResponse(req InitiateRequest) []byte {
	return encodeInitiate(tagInitiateResponse, req)
}

func encodeInitiate(tag asn1.Tag, req InitiateRequest) []byte {
	cbb := asn1.BitStringElem(asn1.ContextPrimitive(1), parameterCBB())
	if req.ParameterCBBRaw != nil {
		cbb = asn1.Prim(asn1.ContextPrimitive(1), req.ParameterCBBRaw)
	}
	svc := asn1.BitStringElem(asn1.ContextPrimitive(2), req.Services.Bits)
	if req.Services.Raw != nil {
		svc = asn1.Prim(asn1.ContextPrimitive(2), req.Services.Raw)
	}
	detail := asn1.Cons(asn1.ContextConstructed(4),
		asn1.IntElem(asn1.ContextPrimitive(0), 1), // proposedVersionNumber
		cbb,
		svc,
	)

	calling, called := req.MaxServOutstandingCalling, req.MaxServOutstandingCalled
	if calling == 0 {
		calling = req.MaxServOutstanding
	}
	if called == 0 {
		called = req.MaxServOutstanding
	}
	pdu := asn1.Cons(tag,
		asn1.IntElem(asn1.ContextPrimitive(0), int64(req.LocalDetail)),
		asn1.IntElem(asn1.ContextPrimitive(1), int64(calling)),
		asn1.IntElem(asn1.ContextPrimitive(2), int64(called)),
		asn1.IntElem(asn1.ContextPrimitive(3), int64(req.NestingLevel)),
		detail,
	)
	return pdu.Encode()
}

// ParameterSupportOptions bit positions (ISO 9506-2).
const (
	cbbStr1 = 0 // arrays
	cbbStr2 = 1 // structures
	cbbVnam = 2 // named variables
	cbbValt = 3 // alternate access
	cbbVadr = 4 // unnamed (addressed) variables
	cbbVsca = 5 // scattered access
	cbbTpy  = 6 // third-party operations
	cbbVlis = 7 // named variable lists
	cbbReal = 8 // floating point
	cbbCei  = 10

	parameterCBBBits = 11
)

// parameterCBB is the parameter-support bit string this end proposes:
// str1, str2, vnam, valt and vlis, the set IEC 61850-8-1 makes mandatory.
// Arrays and structures carry the data model, and named variable lists
// carry datasets; without them a peer that honours the negotiated CBB
// refuses exactly the accesses IEC 61850 is built on.
func parameterCBB() asn1.BitString {
	bs := asn1.NewBitString(parameterCBBBits)
	for _, bit := range []int{cbbStr1, cbbStr2, cbbVnam, cbbValt, cbbVlis} {
		bs.SetBit(bit, true)
	}
	return bs
}

// intersectParameterCBB returns the raw content octets of ours AND the
// proposed CBB (raw content, unused-bits octet first). The negotiated
// parameter CBB is what both ends support; a malformed proposal yields
// ours unchanged.
func intersectParameterCBB(ours asn1.BitString, proposedRaw []byte) []byte {
	out := asn1.NewBitString(ours.Length)
	copy(out.Bits, ours.Bits)
	if proposed, err := asn1.DecodeBitString(proposedRaw); err == nil {
		for i := 0; i < out.Length; i++ {
			out.SetBit(i, ours.Bit(i) && proposed.Bit(i))
		}
	}
	return asn1.AppendBitString(nil, out)
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
		req.MaxServOutstandingCalling = int(n)
	}
	if c, ok, _ := dec.Optional(asn1.ContextPrimitive(2)); ok {
		n, _ := asn1.DecodeInt(c)
		req.MaxServOutstandingCalled = int(n)
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
			switch tag {
			case asn1.ContextPrimitive(1):
				req.ParameterCBBRaw = append([]byte(nil), dc...)
			case asn1.ContextPrimitive(2):
				raw := append([]byte(nil), dc...)
				if bs, err := asn1.DecodeBitString(dc); err == nil {
					req.Services = ServiceSupport{Bits: bs, Raw: raw}
				} else {
					req.Services = ServiceSupport{Raw: raw}
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
