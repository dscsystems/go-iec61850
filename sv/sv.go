// Package sv implements the IEC 61850-9-2 Sampled Values mapping over raw
// Ethernet: the savPdu/ASDU codec, a generic and a 9-2LE typed
// subscriber, and a 9-2LE publisher with a sample clock.
package sv

import (
	"fmt"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
)

// headerLen is the fixed APDU header: APPID, Length, Reserved1, Reserved2.
const headerLen = 8

// savPduTag frames the savPdu after the APDU header.
var savPduTag = asn1.ApplicationConstructed(0) // 0x60

// SmpSynch values (IEC 61850-9-2).
const (
	SmpSynchNone   uint8 = 0
	SmpSynchLocal  uint8 = 1
	SmpSynchGlobal uint8 = 2
)

// ASDU is one Application Service Data Unit within a sampled-value APDU.
type ASDU struct {
	SvID     string
	DatSet   string
	SmpCnt   uint16
	ConfRev  uint32
	RefrTm   time.Time // zero when absent
	SmpSynch uint8
	SmpRate  uint16 // zero when absent
	Sample   []byte // the raw dataset payload (phsMeas for 9-2LE)
}

// PDU is a sampled-value APDU carrying one or more ASDUs.
type PDU struct {
	AppID uint16
	ASDUs []*ASDU
}

// Marshal encodes the full APDU: APPID, Length, two reserved words, then
// the [APPLICATION 0] savPdu.
func (p *PDU) Marshal() []byte {
	seqASDU := asn1.Cons(asn1.ContextConstructed(2)) // seqOfASDU [2]
	for _, a := range p.ASDUs {
		seqASDU.Add(a.element())
	}
	sav := asn1.Cons(savPduTag,
		asn1.UintElem(asn1.ContextPrimitive(0), uint64(len(p.ASDUs))), // noASDU [0]
		seqASDU,
	)
	length := headerLen + sav.Size()
	buf := make([]byte, 0, length)
	buf = append(buf,
		byte(p.AppID>>8), byte(p.AppID),
		byte(length>>8), byte(length),
		0, 0, 0, 0)
	return sav.Append(buf)
}

func (a *ASDU) element() *asn1.Element {
	el := asn1.Cons(asn1.TagSequence,
		asn1.Prim(asn1.ContextPrimitive(0), []byte(a.SvID)), // svID [0]
	)
	if a.DatSet != "" {
		el.Add(asn1.Prim(asn1.ContextPrimitive(1), []byte(a.DatSet))) // datSet [1]
	}
	// smpCnt [2] OCTET STRING (2 octets, big-endian) per 9-2LE.
	el.Add(asn1.Prim(asn1.ContextPrimitive(2), []byte{byte(a.SmpCnt >> 8), byte(a.SmpCnt)}))
	el.Add(asn1.UintElem(asn1.ContextPrimitive(3), uint64(a.ConfRev))) // confRev [3]
	if !a.RefrTm.IsZero() {
		el.Add(asn1.Prim(asn1.ContextPrimitive(4), mms.NewUTCTime(a.RefrTm, mms.TimeAccuracy(10)).Bytes()))
	}
	el.Add(asn1.Prim(asn1.ContextPrimitive(5), []byte{a.SmpSynch})) // smpSynch [5]
	if a.SmpRate != 0 {
		el.Add(asn1.Prim(asn1.ContextPrimitive(6), []byte{byte(a.SmpRate >> 8), byte(a.SmpRate)}))
	}
	el.Add(asn1.Prim(asn1.ContextPrimitive(7), a.Sample)) // sample [7] OCTET STRING
	return el
}

// Parse decodes a sampled-value APDU (the Ethernet payload after the
// EtherType). The returned PDU does not alias apdu.
func Parse(apdu []byte) (*PDU, error) {
	if len(apdu) < headerLen {
		return nil, fmt.Errorf("sv: apdu of %d octets: %w", len(apdu), asn1.ErrTruncated)
	}
	p := &PDU{AppID: uint16(apdu[0])<<8 | uint16(apdu[1])}
	length := int(apdu[2])<<8 | int(apdu[3])
	if length < headerLen || length > len(apdu) {
		return nil, fmt.Errorf("sv: length field %d in apdu of %d octets: %w",
			length, len(apdu), asn1.ErrBadLength)
	}
	content, err := asn1.NewDecoder(apdu[headerLen:length]).Expect(savPduTag)
	if err != nil {
		return nil, fmt.Errorf("sv: %w", err)
	}
	d := asn1.NewDecoder(content)
	if _, err := d.Expect(asn1.ContextPrimitive(0)); err != nil { // noASDU
		return nil, fmt.Errorf("sv: noASDU: %w", err)
	}
	seq, err := d.Expect(asn1.ContextConstructed(2)) // seqOfASDU
	if err != nil {
		return nil, fmt.Errorf("sv: seqOfASDU: %w", err)
	}
	sd := asn1.NewDecoder(seq)
	for sd.More() {
		asduContent, err := sd.Expect(asn1.TagSequence)
		if err != nil {
			return nil, fmt.Errorf("sv: ASDU: %w", err)
		}
		a, err := parseASDU(asduContent)
		if err != nil {
			return nil, err
		}
		p.ASDUs = append(p.ASDUs, a)
	}
	return p, nil
}

func parseASDU(content []byte) (*ASDU, error) {
	d := asn1.NewDecoder(content)
	a := &ASDU{}
	b, err := d.Expect(asn1.ContextPrimitive(0))
	if err != nil {
		return nil, fmt.Errorf("sv: svID: %w", err)
	}
	a.SvID = string(b)
	if b, ok, _ := d.Optional(asn1.ContextPrimitive(1)); ok {
		a.DatSet = string(b)
	}
	if b, err = d.Expect(asn1.ContextPrimitive(2)); err != nil {
		return nil, fmt.Errorf("sv: smpCnt: %w", err)
	}
	a.SmpCnt = beUint16(b)
	if b, err = d.Expect(asn1.ContextPrimitive(3)); err != nil {
		return nil, fmt.Errorf("sv: confRev: %w", err)
	}
	if n, err := asn1.DecodeUint(b); err == nil {
		a.ConfRev = uint32(n)
	}
	if b, ok, _ := d.Optional(asn1.ContextPrimitive(4)); ok {
		if tv, err := mms.NewUTCTimeRaw(b); err == nil {
			a.RefrTm = tv.Time()
		}
	}
	if b, ok, _ := d.Optional(asn1.ContextPrimitive(5)); ok && len(b) > 0 {
		a.SmpSynch = b[len(b)-1]
	}
	if b, ok, _ := d.Optional(asn1.ContextPrimitive(6)); ok {
		a.SmpRate = beUint16(b)
	}
	if b, err = d.Expect(asn1.ContextPrimitive(7)); err != nil {
		return nil, fmt.Errorf("sv: sample: %w", err)
	}
	a.Sample = append([]byte(nil), b...)
	return a, nil
}

func beUint16(b []byte) uint16 {
	switch len(b) {
	case 0:
		return 0
	case 1:
		return uint16(b[0])
	default:
		return uint16(b[len(b)-2])<<8 | uint16(b[len(b)-1])
	}
}
