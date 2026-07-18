// Package goose implements the IEC 61850-8-1 GOOSE mapping over raw
// Ethernet: the goosePdu codec, a publisher with the standard
// retransmission state machine, and a subscriber with anomaly detection.
package goose

import (
	"fmt"
	"math"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
)

// headerLen is the fixed APDU header: APPID, Length, Reserved1, Reserved2.
const headerLen = 8

// pduTag frames the goosePdu after the APDU header.
var pduTag = asn1.ApplicationConstructed(1) // 0x61

// Message is one GOOSE APDU. On publish, the publisher owns T, StNum,
// SqNum and TimeAllowedToLive; on receive, Anomalies carries the
// subscriber's per-goCbRef sequence checks and is not part of the wire
// format.
type Message struct {
	GoCbRef, DatSet, GoID string
	TimeAllowedToLive     uint32 // milliseconds
	T                     time.Time
	StNum, SqNum, ConfRev uint32
	Test, NdsCom          bool
	NumDatSetEntries      uint32
	Values                []*mms.Value
	AppID                 uint16

	Anomalies Anomalies
}

// Marshal encodes the full APDU: APPID, Length, two reserved words, then
// the [APPLICATION 1] goosePdu.
func (m *Message) Marshal() []byte {
	allData := asn1.Cons(asn1.ContextConstructed(11))
	for _, v := range m.Values {
		allData.Add(mms.DataElement(v))
	}
	pdu := asn1.Cons(pduTag,
		asn1.Prim(asn1.ContextPrimitive(0), []byte(m.GoCbRef)),
		asn1.UintElem(asn1.ContextPrimitive(1), uint64(m.TimeAllowedToLive)),
		asn1.Prim(asn1.ContextPrimitive(2), []byte(m.DatSet)),
		asn1.Prim(asn1.ContextPrimitive(3), []byte(m.GoID)),
		asn1.Prim(asn1.ContextPrimitive(4), mms.NewUTCTime(m.T, mms.TimeAccuracy(10)).Bytes()),
		asn1.UintElem(asn1.ContextPrimitive(5), uint64(m.StNum)),
		asn1.UintElem(asn1.ContextPrimitive(6), uint64(m.SqNum)),
		asn1.BoolElem(asn1.ContextPrimitive(7), m.Test),
		asn1.UintElem(asn1.ContextPrimitive(8), uint64(m.ConfRev)),
		asn1.BoolElem(asn1.ContextPrimitive(9), m.NdsCom),
		asn1.UintElem(asn1.ContextPrimitive(10), uint64(m.NumDatSetEntries)),
		allData,
	)
	length := headerLen + pdu.Size() // must fit the MTU in practice
	buf := make([]byte, 0, length)
	buf = append(buf,
		byte(m.AppID>>8), byte(m.AppID),
		byte(length>>8), byte(length),
		0, 0, 0, 0)
	return pdu.Append(buf)
}

// Parse decodes a GOOSE APDU (the Ethernet payload after the EtherType).
// The returned message does not alias apdu.
func Parse(apdu []byte) (*Message, error) {
	if len(apdu) < headerLen {
		return nil, fmt.Errorf("goose: apdu of %d octets: %w", len(apdu), asn1.ErrTruncated)
	}
	m := &Message{AppID: uint16(apdu[0])<<8 | uint16(apdu[1])}
	length := int(apdu[2])<<8 | int(apdu[3])
	if length < headerLen || length > len(apdu) {
		return nil, fmt.Errorf("goose: length field %d in apdu of %d octets: %w",
			length, len(apdu), asn1.ErrBadLength)
	}
	content, err := asn1.NewDecoder(apdu[headerLen:length]).Expect(pduTag)
	if err != nil {
		return nil, fmt.Errorf("goose: %w", err)
	}
	d := asn1.NewDecoder(content)

	b, err := d.Expect(asn1.ContextPrimitive(0))
	if err != nil {
		return nil, fmt.Errorf("goose: gocbRef: %w", err)
	}
	m.GoCbRef = string(b)
	if m.TimeAllowedToLive, err = expectUint32(d, 1, "timeAllowedToLive"); err != nil {
		return nil, err
	}
	if b, err = d.Expect(asn1.ContextPrimitive(2)); err != nil {
		return nil, fmt.Errorf("goose: datSet: %w", err)
	}
	m.DatSet = string(b)
	if b, ok, err := d.Optional(asn1.ContextPrimitive(3)); err != nil {
		return nil, fmt.Errorf("goose: goID: %w", err)
	} else if ok {
		m.GoID = string(b)
	}
	if b, err = d.Expect(asn1.ContextPrimitive(4)); err != nil {
		return nil, fmt.Errorf("goose: t: %w", err)
	}
	tv, err := mms.NewUTCTimeRaw(b)
	if err != nil {
		return nil, fmt.Errorf("goose: t: %w", err)
	}
	m.T = tv.Time()
	if m.StNum, err = expectUint32(d, 5, "stNum"); err != nil {
		return nil, err
	}
	if m.SqNum, err = expectUint32(d, 6, "sqNum"); err != nil {
		return nil, err
	}
	if b, ok, err := d.Optional(asn1.ContextPrimitive(7)); err != nil {
		return nil, fmt.Errorf("goose: test: %w", err)
	} else if ok {
		if m.Test, err = asn1.DecodeBool(b); err != nil {
			return nil, fmt.Errorf("goose: test: %w", err)
		}
	}
	if m.ConfRev, err = expectUint32(d, 8, "confRev"); err != nil {
		return nil, err
	}
	if b, ok, err := d.Optional(asn1.ContextPrimitive(9)); err != nil {
		return nil, fmt.Errorf("goose: ndsCom: %w", err)
	} else if ok {
		if m.NdsCom, err = asn1.DecodeBool(b); err != nil {
			return nil, fmt.Errorf("goose: ndsCom: %w", err)
		}
	}
	if m.NumDatSetEntries, err = expectUint32(d, 10, "numDatSetEntries"); err != nil {
		return nil, err
	}
	if content, err = d.Expect(asn1.ContextConstructed(11)); err != nil {
		return nil, fmt.Errorf("goose: allData: %w", err)
	}
	inner := asn1.NewDecoder(content)
	for inner.More() {
		v, err := mms.DecodeData(inner)
		if err != nil {
			return nil, fmt.Errorf("goose: allData member %d: %w", len(m.Values), err)
		}
		m.Values = append(m.Values, v)
	}
	// Trailing fields (for example [12] security) are ignored.
	return m, nil
}

// expectUint32 consumes a context-primitive unsigned INTEGER field.
func expectUint32(d *asn1.Decoder, tag uint32, name string) (uint32, error) {
	b, err := d.Expect(asn1.ContextPrimitive(tag))
	if err != nil {
		return 0, fmt.Errorf("goose: %s: %w", name, err)
	}
	v, err := asn1.DecodeUint(b)
	if err != nil || v > math.MaxUint32 {
		return 0, fmt.Errorf("goose: %s out of range: %w", name, asn1.ErrBadValue)
	}
	return uint32(v), nil
}
