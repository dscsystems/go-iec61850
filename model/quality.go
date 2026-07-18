package model

import (
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
)

// Quality is the IEC 61850-7-3 Quality type: a 13-bit string. Bit
// positions follow the standard (bit 0 is the first transmitted bit).
type Quality uint16

// Validity values (bits 0-1).
type Validity uint8

const (
	ValidityGood         Validity = 0
	ValidityInvalid      Validity = 1
	ValidityReserved     Validity = 2
	ValidityQuestionable Validity = 3
)

// Quality detail flags, named by bit position.
const (
	QualityOverflow        Quality = 1 << 2
	QualityOutOfRange      Quality = 1 << 3
	QualityBadReference    Quality = 1 << 4
	QualityOscillatory     Quality = 1 << 5
	QualityFailure         Quality = 1 << 6
	QualityOldData         Quality = 1 << 7
	QualityInconsistent    Quality = 1 << 8
	QualityInaccurate      Quality = 1 << 9
	QualitySubstituted     Quality = 1 << 10 // source: 0 process, 1 substituted
	QualityTest            Quality = 1 << 11
	QualityOperatorBlocked Quality = 1 << 12
)

// QualityGood is the all-clear quality.
const QualityGood Quality = 0

// Validity returns the validity field.
func (q Quality) Validity() Validity { return Validity(q & 3) }

// WithValidity returns q with the validity field replaced.
func (q Quality) WithValidity(v Validity) Quality { return q&^3 | Quality(v&3) }

// Is reports whether all flag bits in mask are set.
func (q Quality) Is(mask Quality) bool { return q&mask == mask }

func (v Validity) String() string {
	switch v {
	case ValidityGood:
		return "good"
	case ValidityInvalid:
		return "invalid"
	case ValidityQuestionable:
		return "questionable"
	}
	return "reserved"
}

func (q Quality) String() string {
	parts := []string{q.Validity().String()}
	for _, f := range []struct {
		bit  Quality
		name string
	}{
		{QualityOverflow, "overflow"}, {QualityOutOfRange, "out-of-range"},
		{QualityBadReference, "bad-reference"}, {QualityOscillatory, "oscillatory"},
		{QualityFailure, "failure"}, {QualityOldData, "old-data"},
		{QualityInconsistent, "inconsistent"}, {QualityInaccurate, "inaccurate"},
		{QualitySubstituted, "substituted"}, {QualityTest, "test"},
		{QualityOperatorBlocked, "operator-blocked"},
	} {
		if q.Is(f.bit) {
			parts = append(parts, f.name)
		}
	}
	return strings.Join(parts, "|")
}

// Value converts the quality to a 13-bit MMS bit string. Bit i of the
// quality maps to bit-string position i.
func (q Quality) Value() *mms.Value {
	v := mms.NewBitString(13)
	for i := 0; i < 13; i++ {
		v.SetBit(i, q&(1<<uint(i)) != 0)
	}
	return v
}

// QualityFromValue converts a bit-string value back to a Quality
// (missing/short values decode as good).
func QualityFromValue(v *mms.Value) Quality {
	var q Quality
	n := v.BitLen()
	if n > 16 {
		n = 16
	}
	for i := 0; i < n; i++ {
		if v.Bit(i) {
			q |= 1 << uint(i)
		}
	}
	return q
}

// Dbpos is the double-point position (IEC 61850-7-3), a 2-bit string.
type Dbpos uint8

const (
	DbposIntermediate Dbpos = 0 // 00
	DbposOff          Dbpos = 1 // 01
	DbposOn           Dbpos = 2 // 10
	DbposBad          Dbpos = 3 // 11
)

func (d Dbpos) String() string {
	switch d {
	case DbposIntermediate:
		return "intermediate"
	case DbposOff:
		return "off"
	case DbposOn:
		return "on"
	}
	return "bad"
}

// Value converts to a 2-bit MMS bit string (bit 0 first).
func (d Dbpos) Value() *mms.Value {
	v := mms.NewBitString(2)
	v.SetBit(0, d&2 != 0)
	v.SetBit(1, d&1 != 0)
	return v
}

// DbposFromValue converts a 2-bit string back to a Dbpos.
func DbposFromValue(v *mms.Value) Dbpos {
	var d Dbpos
	if v.Bit(0) {
		d |= 2
	}
	if v.Bit(1) {
		d |= 1
	}
	return d
}

// TrgOps is the report/log trigger-options bit string (6 bits; bit 0 is
// reserved).
type TrgOps uint8

const (
	TrgDataChange    TrgOps = 1 << 1
	TrgQualityChange TrgOps = 1 << 2
	TrgDataUpdate    TrgOps = 1 << 3
	TrgIntegrity     TrgOps = 1 << 4
	TrgGI            TrgOps = 1 << 5
)

// Value converts to a 6-bit MMS bit string.
func (t TrgOps) Value() *mms.Value {
	v := mms.NewBitString(6)
	for i := 0; i < 6; i++ {
		v.SetBit(i, t&(1<<uint(i)) != 0)
	}
	return v
}

// TrgOpsFromValue converts a bit string back to TrgOps.
func TrgOpsFromValue(v *mms.Value) TrgOps {
	var t TrgOps
	for i := 0; i < 6 && i < v.BitLen(); i++ {
		if v.Bit(i) {
			t |= 1 << uint(i)
		}
	}
	return t
}

func (t TrgOps) String() string {
	var parts []string
	for _, f := range []struct {
		bit  TrgOps
		name string
	}{
		{TrgDataChange, "dchg"}, {TrgQualityChange, "qchg"},
		{TrgDataUpdate, "dupd"}, {TrgIntegrity, "period"}, {TrgGI, "gi"},
	} {
		if t&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

// OptFlds is the report optional-fields bit string (10 bits; bit 0
// reserved).
type OptFlds uint16

const (
	OptSeqNum       OptFlds = 1 << 1
	OptTimeOfEntry  OptFlds = 1 << 2
	OptReasonCode   OptFlds = 1 << 3
	OptDataSetName  OptFlds = 1 << 4
	OptDataRef      OptFlds = 1 << 5
	OptBufOvfl      OptFlds = 1 << 6
	OptEntryID      OptFlds = 1 << 7
	OptConfRev      OptFlds = 1 << 8
	OptSegmentation OptFlds = 1 << 9
)

// OptFldsDefault matches what most clients enable.
const OptFldsDefault = OptSeqNum | OptTimeOfEntry | OptReasonCode | OptDataSetName | OptConfRev

// Value converts to a 10-bit MMS bit string.
func (o OptFlds) Value() *mms.Value {
	v := mms.NewBitString(10)
	for i := 0; i < 10; i++ {
		v.SetBit(i, o&(1<<uint(i)) != 0)
	}
	return v
}

// OptFldsFromValue converts a bit string back to OptFlds.
func OptFldsFromValue(v *mms.Value) OptFlds {
	var o OptFlds
	for i := 0; i < 10 && i < v.BitLen(); i++ {
		if v.Bit(i) {
			o |= 1 << uint(i)
		}
	}
	return o
}

// ReasonCode is the per-entry inclusion reason in a report (bit string
// of 7 in reports; bit 0 reserved).
type ReasonCode uint8

const (
	ReasonDataChange    ReasonCode = 1 << 1
	ReasonQualityChange ReasonCode = 1 << 2
	ReasonDataUpdate    ReasonCode = 1 << 3
	ReasonIntegrity     ReasonCode = 1 << 4
	ReasonGI            ReasonCode = 1 << 5
	ReasonApplTrigger   ReasonCode = 1 << 6
)

func (rc ReasonCode) String() string {
	var parts []string
	for _, f := range []struct {
		bit  ReasonCode
		name string
	}{
		{ReasonDataChange, "dchg"}, {ReasonQualityChange, "qchg"},
		{ReasonDataUpdate, "dupd"}, {ReasonIntegrity, "integrity"},
		{ReasonGI, "gi"}, {ReasonApplTrigger, "app-trigger"},
	} {
		if rc&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, "|")
}

// Value converts the reason to a 7-bit reason-for-inclusion bit string.
func (rc ReasonCode) Value() *mms.Value {
	v := mms.NewBitString(7)
	for i := 0; i < 7; i++ {
		v.SetBit(i, rc&(1<<uint(i)) != 0)
	}
	return v
}

// ReasonFromValue converts a report reason-for-inclusion bit string.
func ReasonFromValue(v *mms.Value) ReasonCode {
	var rc ReasonCode
	for i := 0; i < 7 && i < v.BitLen(); i++ {
		if v.Bit(i) {
			rc |= 1 << uint(i)
		}
	}
	return rc
}
