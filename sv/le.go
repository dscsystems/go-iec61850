package sv

import (
	"encoding/binary"
	"fmt"

	"github.com/dscsystems/go-iec61850/model"
)

// LESample is a decoded 9-2LE dataset: four currents and four voltages,
// each an INT32 scaled value with a 32-bit quality word. The 9-2LE
// "PhsMeas1" dataset lays these out as eight (value, quality) pairs in the
// fixed order I_A, I_B, I_C, I_N, V_A, V_B, V_C, V_N.
type LESample struct {
	SmpCnt   uint16
	SmpSynch uint8
	I        [4]int32
	V        [4]int32
	Q        [8]uint32 // quality words, currents 0..3 then voltages 4..7
}

// leSampleLen is the byte length of a 9-2LE phsMeas payload: 8 pairs of
// (int32 value, uint32 quality).
const leSampleLen = 8 * 8

// leQualityMask selects the 13 bits of the quality word that are the
// IEC 61850-7-3 Quality. Position i of the quality string is bit i of the
// word, counting from the least significant bit; bit 13 is the derived
// flag 9-2LE adds, and the bits above it are reserved.
//
// This orientation is easy to get backwards, and getting it backwards
// yields plausible-looking nonsense rather than an error, so it is worth
// stating what pins it down. IEC 61850-9-2:2011 numbers the 32 bits of the
// word from the most significant end, so the least significant bit is its
// bit 31, which makes its bit table easy to misread as the reverse. The
// masks below are the ones Wireshark's SV dissector decodes and
// libiec61850 writes (it puts the Quality integer into the word as is):
//
//	validity = invalid        0x0002   (positions 0-1 = 01)
//	validity = questionable   0x0003   (positions 0-1 = 11)
//	test                      0x0800   (position 11)
//	derived                   0x2000   (9-2LE's bit 13)
//
// A word is therefore the same integer as model.Quality, and the validity
// values carry over unchanged.
//
// The first 9-2LE guideline wrote validity the other way round, with
// invalid as 0x0001, which 9-2:2011 makes the reserved value. Merging
// units built to it are still in service, so Quality reads 0x0001 as
// invalid: a receiver that took it for "reserved" and used the sample
// would be using one its source has disowned. SetQuality always writes the
// 9-2:2011 value, so model.ValidityReserved does not survive the round
// trip; nothing is meant to send it.
const leQualityMask = 0x1fff

// leValidityLegacyInvalid is the validity the first 9-2LE guideline used
// for invalid, and 9-2:2011 for reserved.
const leValidityLegacyInvalid = 0x0001

// Quality returns the quality of channel i (0..3 currents, 4..7 voltages).
func (s *LESample) Quality(i int) model.Quality {
	if i < 0 || i >= len(s.Q) {
		return 0
	}
	q := model.Quality(s.Q[i] & leQualityMask)
	if s.Q[i]&3 == leValidityLegacyInvalid {
		q = q.WithValidity(model.ValidityInvalid)
	}
	return q
}

// SetQuality writes a 13-bit quality into channel i, leaving the derived
// and reserved bits of the word alone.
func (s *LESample) SetQuality(i int, q model.Quality) {
	if i < 0 || i >= len(s.Q) {
		return
	}
	s.Q[i] = (s.Q[i] &^ leQualityMask) | (uint32(q) & leQualityMask)
}

// EncodeLESample serialises a 9-2LE dataset payload (64 octets).
func EncodeLESample(s *LESample) []byte {
	b := make([]byte, leSampleLen)
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(b[i*8:], uint32(s.I[i]))
		binary.BigEndian.PutUint32(b[i*8+4:], s.Q[i])
	}
	for i := 0; i < 4; i++ {
		off := 32 + i*8
		binary.BigEndian.PutUint32(b[off:], uint32(s.V[i]))
		binary.BigEndian.PutUint32(b[off+4:], s.Q[4+i])
	}
	return b
}

// DecodeLESample parses a 9-2LE dataset payload. The SmpCnt and SmpSynch
// fields are left zero; callers copy them from the enclosing ASDU.
func DecodeLESample(sample []byte) (*LESample, error) {
	if len(sample) < leSampleLen {
		return nil, fmt.Errorf("sv: 9-2LE sample of %d octets, want %d", len(sample), leSampleLen)
	}
	s := &LESample{}
	for i := 0; i < 4; i++ {
		s.I[i] = int32(binary.BigEndian.Uint32(sample[i*8:]))
		s.Q[i] = binary.BigEndian.Uint32(sample[i*8+4:])
	}
	for i := 0; i < 4; i++ {
		off := 32 + i*8
		s.V[i] = int32(binary.BigEndian.Uint32(sample[off:]))
		s.Q[4+i] = binary.BigEndian.Uint32(sample[off+4:])
	}
	return s, nil
}

// decodeLEInto decodes into a caller-provided sample without allocating,
// for the zero-allocation receive path.
func decodeLEInto(a *ASDU, s *LESample) error {
	if len(a.Sample) < leSampleLen {
		return fmt.Errorf("sv: 9-2LE sample of %d octets, want %d", len(a.Sample), leSampleLen)
	}
	s.SmpCnt = a.SmpCnt
	s.SmpSynch = a.SmpSynch
	for i := 0; i < 4; i++ {
		s.I[i] = int32(binary.BigEndian.Uint32(a.Sample[i*8:]))
		s.Q[i] = binary.BigEndian.Uint32(a.Sample[i*8+4:])
	}
	for i := 0; i < 4; i++ {
		off := 32 + i*8
		s.V[i] = int32(binary.BigEndian.Uint32(a.Sample[off:]))
		s.Q[4+i] = binary.BigEndian.Uint32(a.Sample[off+4:])
	}
	return nil
}
