package server

import (
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// TestDecodeOperCheckBits is the receiving half of the Check ordering of
// IEC 61850-7-2 Table 51: bit 0 is synchrocheck, bit 1 interlock-check.
// A client-to-server test cannot catch a transposition because both ends
// would move together, so decode a bit string built by hand.
func TestDecodeOperCheckBits(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bit0, bit1 bool
	}{
		{"neither", false, false},
		{"synchro", true, false},
		{"interlock", false, true},
		{"both", true, true},
	} {
		check := mms.NewBitString(2)
		check.SetBit(0, tc.bit0)
		check.SetBit(1, tc.bit1)
		oper := mms.NewStructure(
			mms.NewBool(true),
			mms.NewStructure(mms.NewInt8(int8(model.OrCatStationControl)), mms.NewOctetString(nil)),
			mms.NewUint8(1),
			mms.NewUTCTime(time.Now(), mms.TimeAccuracy(10)),
			mms.NewBool(false),
			check,
		)
		ctx := decodeOper(model.ObjectReference("LD/GGIO1.SPCSO1"), oper, nil)
		if ctx.Synchro != tc.bit0 {
			t.Errorf("%s: Synchro = %v from bit 0 = %v", tc.name, ctx.Synchro, tc.bit0)
		}
		if ctx.Interlock != tc.bit1 {
			t.Errorf("%s: Interlock = %v from bit 1 = %v", tc.name, ctx.Interlock, tc.bit1)
		}
	}
}
