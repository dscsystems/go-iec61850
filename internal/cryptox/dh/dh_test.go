package dh

import (
	"math/big"
	"testing"
)

// A MODP exponent outside [2, p-2] gives a degenerate public value (1 for
// 0, the generator itself for 1) or is not reduced.
func TestFromPrivateMODPRange(t *testing.T) {
	pMinus1 := new(big.Int).Sub(modp2048P, big.NewInt(1)).Bytes()
	for name, x := range map[string][]byte{
		"zero": {0}, "one": {1}, "p-1": pMinus1, "p": modp2048P.Bytes(),
	} {
		if _, err := FromPrivate(MODP2048, 0, x); err == nil {
			t.Errorf("exponent %s accepted", name)
		}
	}
	if _, err := FromPrivate(MODP2048, 0, []byte{2}); err != nil {
		t.Errorf("exponent 2: %v", err)
	}
}
