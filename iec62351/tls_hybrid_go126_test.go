//go:build go1.26

// The module's go line is older than 1.26, so the toolchain defaults
// tlssecpmlkem to 0 and Go 1.26 then drops the NIST-curve hybrids even
// from an explicit CurvePreferences. An application in the same position
// sets the same thing (see docs/tls-hybrid-compatibility.md).
//go:debug tlssecpmlkem=1

package iec62351_test

import "crypto/tls"

// The NIST-curve hybrids need Go 1.26; TestTLSHybridCompatibility covers
// them through hybridGroups.
func init() {
	hybridGroups = append(hybridGroups, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024)
}
