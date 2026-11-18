//go:build go1.26

package iec62351_test

import "crypto/tls"

// The NIST-curve hybrids need Go 1.26; TestTLSHybridCompatibility covers
// them through hybridGroups.
func init() {
	hybridGroups = append(hybridGroups, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024)
}
