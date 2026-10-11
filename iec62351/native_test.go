package iec62351

import (
	"crypto/tls"
	"testing"
)

// Register R-10: the IEC 62351-4 Table 10 prints 0xC023/0xC024 for the
// ECDHE_ECDSA AES-GCM suites; those values are CBC suites and must never be
// part of the native-mode profile.
func TestNativeModeSuites(t *testing.T) {
	for _, s := range NativeModeCipherSuites {
		if s == 0xC023 || s == 0xC024 {
			t.Fatalf("suite 0x%04X configured from the misprinted table value", s)
		}
	}
	want := map[uint16]bool{0xC02B: true, 0x003C: true}
	for _, s := range NativeModeCipherSuites {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Fatalf("mandatory suites missing: %v", want)
	}
	if tls.CipherSuiteName(0xC02B) != "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" {
		t.Fatal("IANA value mismatch")
	}
}
