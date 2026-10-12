// Package ossltls is a TLS engine for the IEC 62351 profiles built on
// OpenSSL, for the cipher suites Go's crypto/tls does not implement: above
// all TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009E), mandatory in the IEC
// 62351-4 native-mode profile (Table 10). It needs cgo, OpenSSL 3 (libssl
// and libcrypto, found with pkg-config) and the build tag openssl; without
// them Available reports false and NewContext fails with ErrUnavailable.
//
// The static-DH suites of Table 10 (TLS_DH_RSA_*, 0x0031, 0x00A0, 0x00A1)
// cannot be offered: OpenSSL removed static Diffie-Hellman in 1.1.0.
//
// OpenSSL does not parse certificates whose subject is an IEC 62351-4 AE
// title (an X.520 objectIdentifier attribute), so both ends' TLS
// certificates must have ordinary subjects; the TLS and E2E credentials
// are separate anyway (IEC 62351-4 G.2).
//
// OpenSSL runs the protocol over memory BIOs; this package moves the bytes
// between them and the net.Conn, so deadlines and cancellation behave as
// with crypto/tls. Peer certificates are accepted during the handshake and
// checked afterwards by iec62351.Options.VerifyPeer — the same chain,
// revocation, key-strength, server-name and pinning checks the crypto/tls
// configurations apply.
package ossltls

import (
	"crypto/tls"
	"errors"
)

// Role is the side of the handshake a Context serves.
type Role int

const (
	Client Role = iota
	Server
)

// ErrUnavailable is NewContext's error in a build without OpenSSL.
var ErrUnavailable = errors.New("ossltls: built without OpenSSL (build with -tags openssl and cgo)")

// The suites offered, by OpenSSL name, forward-secret ones first. Native
// mode (IEC 62351-4 Table 10, TLS 1.2): ECDHE_ECDSA_AES_128_GCM 0xC02B (m;
// printed 0xC0,0x23), the optional ECDHE_RSA_AES_128_GCM 0xC02F,
// DHE_RSA_AES_128_GCM 0x009E (m; printed 0xC0,0x9E), the optional AES-256
// GCM suites 0xC02C and 0xC030, and last RSA_AES_128_CBC_SHA256 0x003C (m),
// which has no forward secrecy. Table 10 sets no order. IEC 62351-3: the
// ECDHE AES-GCM suites the crypto/tls profile offers, and TLS 1.3 AES-GCM.
const (
	nativeCiphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:" +
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA256"
	profileCiphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" +
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
	tls13Suites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
	groups      = "P-256:P-384"
)

// NativeModeSuites are the IANA values native mode offers, in order.
var NativeModeSuites = []uint16{0xC02B, 0xC02F, 0x009E, 0xC02C, 0xC030, 0x003C}

// SuiteName names a negotiated cipher suite, including those crypto/tls
// does not know.
func SuiteName(id uint16) string {
	switch id {
	case 0x009E:
		return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0x003C:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	}
	return tls.CipherSuiteName(id)
}
