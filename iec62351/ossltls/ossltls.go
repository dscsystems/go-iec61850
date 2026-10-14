// Package ossltls is a TLS engine for the IEC 62351 profiles built on
// OpenSSL, for the cipher suites Go's crypto/tls does not implement: above
// all TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009E), mandatory in the IEC
// 62351-4 native-mode profile (Table 10). It needs cgo, OpenSSL (libssl
// and libcrypto, found with pkg-config) and the build tag openssl; without
// them Available reports false and NewContext fails with ErrUnavailable.
//
// The package builds against OpenSSL 3, or with the build tags
// openssl,openssl_v1 against OpenSSL 1.0.2 (Legacy, the engine
// "openssl-v1"): a separate build, since both cannot be linked into one
// binary. OpenSSL
// removed static Diffie-Hellman in 1.1.0, so only a 1.0.2 build offers the
// static-DH suites of Table 10 (TLS_DH_RSA_*, 0x00A0 mandatory, 0x00A1,
// 0x0031), with the server's DH certificate from Context.SetStaticDH. It
// has no TLS 1.3. It builds on Linux and, with MinGW-w64, for Windows
// (openssl-v1.sh builds the library). OpenSSL 1.0.2 has been out of support
// since 2019: use such a build only for a peer that needs these suites.
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
	// Native mode on OpenSSL 1.0.2 adds the static-DH suites after the
	// forward-secret ones, before RSA key exchange: DH_RSA_AES_128_GCM
	// 0x00A0 (m), DH_RSA_AES_256_GCM 0x00A1 and DH_RSA_AES_128_CBC_SHA 0x0031.
	nativeCiphersV1 = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:" +
		"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" +
		"DH-RSA-AES128-GCM-SHA256:DH-RSA-AES256-GCM-SHA384:DH-RSA-AES128-SHA:AES128-SHA256"
	groups = "P-256:P-384"
)

// NativeModeSuites are the IANA values native mode offers, in order.
var NativeModeSuites = []uint16{0xC02B, 0xC02F, 0x009E, 0xC02C, 0xC030, 0x003C}

// NativeModeSuitesV1 are the IANA values native mode offers on OpenSSL
// 1.0.2 (Legacy), in order.
var NativeModeSuitesV1 = []uint16{0xC02B, 0xC02F, 0x009E, 0xC02C, 0xC030, 0x00A0, 0x00A1, 0x0031, 0x003C}

// SuiteName names a negotiated cipher suite, including those crypto/tls
// does not know.
func SuiteName(id uint16) string {
	switch id {
	case 0x009E:
		return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
	case 0x003C:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case 0x00A0:
		return "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"
	case 0x00A1:
		return "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"
	case 0x0031:
		return "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
	}
	return tls.CipherSuiteName(id)
}
