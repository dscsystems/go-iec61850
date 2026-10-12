package e2e

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/internal/cryptox/dh"
)

// Object identifiers of IEC 62351-4 and of the algorithms it uses.
var (
	OIDE2ESecurityAS = asn1.OID{1, 0, 62351, 4, 1, 2, 1} // e2eSecurityAS (15.2.1)
	OIDE2EMMSContext = asn1.OID{1, 0, 62351, 4, 2, 1}    // e2eMmsAC (15.2.2)
	// OIDE2EMMSContextT100 is the application-context-name IEC TS
	// 62351-100-4 Tables 68/69 print (register item R-02). It is only
	// accepted by a server whose policy enables AcceptT100AppContext.
	OIDE2EMMSContextT100 = asn1.OID{1, 0, 62351, 4, 1, 2, 1, 1}

	oidRSAEncryption   = asn1.OID{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.OID{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256 = asn1.OID{1, 2, 840, 10045, 4, 3, 2}
	oidHMACWithSHA256  = asn1.OID{1, 2, 840, 113549, 2, 9}
	oidSHA256          = asn1.OID{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidAES128CBC       = asn1.OID{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES256CBC       = asn1.OID{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128GCM       = asn1.OID{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES256GCM       = asn1.OID{2, 16, 840, 1, 101, 3, 4, 1, 46}
	// id-aes128-GMAC and id-aes256-GMAC (RFC 9044), the ICV identifiers
	// of TISSUE 52.
	oidAES128GMAC = asn1.OID{2, 16, 840, 1, 101, 3, 4, 1, 9}
	oidAES256GMAC = asn1.OID{2, 16, 840, 1, 101, 3, 4, 1, 49}
)

var nullParams = []byte{0x05, 0x00}

// AlgorithmIdentifier is an X.509 AlgorithmIdentifier: the algorithm and
// the complete TLV of its parameters (nil when absent).
type AlgorithmIdentifier struct {
	Algorithm  asn1.OID
	Parameters []byte
}

func (a AlgorithmIdentifier) equal(b AlgorithmIdentifier) bool {
	return a.Algorithm.Equal(b.Algorithm) && bytes.Equal(a.Parameters, b.Parameters)
}

// SigAlg is a signature algorithm of IEC 62351-4 8.5.
type SigAlg uint8

const (
	SigRSASHA256   SigAlg = iota + 1 // sha256WithRSAEncryption, PKCS#1 v1.5
	SigECDSASHA256                   // ecdsa-with-SHA256, P-256
)

func (s SigAlg) String() string {
	switch s {
	case SigRSASHA256:
		return "rsa-sha256"
	case SigECDSASHA256:
		return "ecdsa-p256-sha256"
	}
	return fmt.Sprintf("SigAlg(%d)", uint8(s))
}

func (s SigAlg) id() AlgorithmIdentifier {
	if s == SigRSASHA256 {
		return AlgorithmIdentifier{oidSHA256WithRSA, nullParams}
	}
	return AlgorithmIdentifier{oidECDSAWithSHA256, nil}
}

// sigAlgOf maps an AlgorithmIdentifier; RSA accepts NULL or absent
// parameters (register R-18), ECDSA requires them absent.
func sigAlgOf(a AlgorithmIdentifier) (SigAlg, bool) {
	switch {
	case a.Algorithm.Equal(oidSHA256WithRSA) && (a.Parameters == nil || bytes.Equal(a.Parameters, nullParams)):
		return SigRSASHA256, true
	case a.Algorithm.Equal(oidECDSAWithSHA256) && a.Parameters == nil:
		return SigECDSASHA256, true
	}
	return 0, false
}

// sigAlgFor chooses the signature algorithm a key signs with.
func sigAlgFor(pub crypto.PublicKey) (SigAlg, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return SigRSASHA256, nil
	case *ecdsa.PublicKey:
		return SigECDSASHA256, nil
	}
	return 0, fmt.Errorf("e2e: unsupported signing key %T", pub)
}

// sign signs msg; ECDSA signatures are the DER Ecdsa-Sig-Value (R-14).
func sign(s crypto.Signer, alg SigAlg, rnd io.Reader, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	return s.Sign(rnd, h[:], crypto.SHA256)
}

var errBadSignature = errors.New("e2e: signature verification failed")

func verify(pub crypto.PublicKey, alg SigAlg, msg, sig []byte) error {
	h := sha256.Sum256(msg)
	switch alg {
	case SigRSASHA256:
		k, ok := pub.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) != nil {
			return errBadSignature
		}
	case SigECDSASHA256:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || !ecdsa.VerifyASN1(k, h[:], sig) {
			return errBadSignature
		}
	default:
		return errBadSignature
	}
	return nil
}

// Group is a Diffie-Hellman group, numbered as IEC 62351-4 13.3.1.2 and
// IEC TS 62351-100-4 Table 55 number them (register R-22): these are
// protocol code points, not IKE registry values.
type Group int

const (
	GroupMODP2048 Group = 14 // RFC 3526
	GroupP256     Group = 23 // secp256r1
	GroupBP256    Group = 28 // brainpoolP256r1, not supported
)

func (g Group) kind() (dh.Kind, bool) {
	switch g {
	case GroupMODP2048:
		return dh.MODP2048, true
	case GroupP256:
		return dh.P256, true
	}
	return 0, false
}

func (g Group) String() string {
	switch g {
	case GroupMODP2048:
		return "modp2048"
	case GroupP256:
		return "secp256r1"
	case GroupBP256:
		return "brainpoolP256r1"
	}
	return fmt.Sprintf("group-%d", int(g))
}

// ICVAlg is an integrity check value algorithm of IEC 62351-4 8.8 / 8.7.
type ICVAlg uint8

const (
	ICVHMACSHA256 ICVAlg = iota + 1 // hmacWithSHA256
	ICVGMACAES128                   // aes128-GMAC (aes128-GCM before TISSUE 52)
	ICVGMACAES256                   // aes256-GMAC (aes256-GCM before TISSUE 52)
)

func (a ICVAlg) String() string {
	switch a {
	case ICVHMACSHA256:
		return "hmac-sha256"
	case ICVGMACAES128:
		return "aes128-gmac"
	case ICVGMACAES256:
		return "aes256-gmac"
	}
	return fmt.Sprintf("ICVAlg(%d)", uint8(a))
}

// id is the identifier before TISSUE 52 (aesNNN-GCM for GMAC).
func (a ICVAlg) id() AlgorithmIdentifier { return a.idFor(false) }

// idFor is the identifier to send; tissue52 selects id-aesNNN-GMAC.
func (a ICVAlg) idFor(tissue52 bool) AlgorithmIdentifier {
	switch a {
	case ICVHMACSHA256:
		return AlgorithmIdentifier{oidHMACWithSHA256, nullParams}
	case ICVGMACAES128:
		if tissue52 {
			return AlgorithmIdentifier{oidAES128GMAC, nil}
		}
		return AlgorithmIdentifier{oidAES128GCM, nil}
	}
	if tissue52 {
		return AlgorithmIdentifier{oidAES256GMAC, nil}
	}
	return AlgorithmIdentifier{oidAES256GCM, nil}
}

func (a ICVAlg) keyLen() int {
	switch a {
	case ICVGMACAES128:
		return 16
	}
	return 32
}

// gmacTagLen is the AES-GCM-ICVlen default of IEC 62351-4 8.7.
const gmacTagLen = 12

// icvAlgOf maps an AlgorithmIdentifier. GMAC parameters, when present, are
// GCMParameters; only the default ICV length of 12 is accepted. Both the
// GMAC identifiers of TISSUE 52 and the earlier GCM ones are recognised.
func icvAlgOf(a AlgorithmIdentifier) (ICVAlg, bool) {
	switch {
	case a.Algorithm.Equal(oidHMACWithSHA256) && (a.Parameters == nil || bytes.Equal(a.Parameters, nullParams)):
		return ICVHMACSHA256, true
	case (a.Algorithm.Equal(oidAES128GMAC) || a.Algorithm.Equal(oidAES128GCM)) && gcmParamsOK(a.Parameters):
		return ICVGMACAES128, true
	case (a.Algorithm.Equal(oidAES256GMAC) || a.Algorithm.Equal(oidAES256GCM)) && gcmParamsOK(a.Parameters):
		return ICVGMACAES256, true
	}
	return 0, false
}

func gcmParamsOK(p []byte) bool {
	if p == nil {
		return true
	}
	content, err := asn1.NewDecoder(p).Expect(asn1.TagSequence)
	if err != nil {
		return false
	}
	d := asn1.NewDecoder(content)
	if _, err := d.Expect(asn1.TagOctetString); err != nil {
		return false
	}
	if d.More() {
		v, err := d.Expect(asn1.TagInteger)
		if err != nil || d.More() {
			return false
		}
		n, err := asn1.DecodeInt(v)
		if err != nil || n != gmacTagLen {
			return false
		}
	}
	return true
}

// CipherAlg is a symmetric encryption algorithm of IEC 62351-4 8.6.
// Encryption is not enabled in this release (implementation plan WP9); the
// type exists so proposals can be recognised and refused precisely.
type CipherAlg uint8

const (
	CipherAES128CBC CipherAlg = iota + 1
	CipherAES256CBC
)

func cipherAlgOf(a AlgorithmIdentifier) (CipherAlg, bool) {
	switch {
	case a.Algorithm.Equal(oidAES128CBC):
		return CipherAES128CBC, true
	case a.Algorithm.Equal(oidAES256CBC):
		return CipherAES256CBC, true
	}
	return 0, false
}

// computeICV computes the ICV of msg; nonce is used by GMAC only.
func computeICV(alg ICVAlg, key, nonce, msg []byte) ([]byte, error) {
	switch alg {
	case ICVHMACSHA256:
		m := hmac.New(sha256.New, key)
		m.Write(msg)
		return m.Sum(nil), nil
	case ICVGMACAES128, ICVGMACAES256:
		b, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		g, err := cipher.NewGCMWithTagSize(b, gmacTagLen)
		if err != nil {
			return nil, err
		}
		if len(nonce) != g.NonceSize() {
			return nil, fmt.Errorf("e2e: GMAC nonce of %d octets", len(nonce))
		}
		return g.Seal(nil, nonce, nil, msg), nil
	}
	return nil, fmt.Errorf("e2e: ICV algorithm %v", alg)
}

func newNonce(rnd io.Reader) ([]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	n := make([]byte, 12)
	_, err := io.ReadFull(rnd, n)
	return n, err
}

// hmacAlgOK reports whether a is the HKDF selector this implementation
// supports: hmacWithSHA256, or id-sha256 when allowed (register R-15).
func hmacAlgOK(a AlgorithmIdentifier, allowSHA256 bool) bool {
	if a.Algorithm.Equal(oidHMACWithSHA256) && (a.Parameters == nil || bytes.Equal(a.Parameters, nullParams)) {
		return true
	}
	return allowSHA256 && a.Algorithm.Equal(oidSHA256)
}

var hmacSHA256ID = AlgorithmIdentifier{oidHMACWithSHA256, nullParams}
