// Package aprofile implements the A-security profile of IEC 62351-4
// (clause 11, Annex A), which the 2018 edition calls compatibility mode and
// IEC TS 62351-4:2007 defined: peer authentication carried in the ACSE
// AARQ and AARE. Each side sends its certificate, the current time and an
// RSA signature over that time; the receiver checks the certificate, that
// the time is within 10 minutes of its own clock, that it has not seen the
// same time from the same certificate within those 10 minutes, and the
// signature.
//
// The profile authenticates the association; it encrypts nothing. Under
// the standard it runs over TLS (IEC 62351-3), which provides the
// confidentiality and integrity of the data.
package aprofile

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
)

// Mechanism is the mechanism-name of the profile, version1-mechanism
// {iso(1) standard(0) iec62351(62351) part4(4) auth-mechanism(3) 1}
// (11.1.4.3).
var Mechanism = asn1.OID{1, 0, 62351, 4, 3, 1}

// LegacyMechanism is the object identifier some IEC TS 62351-4:2007
// implementations send instead (11.1.4.3 notes it is not a legal one).
var LegacyMechanism = asn1.OID{1, 0, 840, 0, 1, 0, 1, 1}

// MaxClockSkew is the largest difference accepted between a peer's time
// and the local clock, and how long a time value is remembered against
// replay (11.2.3.2 d) and e)).
const MaxClockSkew = 10 * time.Minute

// timeLayout is the GeneralizedTime of the profile: UTC, one-second
// accuracy, concluded by Z (11.2.2 b)).
const timeLayout = "20060102150405Z"

// Errors of verification; each one aborts the association.
var (
	ErrMalformed   = errors.New("aprofile: malformed authentication value")
	ErrCertificate = errors.New("aprofile: certificate not valid")
	ErrTime        = errors.New("aprofile: time more than 10 minutes from the local clock")
	ErrReplay      = errors.New("aprofile: time value replayed")
	ErrSignature   = errors.New("aprofile: signature invalid")
)

// Value is an MMS-Authentication-value, certificate-based alternative.
type Value struct {
	Certificate []byte // DER
	Time        []byte // GeneralizedTime content octets, e.g. "20261012213000Z"
	Signature   []byte // RSASSA-PKCS1-v1_5 SHA-256 over Time

	// IndirectReference is the presentation-context-identifier of the
	// EXTERNAL; HasIndirectReference is false when it is absent, which is
	// what current implementations send (11.1.4.4).
	IndirectReference    int
	HasIndirectReference bool
}

// Encode returns the Authentication-value (external [2] alternative) to
// carry in calling-authentication-value [12] or
// responding-authentication-value [10]:
//
//	[2] IMPLICIT SEQUENCE { indirect-reference INTEGER OPTIONAL,
//	  single-ASN1-type [0] MMS-Authentication-value }
//	MMS-Authentication-value ::= CHOICE { certificate-based [0] IMPLICIT
//	  SEQUENCE { [0] OCTET STRING, [1] GeneralizedTime, [2] OCTET STRING } }
func (v *Value) Encode() []byte {
	ext := asn1.Cons(asn1.ContextConstructed(2))
	if v.HasIndirectReference {
		ext.Add(asn1.IntElem(asn1.TagInteger, int64(v.IndirectReference)))
	}
	ext.Add(asn1.Cons(asn1.ContextConstructed(0),
		asn1.Cons(asn1.ContextConstructed(0),
			asn1.Prim(asn1.ContextPrimitive(0), v.Certificate),
			asn1.Prim(asn1.ContextPrimitive(1), v.Time),
			asn1.Prim(asn1.ContextPrimitive(2), v.Signature))))
	return ext.Encode()
}

// IsValue reports whether an Authentication-value is the external
// alternative this profile uses, as opposed to a password (charstring).
func IsValue(authValue []byte) bool {
	return asn1.NewDecoder(authValue).PeekIs(asn1.ContextConstructed(2))
}

// Parse decodes an Authentication-value. It is tolerant where 11.1.4.4
// asks for tolerance: the indirect reference may be absent, and so may the
// single-ASN1-type wrapper.
func Parse(authValue []byte) (*Value, error) {
	ext, err := asn1.NewDecoder(authValue).Expect(asn1.ContextConstructed(2))
	if err != nil {
		return nil, fmt.Errorf("%w: not the external alternative", ErrMalformed)
	}
	v := &Value{}
	d := asn1.NewDecoder(ext)
	if d.PeekIs(asn1.TagInteger) {
		c, _ := d.Expect(asn1.TagInteger)
		n, err := asn1.DecodeInt(c)
		if err != nil {
			return nil, fmt.Errorf("%w: indirect-reference", ErrMalformed)
		}
		v.IndirectReference, v.HasIndirectReference = int(n), true
	}
	body, err := d.Expect(asn1.ContextConstructed(0)) // single-ASN1-type
	if err != nil {
		return nil, fmt.Errorf("%w: no single-ASN1-type", ErrMalformed)
	}
	// certificate-based [0]; without the single-ASN1-type wrapper body is
	// already its content.
	if inner := asn1.NewDecoder(body); inner.PeekIs(asn1.ContextConstructed(0)) {
		if body, err = inner.Expect(asn1.ContextConstructed(0)); err != nil {
			return nil, fmt.Errorf("%w: certificate-based", ErrMalformed)
		}
	}
	f := asn1.NewDecoder(body)
	for f.More() {
		t, c, err := f.ReadTLV()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
		}
		switch t {
		case asn1.ContextPrimitive(0):
			v.Certificate = c
		case asn1.ContextPrimitive(1):
			v.Time = c
		case asn1.ContextPrimitive(2):
			v.Signature = c
		}
	}
	if v.Certificate == nil || v.Time == nil || v.Signature == nil {
		return nil, fmt.Errorf("%w: certificate, time or signature missing", ErrMalformed)
	}
	return v, nil
}

// Credential is this end's certificate and RSA private key.
type Credential struct {
	Certificate []byte // DER
	Signer      crypto.Signer
}

// Sign builds an authentication value for time now.
func (c Credential) Sign(now time.Time) (*Value, error) {
	if _, ok := c.Signer.Public().(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("aprofile: the profile signs with RSA, not %T", c.Signer.Public())
	}
	tm := []byte(now.UTC().Format(timeLayout))
	h := sha256.Sum256(tm)
	sig, err := c.Signer.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("aprofile: signing: %w", err)
	}
	return &Value{Certificate: c.Certificate, Time: tm, Signature: sig}, nil
}

// Verifier checks the authentication values of peers. One Verifier should
// serve every association of an endpoint, so its replay cache sees them
// all.
type Verifier struct {
	Trust      *pki.TrustStore
	Revocation *pki.RevocationChecker // nil: no revocation checks
	// Intermediates are CA certificates (DER) completing peers' paths.
	Intermediates [][]byte
	// Now overrides the clock (tests).
	Now func() time.Time

	mu   sync.Mutex
	seen map[[32]byte]map[string]time.Time // certificate hash -> time value -> when seen
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify checks val against 11.2.3.2 c) to f) and returns the peer's
// certificate. The replay check comes last, after the signature, so only
// authentic values are recorded.
//
// The time value has one-second resolution (11.2.3.2), so a second
// association from the same certificate within the same second is refused
// as a replay; a client retrying must wait for the next second. Verify
// does not bind the certificate to the peer's AE title: an application
// that authorizes by identity checks the returned certificate's subject
// itself.
func (v *Verifier) Verify(val *Value) (*pki.Certificate, error) {
	now := v.now()
	cert, err := pki.ParseCertificate(val.Certificate)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	if _, err := pki.Verify(cert, pki.PathOptions{Roots: v.Trust, Intermediates: v.Intermediates,
		Revocation: v.Revocation, Now: now}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("%w: the profile requires an RSA key of at least 2048 bits", ErrCertificate)
	}
	t, err := parseTime(val.Time)
	if err != nil {
		return nil, err
	}
	if d := now.Sub(t); d > MaxClockSkew || d < -MaxClockSkew {
		return nil, fmt.Errorf("%w: %s, local %s", ErrTime, val.Time, now.UTC().Format(timeLayout))
	}
	// The signature is checked before the time value is recorded: a forged
	// value would otherwise take the genuine peer's time value and have its
	// own association refused as a replay.
	h := sha256.Sum256(val.Time)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], val.Signature); err != nil {
		return nil, ErrSignature
	}
	if err := v.remember(val, now); err != nil {
		return nil, err
	}
	return cert, nil
}

// remember records the time value against the certificate, refusing one
// already seen within MaxClockSkew.
func (v *Verifier) remember(val *Value, now time.Time) error {
	key := sha256.Sum256(val.Certificate)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[[32]byte]map[string]time.Time{}
	}
	for k, times := range v.seen {
		for tv, at := range times {
			if now.Sub(at) > MaxClockSkew {
				delete(times, tv)
			}
		}
		if len(times) == 0 {
			delete(v.seen, k)
		}
	}
	times := v.seen[key]
	if _, dup := times[string(val.Time)]; dup {
		return fmt.Errorf("%w: %s", ErrReplay, val.Time)
	}
	if times == nil {
		times = map[string]time.Time{}
		v.seen[key] = times
	}
	times[string(val.Time)] = now
	return nil
}

// parseTime accepts the profile's format and, tolerantly, fractional
// seconds.
func parseTime(b []byte) (time.Time, error) {
	for _, layout := range []string{timeLayout, "20060102150405.999999999Z"} {
		if t, err := time.Parse(layout, string(b)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: time %q", ErrMalformed, b)
}

// Config is one end's A-profile configuration.
type Config struct {
	Credential Credential
	Verifier   *Verifier
	// Mechanism is the mechanism-name sent; nil sends Mechanism. Received
	// names are not checked (11.1.4.3 asks for tolerance).
	Mechanism asn1.OID
	// IndirectReference, when non-zero, is sent as the EXTERNAL's
	// indirect-reference.
	IndirectReference int
	// AllowWithoutTLS permits the profile on a plain TCP connection. The
	// standard requires TLS beneath it (7.1 a)): without it the association
	// is authenticated but nothing protects the data after it. For lab
	// devices only.
	AllowWithoutTLS bool
}

// MechanismName returns the mechanism-name to send.
func (c *Config) MechanismName() asn1.OID {
	if c.Mechanism != nil {
		return c.Mechanism
	}
	return Mechanism
}

// Value signs a fresh authentication value.
func (c *Config) Value() (*Value, error) {
	now := time.Now()
	if c.Verifier != nil {
		now = c.Verifier.now()
	}
	v, err := c.Credential.Sign(now)
	if err != nil {
		return nil, err
	}
	if c.IndirectReference != 0 {
		v.IndirectReference, v.HasIndirectReference = c.IndirectReference, true
	}
	return v, nil
}

// Validate checks the configuration is usable.
func (c *Config) Validate() error {
	if len(c.Credential.Certificate) == 0 || c.Credential.Signer == nil {
		return errors.New("aprofile: a certificate and private key are required")
	}
	if _, ok := c.Credential.Signer.Public().(*rsa.PublicKey); !ok {
		return errors.New("aprofile: the private key must be RSA (sha256WithRSAEncryption)")
	}
	if c.Verifier == nil || c.Verifier.Trust == nil || c.Verifier.Trust.Len() == 0 {
		return errors.New("aprofile: trust anchors are required to verify the peer")
	}
	return nil
}
