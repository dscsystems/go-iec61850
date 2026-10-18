package pki

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

// TrustStore is a set of trust anchors that can be replaced atomically
// while in use: each validation takes a snapshot, so an association keeps
// the anchors it was validated against (IEC 62351-4 6.2.5 requires at least
// two anchors to be supported; any number is).
type TrustStore struct {
	pool atomic.Pointer[x509.CertPool]
	n    atomic.Int32
}

// NewTrustStore returns a store holding anchors.
func NewTrustStore(anchors ...*x509.Certificate) *TrustStore {
	t := &TrustStore{}
	t.Replace(anchors...)
	return t
}

// Replace swaps the anchors.
func (t *TrustStore) Replace(anchors ...*x509.Certificate) {
	p := x509.NewCertPool()
	for _, a := range anchors {
		p.AddCert(a)
	}
	t.pool.Store(p)
	t.n.Store(int32(len(anchors)))
}

// Len is the number of anchors.
func (t *TrustStore) Len() int { return int(t.n.Load()) }

func (t *TrustStore) snapshot() *x509.CertPool { return t.pool.Load() }

// RevocationStatus is the result of a revocation check of one certificate.
type RevocationStatus uint8

const (
	// Good: a current CRL of the issuer covers the certificate and does
	// not list it.
	Good RevocationStatus = iota
	// Revoked: listed by a CRL its issuer signed.
	Revoked
	// Unknown: no CRL of the issuer is configured.
	Unknown
	// Unavailable: the issuer's CRLs are past their next update, carry
	// none, are not yet valid, or were not signed by the issuer.
	Unavailable
)

func (s RevocationStatus) String() string {
	return [...]string{"good", "revoked", "unknown", "unavailable"}[s]
}

// UnavailablePolicy decides what an Unknown or Unavailable status does.
type UnavailablePolicy uint8

const (
	// Warn accepts the certificate and reports the condition: IEC 62351-4
	// 6.2.7 requires that unavailable revocation information does not
	// terminate the session. The default.
	Warn UnavailablePolicy = iota
	// FailClosed refuses the certificate.
	FailClosed
)

// RevocationChecker holds CRLs and answers revocation queries. CRLs are
// supplied (and refreshed) by the application through Set, never fetched
// during a handshake.
type RevocationChecker struct {
	mu       sync.RWMutex
	crls     []*x509.RevocationList
	Policy   UnavailablePolicy
	loadedAt time.Time
}

// NewRevocationChecker returns a checker holding crls.
func NewRevocationChecker(policy UnavailablePolicy, crls ...*x509.RevocationList) *RevocationChecker {
	r := &RevocationChecker{Policy: policy}
	r.Set(crls...)
	return r
}

// Set replaces the CRLs (a refresh).
func (r *RevocationChecker) Set(crls ...*x509.RevocationList) {
	r.mu.Lock()
	r.crls = append([]*x509.RevocationList(nil), crls...)
	r.loadedAt = time.Now()
	r.mu.Unlock()
}

// LoadedAt is when the CRLs were last set.
func (r *RevocationChecker) LoadedAt() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loadedAt
}

// Status checks c, issued by issuer, at time now.
func (r *RevocationChecker) Status(c, issuer *x509.Certificate, now time.Time) RevocationStatus {
	if r == nil {
		return Unknown
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	status := Unknown
	for _, crl := range r.crls {
		if !bytes.Equal(crl.RawIssuer, c.RawIssuer) {
			continue
		}
		if crl.CheckSignatureFrom(issuer) != nil {
			// A CRL under the issuer's name it did not sign: coverage was
			// meant but cannot be trusted.
			if status == Unknown {
				status = Unavailable
			}
			continue
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(c.SerialNumber) == 0 {
				return Revoked
			}
		}
		if crl.NextUpdate.IsZero() || now.After(crl.NextUpdate) || now.Before(crl.ThisUpdate) {
			if status == Unknown {
				status = Unavailable
			}
			continue
		}
		status = Good
	}
	return status
}

// PathOptions configures Verify.
type PathOptions struct {
	Roots         *TrustStore
	Intermediates [][]byte // DER CA certificates, in any order
	Revocation    *RevocationChecker
	Now           time.Time
	// MaxIntermediates bounds the path supplied by the peer (default 4).
	MaxIntermediates int
	// OnStatus, when set, is told of every non-Good revocation status
	// accepted under the Warn policy, so it can raise a security event.
	OnStatus func(c *x509.Certificate, s RevocationStatus)
}

// Verify validates leaf against the trust store: chain, validity at Now,
// and revocation of every certificate of the chain. It returns the verified
// chain, leaf first.
func Verify(leaf *Certificate, o PathOptions) ([]*x509.Certificate, error) {
	if o.Roots == nil {
		return nil, fmt.Errorf("%w: no trust anchors", ErrPath)
	}
	max := o.MaxIntermediates
	if max == 0 {
		max = 4
	}
	if len(o.Intermediates) > max {
		return nil, fmt.Errorf("%w: %d CA certificates exceed the limit of %d", ErrPath, len(o.Intermediates), max)
	}
	now := o.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, ErrExpired
	}
	inter := x509.NewCertPool()
	for _, der := range o.Intermediates {
		c, err := ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPath, err)
		}
		inter.AddCert(c.Certificate)
	}
	chains, err := leaf.Certificate.Verify(x509.VerifyOptions{
		Roots:         o.Roots.snapshot(),
		Intermediates: inter,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var inv x509.CertificateInvalidError
		if errors.As(err, &inv) && inv.Reason == x509.Expired {
			return nil, fmt.Errorf("%w: %v", ErrExpired, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrPath, err)
	}
	var lastErr error
	for _, chain := range chains {
		if lastErr = checkChainRevocation(chain, o, now); lastErr == nil {
			return chain, nil
		}
	}
	return nil, lastErr
}

func checkChainRevocation(chain []*x509.Certificate, o PathOptions, now time.Time) error {
	for i := 0; i+1 < len(chain); i++ {
		s := o.Revocation.Status(chain[i], chain[i+1], now)
		switch s {
		case Good:
		case Revoked:
			return fmt.Errorf("%w: serial %s", ErrRevoked, chain[i].SerialNumber)
		default:
			if o.Revocation != nil && o.Revocation.Policy == FailClosed {
				return fmt.Errorf("%w: %s", ErrRevocationState, s)
			}
			if o.OnStatus != nil && o.Revocation != nil {
				o.OnStatus(chain[i], s)
			}
		}
	}
	return nil
}

// AETitleOID forms the AE-title object identifier from an AP-title and an
// AE-qualifier (IEC 62351-4 10.5.3 NOTE 1).
func AETitleOID(apTitle asn1.OID, aeQualifier int32) asn1.OID {
	out := append(asn1.OID(nil), apTitle...)
	return append(out, uint32(aeQualifier))
}

// CheckIdentity verifies the certificate subject is the AE-title object
// identifier want (IEC 62351-4 G.6.2). attrType, when non-nil, pins the
// attribute type too.
func CheckIdentity(c *Certificate, want asn1.OID, attrType asn1.OID) error {
	if c.SubjectOID == nil {
		return ErrNoAEIdentity
	}
	if attrType != nil && !c.SubjectOIDType.Equal(attrType) {
		return fmt.Errorf("%w: attribute type %s", ErrIdentity, c.SubjectOIDType)
	}
	if !c.SubjectOID.Equal(want) {
		return fmt.Errorf("%w: subject %s, peer %s", ErrIdentity, c.SubjectOID, want)
	}
	return nil
}
