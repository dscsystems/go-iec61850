// Package iec62351 holds the IEC 62351 profiles this module implements:
// the TLS profile of IEC 62351-3 for MMS (the transport security of the
// client and server packages). The IEC 61850-90-5 session security of
// R-GOOSE and R-SV is in package rsession.
package iec62351

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// MMSTLSPort is the port of MMS over TLS (IEC 62351-3, ISO-TSAP over
// TLS).
const MMSTLSPort = 3782

// CipherSuites are the TLS 1.2 cipher suites of the profile: ephemeral
// elliptic-curve key exchange with AES-GCM, the mandatory
// AES-128 suites first. TLS 1.3 suites are not configurable in Go; its
// AES-GCM suites are the ones IEC 62351-3 names.
var CipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
}

// Curves are the key exchange groups offered.
var Curves = []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521}

// MinRSABits is the smallest RSA key accepted from a peer.
const MinRSABits = 2048

// Options configure one end of a TLS connection under the profile.
type Options struct {
	// Certificates is this end's identity. Required: the profile
	// authenticates both ends.
	Certificates []tls.Certificate
	// Roots are the certificate authorities a peer's chain must lead to.
	// Required.
	Roots *x509.CertPool
	// CRLs are checked against every certificate of the peer's chain: one
	// listed by a CRL its issuer signed is refused. A CRL past its next
	// update is itself refused, and so is the connection, unless
	// AllowStaleCRL.
	CRLs          []*x509.RevocationList
	AllowStaleCRL bool
	// AllowedPeers, when not empty, restricts the peers to these
	// certificates exactly (pinning), after the chain checks.
	AllowedPeers []*x509.Certificate
	// ServerName, on a client, is the identity the server's certificate
	// must carry: in a subject alternative name, or, for a certificate
	// that has none (usual for IEDs), as its common name. Empty checks
	// the chain only.
	ServerName string
	// TLS13Only refuses TLS 1.2.
	TLS13Only bool
	// OnEvent is told of every peer refused, for the security event log
	// (IEC 62351-14).
	OnEvent func(Event)
	// Now overrides the clock the certificates and CRLs are checked
	// against (tests).
	Now func() time.Time
}

// Event is a refused peer.
type Event struct {
	Peer *x509.Certificate // the leaf the peer presented, nil if none
	Err  error
}

// Errors of peer verification.
var (
	ErrNoPeerCertificate = errors.New("iec62351: peer presented no certificate")
	ErrRevoked           = errors.New("iec62351: certificate revoked")
	ErrStaleCRL          = errors.New("iec62351: CRL past its next update")
	ErrWeakKey           = errors.New("iec62351: key too weak")
	ErrNotAllowed        = errors.New("iec62351: peer certificate not in the allowed set")
	ErrServerName        = errors.New("iec62351: server certificate does not name the server")
)

// ClientConfig returns the TLS configuration of an MMS client under the
// profile, for client.WithTLS.
func ClientConfig(o Options) (*tls.Config, error) {
	cfg, err := base(o)
	if err != nil {
		return nil, err
	}
	cfg.Renegotiation = tls.RenegotiateNever
	return cfg, nil
}

// ServerConfig returns the TLS configuration of an MMS server under the
// profile, for server.WithTLS: clients must present a certificate, which
// is checked as ClientConfig checks a server's.
func ServerConfig(o Options) (*tls.Config, error) {
	cfg, err := base(o)
	if err != nil {
		return nil, err
	}
	// The verification is VerifyConnection's; asking for the certificate
	// here makes its absence an error before the handshake completes.
	cfg.ClientAuth = tls.RequireAnyClientCert
	// Resumption skips the certificate checks for a connection's lifetime
	// of a ticket; MMS associations are long-lived, so a full handshake
	// each time costs nothing that matters.
	cfg.SessionTicketsDisabled = true
	return cfg, nil
}

func base(o Options) (*tls.Config, error) {
	if len(o.Certificates) == 0 {
		return nil, errors.New("iec62351: Options.Certificates is required")
	}
	if o.Roots == nil {
		return nil, errors.New("iec62351: Options.Roots is required")
	}
	o.CRLs = append([]*x509.RevocationList(nil), o.CRLs...)
	o.AllowedPeers = append([]*x509.Certificate(nil), o.AllowedPeers...)
	min := uint16(tls.VersionTLS12)
	if o.TLS13Only {
		min = tls.VersionTLS13
	}
	return &tls.Config{
		Certificates:     o.Certificates,
		MinVersion:       min,
		CipherSuites:     CipherSuites,
		CurvePreferences: Curves,
		// The chain is verified by VerifyConnection, which checks what
		// the standard library's verification does not (revocation, key
		// strength, pinning) and names the server the way IED
		// certificates do.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			err := o.verify(cs.PeerCertificates)
			if err != nil && o.OnEvent != nil {
				var leaf *x509.Certificate
				if len(cs.PeerCertificates) > 0 {
					leaf = cs.PeerCertificates[0]
				}
				o.OnEvent(Event{Peer: leaf, Err: err})
			}
			return err
		},
	}, nil
}

func (o *Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// verify checks a peer's certificates against the options.
func (o *Options) verify(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return ErrNoPeerCertificate
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         o.Roots,
		Intermediates: inter,
		CurrentTime:   o.now(),
		// IED certificates often carry no extended key usage; one that
		// does is still checked by the library against Any.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("iec62351: %w", err)
	}
	var lastErr error
	for _, chain := range chains {
		if lastErr = o.checkChain(chain); lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		return lastErr
	}
	if o.ServerName != "" && !namesServer(leaf, o.ServerName) {
		return fmt.Errorf("%w: want %q", ErrServerName, o.ServerName)
	}
	if len(o.AllowedPeers) > 0 {
		for _, a := range o.AllowedPeers {
			if bytes.Equal(a.Raw, leaf.Raw) {
				return nil
			}
		}
		return fmt.Errorf("%w: %s", ErrNotAllowed, leaf.Subject)
	}
	return nil
}

// checkChain checks the key strength and revocation of every certificate
// of a verified chain, from the leaf to the root.
func (o *Options) checkChain(chain []*x509.Certificate) error {
	for i, c := range chain {
		if err := checkKey(c); err != nil {
			return err
		}
		if i+1 < len(chain) {
			if err := o.checkRevoked(c, chain[i+1]); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkKey(c *x509.Certificate) error {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return fmt.Errorf("%w: %d-bit RSA in %s", ErrWeakKey, k.N.BitLen(), c.Subject)
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < elliptic.P256().Params().BitSize {
			return fmt.Errorf("%w: %s in %s", ErrWeakKey, k.Curve.Params().Name, c.Subject)
		}
	case ed25519.PublicKey:
	default:
		return fmt.Errorf("%w: %T in %s", ErrWeakKey, k, c.Subject)
	}
	return nil
}

// checkRevoked looks c up in the CRLs its issuer signed.
func (o *Options) checkRevoked(c, issuer *x509.Certificate) error {
	now := o.now()
	for _, crl := range o.CRLs {
		if !bytes.Equal(crl.RawIssuer, c.RawIssuer) || crl.CheckSignatureFrom(issuer) != nil {
			continue
		}
		if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) && !o.AllowStaleCRL {
			return fmt.Errorf("%w: issued by %s, next update %s", ErrStaleCRL, crl.Issuer, crl.NextUpdate.Format(time.RFC3339))
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(c.SerialNumber) == 0 {
				return fmt.Errorf("%w: %s (serial %s)", ErrRevoked, c.Subject, c.SerialNumber)
			}
		}
	}
	return nil
}

// namesServer reports whether the certificate names the server: in its
// subject alternative names when it has any, else in its common name.
func namesServer(c *x509.Certificate, name string) bool {
	if len(c.DNSNames) > 0 || len(c.IPAddresses) > 0 || len(c.URIs) > 0 {
		return c.VerifyHostname(name) == nil
	}
	return c.Subject.CommonName == name
}
