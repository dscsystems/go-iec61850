// Package e2e implements the end-to-end application security of IEC
// 62351-4:2018+AMD1:2020 (clauses 12 to 14): the signed handshake with
// Diffie-Hellman key agreement, integrity-protected data transfer,
// rekeying, signed release and the security aborts.
//
// The package is independent of the operational environment and of the
// protected protocol. The OSI mapping (clause 15) is in package
// e2e/osi; the MMS stack of this module and other ISO stacks drive an
// Association through it.
//
// Scope of this release (see docs/iec62351-4-implementation-guide.md):
// native mode, clear data transfer with HMAC-SHA-256 or AES-GMAC integrity,
// RSA (>= 2048) and ECDSA P-256 signatures, Diffie-Hellman groups 14 and 23.
// Encryption (AES-CBC, AES-GCM authenticated encryption) and brainpool
// keys are not supported and are refused with the matching diagnostics.
package e2e

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
)

// ProtocolIEC61850 and ProtocolTASE2 are the protected-protocol
// identifiers of IEC 62351-4 13.1.3 a).
const (
	ProtocolIEC61850 = "IEC 61850-8-1"
	ProtocolTASE2    = "IEC 60870-6-503"
)

// AETitle is an OSI application-entity title in form 2: an AP-title object
// identifier and an AE-qualifier. Their concatenation is the object
// identifier an E2E certificate names (IEC 62351-4 10.5.3, G.6.2).
type AETitle struct {
	APTitle     asn1.OID
	AEQualifier int32
}

// OID returns APTitle || AEQualifier.
func (t AETitle) OID() asn1.OID { return pki.AETitleOID(t.APTitle, t.AEQualifier) }

// IsZero reports an unset title.
func (t AETitle) IsZero() bool { return len(t.APTitle) == 0 }

func (t AETitle) String() string {
	if t.IsZero() {
		return ""
	}
	return t.OID().String()
}

// Identity is this end's E2E credential.
type Identity struct {
	AE AETitle
	// Certificate is the DER end-entity certificate (at most 8192 octets).
	// It must be different from any TLS certificate (IEC 62351-4 G.2).
	Certificate []byte
	// Path holds the DER CA certificates the peer needs, top-down: the
	// first is signed by a trust anchor, the last issued Certificate
	// (13.3.1.5). Empty when Certificate is issued by an anchor.
	Path [][]byte
	// Signer is the private key: RSA >= 2048 or ECDSA P-256.
	Signer crypto.Signer
}

// EncryptionPolicy is whether E2E encryption is used. Only Forbid is
// supported by this release.
type EncryptionPolicy uint8

const (
	EncryptionForbid EncryptionPolicy = iota
	EncryptionOptional
	EncryptionRequire
)

// AlarmDiagnostic selects what is sent in place of a diagnostic when an
// alarm is raised (register R-07).
type AlarmDiagnostic uint8

const (
	// AlarmOmitDiagnostic leaves diag absent, as IEC 62351-4 14.3.1
	// requires. The default.
	AlarmOmitDiagnostic AlarmDiagnostic = iota
	// AlarmNoReasonGiven sends no-reason-given, as several tables of IEC TS
	// 62351-100-4 expect. For test campaigns.
	AlarmNoReasonGiven
)

// ChainInit is the representation of the initial hash-chain value h0 of
// the key derivation (13.3.1.3, register R-12).
type ChainInit uint8

const (
	// ChainZeroOctet uses a single 0x00 octet. The default until the
	// register item is closed with a reference vector.
	ChainZeroOctet ChainInit = iota
	// ChainEmpty uses no octets.
	ChainEmpty
	// ChainZeroHash uses as many zero octets as the hash output.
	ChainZeroHash
)

// Policy holds the security choices shared by clients and servers.
type Policy struct {
	// Trust holds the trust anchors of E2E certificates. Required.
	Trust *pki.TrustStore
	// Revocation holds CRLs; nil means no revocation information, which the
	// pki.Warn semantics report but accept.
	Revocation *pki.RevocationChecker
	// MaxCertPath bounds the CA certificates a peer may send (default 4).
	MaxCertPath int
	// AEAttributeType pins the subject attribute type of peer certificates;
	// nil means pki.AEAttributeType (X.520 objectIdentifier, 2.5.4.106).
	AEAttributeType asn1.OID
	// AcceptAnyAEAttributeType accepts any single attribute with an OBJECT
	// IDENTIFIER value, for certificates issued before the attribute type
	// was settled (register R-25).
	AcceptAnyAEAttributeType bool

	// DHGroups: for a client the group proposed (the first); for a server
	// the groups accepted. Default {GroupP256, GroupMODP2048}.
	DHGroups []Group
	// ICVAlgs: for a client the proposal in preference order; for a server
	// the algorithms accepted. Default {ICVHMACSHA256, ICVGMACAES128,
	// ICVGMACAES256}.
	ICVAlgs []ICVAlg
	// Encryption: only EncryptionForbid is supported.
	Encryption EncryptionPolicy

	// Freshness is the accepted clock difference (at most and by default
	// 10 minutes, 14.3.4 f), 14.4.3 a)).
	Freshness time.Duration
	// RekeyInterval is the longest time a client uses one set of keys
	// (15 min to 24 h, default 1 h; 13.3.2 f)).
	RekeyInterval time.Duration
	// RekeyRequest, on a server, sets reqRekey after this long on one set
	// of keys; zero never requests.
	RekeyRequest time.Duration
	// MaxMessagesPerKey forces a rekey after this many messages under one
	// key (default 2^30).
	MaxMessagesPerKey uint64

	AlarmDiagnostic AlarmDiagnostic
	// T100Diagnostics selects the diagnostics IEC TS 62351-100-4 expects
	// where they differ from IEC 62351-4 (register R-07): Tables 49 #11,
	// 50 #12 and 54 #7.
	T100Diagnostics bool
	// Authenticator selects the Authenticator encoding (register R-04).
	Authenticator AuthenticatorTagging
	// AcceptSHA256HMACID accepts id-sha256 in the hmac field (R-15).
	AcceptSHA256HMACID bool
	// AcceptUnverifiedAttributeCertificates ignores a received attCert in
	// every case (attribute certificates are not validated).
	AcceptUnverifiedAttributeCertificates bool
	// RequireAuthorization means authorization is configured (TISSUE 97):
	// a received attribute certificate must then be validated, and as
	// IEC 62351-8 is not implemented it is refused. Without it, an
	// attribute certificate is ignored.
	RequireAuthorization bool
	// Corrections selects the published corrections applied to
	// Edition2020; the default is the TISSUEs in force.
	Corrections Corrections
	// HKDFInit is the representation of h0 (R-12).
	HKDFInit ChainInit
	// Edition selects the wire format: Edition2020 (IEC 62351-4:2018+AMD1:2020,
	// the default) or Edition2018 for peers built on the first edition. Both
	// ends must use the same edition.
	Edition Edition
}

func (p *Policy) withDefaults() Policy {
	q := *p
	if q.MaxCertPath == 0 {
		q.MaxCertPath = 4
	}
	if q.AEAttributeType == nil && !q.AcceptAnyAEAttributeType {
		q.AEAttributeType = pki.AEAttributeType
	}
	if q.AcceptAnyAEAttributeType {
		q.AEAttributeType = nil
	}
	if len(q.DHGroups) == 0 {
		q.DHGroups = []Group{GroupP256, GroupMODP2048}
	}
	if len(q.ICVAlgs) == 0 {
		q.ICVAlgs = []ICVAlg{ICVHMACSHA256, ICVGMACAES128, ICVGMACAES256}
	}
	if q.Freshness == 0 {
		q.Freshness = 10 * time.Minute
	}
	if q.RekeyInterval == 0 {
		q.RekeyInterval = time.Hour
	}
	if q.MaxMessagesPerKey == 0 {
		q.MaxMessagesPerKey = 1 << 30
	}
	return q
}

func (p *Policy) validate() error {
	if p.Trust == nil || p.Trust.Len() == 0 {
		return errors.New("e2e: Policy.Trust must hold at least one trust anchor")
	}
	if p.Encryption != EncryptionForbid {
		return errors.New("e2e: E2E encryption is not supported by this release")
	}
	if p.Freshness <= 0 || p.Freshness > 10*time.Minute {
		return fmt.Errorf("e2e: Freshness %v outside (0, 10m]", p.Freshness)
	}
	if p.RekeyInterval < 15*time.Minute || p.RekeyInterval > 24*time.Hour {
		return fmt.Errorf("e2e: RekeyInterval %v outside 15m..24h", p.RekeyInterval)
	}
	for _, g := range p.DHGroups {
		if _, ok := g.kind(); !ok {
			return fmt.Errorf("e2e: Diffie-Hellman group %v not supported", g)
		}
	}
	for _, a := range p.ICVAlgs {
		if a < ICVHMACSHA256 || a > ICVGMACAES256 {
			return fmt.Errorf("e2e: ICV algorithm %v not supported", a)
		}
	}
	return nil
}

// common holds what both roles share.
type common struct {
	Local   Identity
	Policy  Policy
	Clock   func() time.Time
	Rand    io.Reader
	OnEvent func(Event)
}

// ClientConfig configures the client role. A ClientConfig may be shared by
// many associations; it must not be modified after first use.
type ClientConfig struct {
	Local  Identity
	Policy Policy
	// Peer is the called AE title; the server certificate must name it.
	Peer AETitle
	// Protocol is the protected protocol identifier, e.g. ProtocolIEC61850.
	Protocol string
	// TLSProtected sets the tlsProtected bit of confParams.
	TLSProtected bool
	Clock        func() time.Time
	Rand         io.Reader
	OnEvent      func(Event)

	once  sync.Once
	state *sharedState
	err   error
}

// ServerConfig configures the server role. It may be shared by many
// associations; it must not be modified after first use.
type ServerConfig struct {
	Local  Identity
	Policy Policy
	// Protocols are the protected protocols accepted.
	Protocols []string
	// AcceptT100AppContext also accepts the application-context-name of
	// IEC TS 62351-100-4 Tables 68/69 (register R-02).
	AcceptT100AppContext bool
	Clock                func() time.Time
	Rand                 io.Reader
	OnEvent              func(Event)

	once  sync.Once
	state *sharedState
	err   error
}

// sharedState is the per-configuration state shared by its associations:
// the parsed local credential, the association-identifier allocator and the
// handshake replay cache.
type sharedState struct {
	cert     *pki.Certificate
	sigAlg   SigAlg
	policy   Policy
	replay   *replayCache
	assoIDs  *idAllocator
	clock    func() time.Time
	rnd      io.Reader
	onEvent  func(Event)
	local    Identity
	protocol []string
}

func (c *common) prepare(role string, protocols []string) (*sharedState, error) {
	if c.Local.Signer == nil || len(c.Local.Certificate) == 0 {
		return nil, errors.New("e2e: Local identity needs a certificate and a signer")
	}
	if c.Local.AE.IsZero() || c.Local.AE.AEQualifier < 0 {
		return nil, errors.New("e2e: Local.AE needs an AP-title and a non-negative AE-qualifier")
	}
	pol := c.Policy.withDefaults()
	if err := pol.validate(); err != nil {
		return nil, err
	}
	cert, err := pki.ParseCertificate(c.Local.Certificate)
	if err != nil {
		return nil, fmt.Errorf("e2e: local certificate: %w", err)
	}
	if err := pki.EndEntityProfile(cert); err != nil {
		return nil, fmt.Errorf("e2e: local certificate: %w", err)
	}
	if err := pki.CheckIdentity(cert, c.Local.AE.OID(), nil); err != nil {
		return nil, fmt.Errorf("e2e: local certificate does not name %v: %w", c.Local.AE, err)
	}
	if !publicKeysEqual(cert.PublicKey, c.Local.Signer.Public()) {
		return nil, errors.New("e2e: signer does not match the local certificate")
	}
	alg, err := sigAlgFor(c.Local.Signer.Public())
	if err != nil {
		return nil, err
	}
	clock := c.Clock
	if clock == nil {
		clock = time.Now
	}
	return &sharedState{
		cert: cert, sigAlg: alg, policy: pol,
		replay: newReplayCache(), assoIDs: newIDAllocator(c.Rand),
		clock: clock, rnd: c.Rand, onEvent: c.OnEvent, local: c.Local, protocol: protocols,
	}, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	if ra, ok := a.(*rsa.PublicKey); ok {
		if rb, ok := b.(*rsa.PublicKey); ok {
			return ra.E == rb.E && bytes.Equal(ra.N.Bytes(), rb.N.Bytes())
		}
	}
	return false
}

func (c *ClientConfig) shared() (*sharedState, error) {
	c.once.Do(func() {
		if c.Peer.IsZero() {
			c.err = errors.New("e2e: ClientConfig.Peer (called AE title) is required")
			return
		}
		p := c.Protocol
		if p == "" {
			p = ProtocolIEC61850
		}
		cm := common{Local: c.Local, Policy: c.Policy, Clock: c.Clock, Rand: c.Rand, OnEvent: c.OnEvent}
		c.state, c.err = cm.prepare("client", []string{p})
	})
	return c.state, c.err
}

func (c *ServerConfig) shared() (*sharedState, error) {
	c.once.Do(func() {
		ps := c.Protocols
		if len(ps) == 0 {
			ps = []string{ProtocolIEC61850}
		}
		cm := common{Local: c.Local, Policy: c.Policy, Clock: c.Clock, Rand: c.Rand, OnEvent: c.OnEvent}
		c.state, c.err = cm.prepare("server", ps)
	})
	return c.state, c.err
}

// Validate checks the configuration without starting an association.
func (c *ClientConfig) Validate() error { _, err := c.shared(); return err }

// Validate checks the configuration without starting an association.
func (c *ServerConfig) Validate() error { _, err := c.shared(); return err }

// LocalCertificate returns the parsed local certificate (after Validate).
func (c *ServerConfig) LocalCertificate() *pki.Certificate {
	if s, err := c.shared(); err == nil {
		return s.cert
	}
	return nil
}
