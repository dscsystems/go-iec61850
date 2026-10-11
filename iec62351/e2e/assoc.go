package e2e

import (
	"crypto/hmac"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/internal/cryptox/dh"
)

// Role is the side of an association.
type Role uint8

const (
	RoleClient Role = iota + 1
	RoleServer
)

func (r Role) String() string {
	if r == RoleServer {
		return "server"
	}
	return "client"
}

type assocState uint8

const (
	stIdle assocState = iota
	stRequested
	stEstablished
	stReleasing
	stClosed
)

// PeerSecurity is an immutable description of an authenticated peer. It
// carries no secrets.
type PeerSecurity struct {
	AE             AETitle
	Certificate    *x509.Certificate
	CertificateRaw []byte
	VerifiedChain  []*x509.Certificate
	AssoID         string
	Signature      SigAlg
	Group          Group
	ICV            ICVAlg
	KeyEpoch       uint32
	ValidatedAt    time.Time
}

// direction is the token and key state of one direction.
type direction struct {
	key      []byte
	lastTime time.Time
	lastSeq  int64
	have     bool
	msgs     uint64
}

// Association is one E2E association, driven by the environment. Seal is
// called with the environment's write serialisation; Open from its single
// reader. Both may run concurrently.
type Association struct {
	role  Role
	sh    *sharedState
	pol   *Policy
	ccfg  *ClientConfig
	scfg  *ServerConfig
	mu    sync.Mutex
	state assocState

	peerAE   AETitle // client: expected (called); server: calling
	peerCert *pki.Certificate
	peerKey  string // allocator and replay key of the peer
	peer     PeerSecurity

	assoID     string // full identifier
	clientPart string
	ownPart    string // the part this end allocated

	group      Group
	dhKey      *dh.Key // client: current; server: retained for rekeying
	peerPub    []byte  // server's public value on the client
	icv        ICVAlg
	reqTBS     []byte // client: data1 until the accept
	reqToken   *ClearToken1
	applDataIn []byte // server: ApplData of the request until accepted
	salt       []byte

	tx, rx       direction
	epoch        uint32
	epochStart   time.Time
	rekeyWanted  bool
	rekeyOut     bool      // client: rekey sent, changedKey not yet seen
	rekeyOutAt   time.Time // client: when
	pendingRx    []byte    // client: server key of the new epoch
	pendingTx    []byte    // server: own key of the new epoch
	pendingChg   bool      // server: changedKey to send
	reqRekeySent bool      // server: reqRekey sent this epoch
}

// NewClient prepares a client association.
func NewClient(cfg *ClientConfig) (*Association, error) {
	sh, err := cfg.shared()
	if err != nil {
		return nil, err
	}
	return &Association{role: RoleClient, sh: sh, pol: &sh.policy, ccfg: cfg, peerAE: cfg.Peer,
		peerKey: "s:" + cfg.Peer.String()}, nil
}

// NewServer prepares a server association.
func NewServer(cfg *ServerConfig) (*Association, error) {
	sh, err := cfg.shared()
	if err != nil {
		return nil, err
	}
	return &Association{role: RoleServer, sh: sh, pol: &sh.policy, scfg: cfg}, nil
}

// Role returns the side of the association.
func (a *Association) Role() Role { return a.role }

// Peer returns the authenticated peer, valid once established.
func (a *Association) Peer() PeerSecurity {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.peer
	p.KeyEpoch = a.epoch
	return p
}

// AssoID returns the association identifier.
func (a *Association) AssoID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.assoID
}

// Established reports the data transfer phase.
func (a *Association) Established() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state == stEstablished
}

func (a *Association) now() time.Time { return a.sh.clock() }

func (a *Association) event(code EventCode, class EventClass, diag, detail string) {
	if a.sh.onEvent == nil {
		return
	}
	var sha [32]byte
	if a.peerCert != nil {
		sha = certSHA(a.peerCert.Raw)
	}
	a.sh.onEvent(Event{Time: a.now(), Code: code, Class: class, Role: a.role.String(), AssoID: a.assoID,
		PeerAE: a.peerAE.String(), CertSHA: sha, Diag: diag, Detail: detail})
}

// reportError raises the events for a security error found locally.
func (a *Association) reportError(se *SecurityError) {
	if se.Alarm != AlarmNone {
		a.event(alarmEvent(se.Alarm), ClassAlarm, "", errString(se.Err))
		return
	}
	name := HandshakeDiagName(se.Diag)
	if se.Phase == PhaseData {
		name = DtDiagName(se.Diag)
	}
	a.event(EventDiagnosticSent, ClassWarning, name, errString(se.Err))
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// ---------------------------------------------------------------------
// Handshake

func (a *Association) signFn(tbs []byte) ([]byte, error) {
	return sign(a.sh.local.Signer, a.sh.sigAlg, a.sh.rnd, tbs)
}

func (a *Association) icvIDs() []AlgorithmIdentifier {
	var out []AlgorithmIdentifier
	for _, x := range a.pol.ICVAlgs {
		out = append(out, x.id())
	}
	return out
}

// HandshakeRequest builds the HandshakeReq SecPDU (a SEQUENCE TLV) carrying
// applData, the environment's complete ApplData TLV (13.1.3).
func (a *Association) HandshakeRequest(applData []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.role != RoleClient || a.state != stIdle {
		return nil, errors.New("e2e: HandshakeRequest in wrong state")
	}
	a.group = a.pol.DHGroups[0]
	kind, _ := a.group.kind()
	key, err := dh.Generate(kind, dh.Uncompressed, a.sh.rnd)
	if err != nil {
		return nil, err
	}
	a.dhKey = key
	id, err := a.sh.assoIDs.get(a.peerKey)
	if err != nil {
		return nil, err
	}
	a.clientPart, a.ownPart, a.assoID = id, id, id
	t1 := &ClearToken1{
		SigAlg:   a.sh.sigAlg.id(),
		PKCert:   a.sh.local.Certificate,
		CertPath: nilIfEmpty(a.sh.local.Path),
		AssoID:   id,
		DHGroup:  int64(a.group),
		DHPublic: key.Public(),
		HMAC:     hmacSHA256ID,
		TimeRaw:  asn1.FormatTime62351(a.now()),
		ICV:      a.icvIDs(),
	}
	if a.ccfg.TLSProtected {
		t1.ConfParams = bits(0)
	} else {
		t1.ConfParams = bits()
	}
	s := &Signed{Kind: KindHandshakeReq, PP: a.sh.protocol[0], Token1: t1, ApplData: applData,
		Diag: -1, Sig: Signature{Alg: a.sh.sigAlg.id()}}
	out, err := encodeSigned(s, a.signFn)
	if err != nil {
		return nil, err
	}
	a.reqTBS = s.TBS
	a.reqToken = t1
	a.state = stRequested
	return out, nil
}

func nilIfEmpty(p [][]byte) [][]byte {
	if len(p) == 0 {
		return nil
	}
	return p
}

func bits(n ...int) asn1.BitString {
	bs, _ := asn1.DecodeBitString(asn1.NamedBits(n...))
	return bs
}

// verifySigned runs the signature part of 14.3.2 for a token-1 PDU and
// returns the parsed certificate.
func (a *Association) verifySigned(s *Signed, sigAlg AlgorithmIdentifier, pkCert []byte) (*pki.Certificate, SigAlg, *SecurityError) {
	if len(pkCert) > pki.MaxCertificateSize {
		a.event(EventCertificateTooLarge, ClassWarning, "",
			"warning: session termination due to unsupported public-key certificate size")
		return nil, 0, hsErr(HDInvalidPublicKeyCertificate, pki.ErrCertTooLarge)
	}
	if !sigAlg.equal(s.Sig.Alg) {
		return nil, 0, hsAlarm(AlarmSignatureAlgorithmMismatch, errors.New("sigAlg differs from sign.algo"))
	}
	alg, ok := sigAlgOf(sigAlg)
	if !ok {
		return nil, 0, hsErr(HDInvalidSignatureAlgorithm, fmt.Errorf("signature algorithm %v", sigAlg.Algorithm))
	}
	cert, err := pki.ParseCertificate(pkCert)
	if err != nil {
		return nil, 0, hsErr(HDInvalidPublicKeyCertificate, err)
	}
	if err := verify(cert.PublicKey, alg, s.TBS, s.Sig.Value); err != nil {
		return nil, 0, hsAlarm(AlarmInvalidSignature, err)
	}
	return cert, alg, nil
}

// checkCertificate runs 14.3.4 b) to d) on a verified peer certificate.
func (a *Association) checkCertificate(cert *pki.Certificate, path [][]byte, want AETitle) ([]*x509.Certificate, *SecurityError) {
	if err := pki.EndEntityProfile(cert); err != nil {
		return nil, hsErr(HDInvalidPublicKeyCertificate, err)
	}
	if err := pki.CheckIdentity(cert, want.OID(), a.pol.AEAttributeType); err != nil {
		return nil, hsAlarm(AlarmAddressMismatch, err)
	}
	if len(path) > a.pol.MaxCertPath {
		return nil, hsErr(HDInvalidCertificationPath, fmt.Errorf("%d CA certificates", len(path)))
	}
	chain, err := pki.Verify(cert, pki.PathOptions{
		Roots: a.pol.Trust, Intermediates: path, Revocation: a.pol.Revocation,
		Now: a.now(), MaxIntermediates: a.pol.MaxCertPath,
		OnStatus: func(c *x509.Certificate, s pki.RevocationStatus) {
			a.event(EventRevocationUnavailable, ClassWarning, "",
				"warning: certificate revocation information unavailable ("+s.String()+") for "+c.Subject.String())
		},
	})
	switch {
	case err == nil:
		return chain, nil
	case errors.Is(err, pki.ErrRevoked):
		a.event(EventCertificateRevoked, ClassIncident, "", "incident: revoked public-key certificate")
		return nil, hsErr(HDInvalidPublicKeyCertificate, err)
	case errors.Is(err, pki.ErrExpired):
		a.event(EventCertificateExpired, ClassWarning, "", "warning: expired public-key certificate")
		return nil, hsErr(HDInvalidPublicKeyCertificate, err)
	case errors.Is(err, pki.ErrRevocationState):
		return nil, hsErr(HDInvalidCertificationPath, err)
	}
	return nil, hsErr(HDInvalidCertificationPath, err)
}

func (a *Association) fresh(t time.Time) bool {
	d := a.now().Sub(t)
	if d < 0 {
		d = -d
	}
	return d <= a.pol.Freshness
}

func versionHasV1(t *ClearToken1) bool {
	return !t.HasVersion || t.Version.Bit(0)
}

func versionIsV1(has bool, v asn1.BitString) bool {
	if !has {
		return true
	}
	if !v.Bit(0) {
		return false
	}
	for i := 1; i < v.Length; i++ {
		if v.Bit(i) {
			return false
		}
	}
	return true
}

// ProcessHandshakeRequest checks a received HandshakeReq (the content
// octets of its SEQUENCE) from the peer calling as calling. It returns the
// protected protocol's ApplData TLV, or a *SecurityError for which the
// environment sends SecReject.
func (a *Association) ProcessHandshakeRequest(content []byte, calling AETitle) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	se := a.processRequest(content, calling)
	if se != nil {
		a.reportError(se)
		return nil, se
	}
	return a.applDataIn, nil
}

func (a *Association) processRequest(content []byte, calling AETitle) *SecurityError {
	if a.role != RoleServer || a.state != stIdle {
		return hsErr(HDProtocolError, errors.New("unexpected HandshakeReq"))
	}
	a.peerAE = calling
	a.peerKey = "c:" + calling.String()
	s, err := ParseSigned(KindHandshakeReq, content)
	if err != nil {
		return hsErr(HDProtocolError, err)
	}
	t := s.Token1
	cert, alg, se := a.verifySigned(s, t.SigAlg, t.PKCert)
	if se != nil {
		return se
	}
	a.peerCert = cert
	ok := false
	for _, p := range a.sh.protocol {
		if s.PP == p {
			ok = true
		}
	}
	if !ok {
		return hsErr(HDProtectedProtocolNotSupported, fmt.Errorf("pp %q", s.PP))
	}
	chain, se := a.checkCertificate(cert, t.CertPath, calling)
	if se != nil {
		return se
	}
	if !versionHasV1(t) {
		return hsErr(HDUnexpectedVersion, errors.New("v1 not offered"))
	}
	if !a.fresh(t.Time) {
		return hsErr(HDInvalidTimeValue, fmt.Errorf("time %s", t.TimeRaw))
	}
	if !validIDPart(t.AssoID) {
		return hsErr(HDProtocolError, fmt.Errorf("assoID %q", t.AssoID))
	}
	if a.sh.replay.seen(a.peerKey+"|"+string(t.TimeRaw)+"|"+t.AssoID, a.now(), a.now().Add(a.pol.Freshness+time.Minute)) {
		return hsAlarm(AlarmReplay, errors.New("time and assoID seen before"))
	}
	g := Group(t.DHGroup)
	groupOK := false
	for _, x := range a.pol.DHGroups {
		if x == g {
			groupOK = true
		}
	}
	if !groupOK {
		return hsErr(HDDHGroupNotSupported, fmt.Errorf("group %d", t.DHGroup))
	}
	kind, _ := g.kind()
	if err := dh.CheckPublic(kind, dh.Uncompressed, t.DHPublic); err != nil {
		return hsErr(HDProtocolError, err)
	}
	if !hmacAlgOK(t.HMAC, a.pol.AcceptSHA256HMACID) {
		return hsErr(HDHMACAlgorithmNotSupported, fmt.Errorf("hmac %v", t.HMAC.Algorithm))
	}
	// Encryption mode (14.3.4 k) to z)); this release supports neither
	// encryption nor authenticated encryption.
	if t.AEA {
		if a.pol.T100Diagnostics {
			return hsErr(HDAEAAlgorithmsNotSupported, errors.New("authenticated encryption not supported"))
		}
		return hsErr(HDEncrModeAEANotSupported, errors.New("authenticated encryption not supported"))
	}
	if t.HasEncr {
		return hsErr(HDEncryptionNotRequired, errors.New("encryption not supported"))
	}
	if t.ConfParams.Bit(1) {
		return hsErr(HDEncryptionNotRequired, errors.New("applProtected set"))
	}
	icv, found := ICVAlg(0), false
	for _, id := range t.ICV {
		alg, ok := icvAlgOf(id)
		if !ok {
			continue
		}
		for _, mine := range a.pol.ICVAlgs {
			if mine == alg {
				icv, found = alg, true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return hsErr(HDICVAlgorithmsNotSupported, errors.New("no supported ICV algorithm"))
	}
	if t.AttCert != nil && !a.pol.AcceptUnverifiedAttributeCertificates {
		return hsErr(HDInvalidAttributeCertificate, errors.New("attribute certificates are not supported"))
	}
	// Accepted: allocate the server part of the identifier.
	own, err := a.sh.assoIDs.get(a.peerKey + "|" + t.AssoID)
	if err != nil {
		return hsErr(HDNoReasonGiven, err)
	}
	a.clientPart, a.ownPart = t.AssoID, own
	a.assoID = t.AssoID + ":" + own
	a.group, a.icv = g, icv
	a.peerPub = t.DHPublic
	a.reqTBS = s.TBS
	a.reqToken = t
	a.applDataIn = s.ApplData
	a.peer = PeerSecurity{AE: calling, Certificate: cert.Certificate, CertificateRaw: cert.Raw,
		VerifiedChain: chain, AssoID: a.assoID, Signature: alg, Group: g, ICV: icv, ValidatedAt: a.now()}
	a.state = stRequested
	return nil
}

// HandshakeAccept builds the HandshakeAcc SecPDU carrying applData (the
// protected protocol's response) and enters the data transfer phase.
func (a *Association) HandshakeAccept(applData []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.role != RoleServer || a.state != stRequested {
		return nil, errors.New("e2e: HandshakeAccept in wrong state")
	}
	kind, _ := a.group.kind()
	key, err := dh.Generate(kind, dh.Uncompressed, a.sh.rnd)
	if err != nil {
		return nil, err
	}
	a.dhKey = key
	t1 := &ClearToken1{
		SigAlg:   a.sh.sigAlg.id(),
		PKCert:   a.sh.local.Certificate,
		CertPath: nilIfEmpty(a.sh.local.Path),
		AssoID:   a.assoID,
		DHGroup:  int64(a.group),
		DHPublic: key.Public(),
		HMAC:     a.reqToken.HMAC,
		TimeRaw:  asn1.FormatTime62351(a.now()),
		ICV:      []AlgorithmIdentifier{a.icv.id()},
		// The server mirrors the client's view of hop protection.
		ConfParams: bits(),
	}
	if a.reqToken.ConfParams.Bit(0) {
		t1.ConfParams = bits(0)
	}
	s := &Signed{Kind: KindHandshakeAcc, Token1: t1, ApplData: applData, Diag: -1, Sig: Signature{Alg: a.sh.sigAlg.id()}}
	out, err := encodeSigned(s, a.signFn)
	if err != nil {
		return nil, err
	}
	z, err := key.Shared(a.peerPub)
	if err != nil {
		return nil, err
	}
	a.salt = handshakeSalt(a.pol.HKDFInit, a.reqTBS, s.TBS)
	ks, err := deriveKeys(a.icv, a.salt, z)
	if err != nil {
		return nil, err
	}
	a.tx.key, a.rx.key = ks.server, ks.client
	a.reqTBS, a.applDataIn = nil, nil
	a.establish()
	a.event(EventHandshakeAccepted, ClassInfo, "", "")
	return out, nil
}

func (a *Association) establish() {
	a.state = stEstablished
	a.epochStart = a.now()
}

// token3 builds a ClearToken3 for this end.
func (a *Association) token3() *ClearToken3 {
	t := &ClearToken3{
		SigAlg:   a.sh.sigAlg.id(),
		TimeRaw:  asn1.FormatTime62351(a.now()),
		PKCert:   a.sh.local.Certificate,
		CertPath: nilIfEmpty(a.sh.local.Path),
	}
	if a.assoID != "" {
		t.HasAssoID, t.AssoID = true, a.assoID
	} else if a.clientPart != "" {
		t.HasAssoID, t.AssoID = true, a.clientPart
	}
	return t
}

func (a *Association) signed3(kind Kind, diag int, applData []byte) ([]byte, error) {
	s := &Signed{Kind: kind, Token3: a.token3(), Diag: diag, ApplData: applData, Sig: Signature{Alg: a.sh.sigAlg.id()}}
	return encodeSigned(s, a.signFn)
}

// SecReject builds the HandshakeSecReject for a request that failed with se.
func (a *Association) SecReject(se *SecurityError) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = stClosed
	a.release()
	return a.signed3(KindHandshakeSecReject, se.WireDiag(a.pol.AlarmDiagnostic), nil)
}

// ApplicationReject builds the ApplicationReject carrying the protected
// protocol's refusal (13.1.5).
func (a *Association) ApplicationReject(applData []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = stClosed
	a.release()
	return a.signed3(KindApplicationReject, -1, applData)
}

// ProcessHandshakeAccept checks the server's HandshakeAcc (content octets).
// responding is the AE title the server answered with (the called one when
// it omitted it). It returns the ApplData TLV of the response; on a
// *SecurityError the environment sends HandshakeSecAbort.
func (a *Association) ProcessHandshakeAccept(content []byte, responding AETitle) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	appl, se := a.processAccept(content, responding)
	if se != nil {
		a.reportError(se)
		return nil, se
	}
	return appl, nil
}

func (a *Association) processAccept(content []byte, responding AETitle) ([]byte, *SecurityError) {
	if a.role != RoleClient || a.state != stRequested {
		return nil, hsErr(HDProtocolError, errors.New("unexpected HandshakeAcc"))
	}
	s, err := ParseSigned(KindHandshakeAcc, content)
	if err != nil {
		return nil, hsErr(HDProtocolError, err)
	}
	t := s.Token1
	cert, alg, se := a.verifySigned(s, t.SigAlg, t.PKCert)
	if se != nil {
		return nil, se
	}
	a.peerCert = cert
	chain, se := a.checkCertificate(cert, t.CertPath, responding)
	if se != nil {
		return nil, se
	}
	if !versionIsV1(t.HasVersion, t.Version) {
		return nil, hsErr(HDUnexpectedVersion, errors.New("version other than v1"))
	}
	if !a.fresh(t.Time) {
		return nil, hsErr(HDInvalidTimeValue, fmt.Errorf("time %s", t.TimeRaw))
	}
	if a.sh.replay.seen(a.peerKey+"|"+string(t.TimeRaw)+"|"+t.AssoID, a.now(), a.now().Add(a.pol.Freshness+time.Minute)) {
		return nil, hsAlarm(AlarmReplay, errors.New("time and assoID seen before"))
	}
	cp, sp, ok := strings.Cut(t.AssoID, ":")
	if !ok || cp != a.clientPart || !validIDPart(sp) {
		return nil, hsErr(HDProtocolError, fmt.Errorf("assoID %q", t.AssoID))
	}
	if Group(t.DHGroup) != a.group {
		return nil, hsErr(HDIllegalDHGroupSelected, fmt.Errorf("group %d", t.DHGroup))
	}
	kind, _ := a.group.kind()
	if err := dh.CheckPublic(kind, dh.Uncompressed, t.DHPublic); err != nil {
		return nil, hsErr(HDProtocolError, err)
	}
	if !t.HMAC.equal(a.reqToken.HMAC) && !(hmacAlgOK(t.HMAC, false) && hmacAlgOK(a.reqToken.HMAC, false)) {
		return nil, hsErr(HDHMACAlgorithmNotSupported, errors.New("hmac differs from the request"))
	}
	if t.AEA {
		if a.pol.T100Diagnostics {
			return nil, hsErr(HDAEAAlgorithmsNotSupported, errors.New("server selected authenticated encryption"))
		}
		return nil, hsErr(HDAENotUsed, errors.New("server selected authenticated encryption"))
	}
	if t.HasEncr {
		return nil, hsErr(HDEncryptionNotRequired, errors.New("server selected encryption"))
	}
	if len(t.ICV) != 1 {
		return nil, hsErr(HDSingleICVAlgoRequired, fmt.Errorf("%d ICV algorithms", len(t.ICV)))
	}
	icv, ok := icvAlgOf(t.ICV[0])
	offered := false
	for _, x := range a.pol.ICVAlgs {
		if ok && x == icv {
			offered = true
		}
	}
	if !offered {
		return nil, hsErr(HDICVAlgorithmsNotSupported, errors.New("ICV algorithm not offered"))
	}
	if t.ConfParams.Bit(1) {
		return nil, hsErr(HDEncryptionNotRequired, errors.New("applProtected set"))
	}
	if t.AttCert != nil && !a.pol.AcceptUnverifiedAttributeCertificates {
		return nil, hsErr(HDInvalidAttributeCertificate, errors.New("attribute certificates are not supported"))
	}
	z, err := a.dhKey.Shared(t.DHPublic)
	if err != nil {
		return nil, hsErr(HDProtocolError, err)
	}
	a.salt = handshakeSalt(a.pol.HKDFInit, a.reqTBS, s.TBS)
	ks, err := deriveKeys(icv, a.salt, z)
	if err != nil {
		return nil, hsErr(HDNoReasonGiven, err)
	}
	a.tx.key, a.rx.key = ks.client, ks.server
	a.icv = icv
	a.peerPub = t.DHPublic
	a.assoID = t.AssoID
	a.reqTBS = nil
	a.peer = PeerSecurity{AE: responding, Certificate: cert.Certificate, CertificateRaw: cert.Raw,
		VerifiedChain: chain, AssoID: a.assoID, Signature: alg, Group: a.group, ICV: icv, ValidatedAt: a.now()}
	a.establish()
	a.event(EventHandshakeAccepted, ClassInfo, "", "")
	return s.ApplData, nil
}

// HandshakeSecAbort builds the client's HandshakeSecAbort for se.
func (a *Association) HandshakeSecAbort(se *SecurityError) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = stClosed
	a.event(EventAbortSent, ClassWarning, HandshakeDiagName(se.WireDiag(a.pol.AlarmDiagnostic)), "HandshakeSecAbort")
	a.release()
	return a.signed3(KindHandshakeSecAbort, se.WireDiag(a.pol.AlarmDiagnostic), nil)
}

// ProcessRejection authenticates a peer's signed reject or abort (content
// octets of a SecPDU of kind) as well as possible and returns it as a
// *RejectedError. It never fails: an unverifiable rejection is reported
// as unauthenticated.
func (a *Association) ProcessRejection(kind Kind, content []byte) *RejectedError {
	a.mu.Lock()
	defer a.mu.Unlock()
	re := &RejectedError{Kind: kind, Diag: -1}
	s, err := ParseSigned(kind, content)
	if err != nil {
		a.event(EventAbortReceived, ClassWarning, "", "malformed "+kind.String())
		a.state = stClosed
		a.release()
		return re
	}
	re.Diag, re.ApplData = s.Diag, s.ApplData
	re.Authenticated = a.verifyToken3(s) == nil
	d := HandshakeDiagName(s.Diag)
	if kind == KindDtSecAbort {
		d = DtDiagName(s.Diag)
	}
	code := EventAbortReceived
	if kind == KindHandshakeSecReject || kind == KindApplicationReject {
		code = EventHandshakeRejected
	}
	a.event(code, ClassWarning, d, fmt.Sprintf("%v authenticated=%v", kind, re.Authenticated))
	a.state = stClosed
	a.release()
	return re
}

// verifyToken3 verifies a token-3 PDU: its signature, that its certificate
// is the one of the handshake when there was one (or a valid one naming the
// peer otherwise), and its time.
func (a *Association) verifyToken3(s *Signed) error {
	t := s.Token3
	if !t.SigAlg.equal(s.Sig.Alg) {
		return errors.New("sigAlg differs from sign.algo")
	}
	alg, ok := sigAlgOf(t.SigAlg)
	if !ok {
		return errors.New("signature algorithm not supported")
	}
	var cert *pki.Certificate
	if a.peerCert != nil {
		if !bytesEqual(a.peerCert.Raw, t.PKCert) {
			return errors.New("certificate differs from the handshake")
		}
		cert = a.peerCert
	} else {
		c, err := pki.ParseCertificate(t.PKCert)
		if err != nil {
			return err
		}
		if _, se := a.checkCertificate(c, t.CertPath, a.peerAE); se != nil {
			return se
		}
		cert = c
	}
	if err := verify(cert.PublicKey, alg, s.TBS, s.Sig.Value); err != nil {
		return err
	}
	if !a.fresh(t.Time) {
		return errors.New("time outside the freshness window")
	}
	if a.assoID != "" && t.HasAssoID && t.AssoID != a.assoID && t.AssoID != a.clientPart {
		return errors.New("assoID mismatch")
	}
	return nil
}

func bytesEqual(a, b []byte) bool { return hmac.Equal(a, b) }

// ---------------------------------------------------------------------
// Data transfer

// Seal protects applData (the complete ApplData TLV) in a ClearTransfer and
// returns its SEQUENCE TLV.
func (a *Association) Seal(applData []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != stEstablished && a.state != stReleasing {
		return nil, errors.New("e2e: association not established")
	}
	now := a.now()
	t := asn1Truncate(now)
	if a.tx.have && t.Before(a.tx.lastTime) {
		if a.tx.lastTime.Sub(t) > a.pol.Freshness/2 {
			a.event(EventClockRegression, ClassWarning, "", "local clock behind the last time sent")
		}
		t = a.tx.lastTime
	}
	seq := int64(0)
	if a.tx.have && t.Equal(a.tx.lastTime) {
		seq = a.tx.lastSeq + 1
	}
	tok := ClearToken2{AssoID: a.assoID, TimeRaw: asn1.FormatTime62351(t), Seq: seq}
	// Key management flags.
	var newClientKey *dh.Key
	switch a.role {
	case RoleClient:
		if !a.rekeyOut && (a.rekeyWanted || now.Sub(a.epochStart) >= a.pol.RekeyInterval || a.tx.msgs >= a.pol.MaxMessagesPerKey) {
			kind, _ := a.group.kind()
			k, err := dh.Generate(kind, dh.Uncompressed, a.sh.rnd)
			if err != nil {
				return nil, err
			}
			newClientKey = k
			tok.Rekey = k.Public()
		}
	case RoleServer:
		if a.pendingChg {
			tok.ChangedKey = true
		} else if a.pol.RekeyRequest > 0 && !a.reqRekeySent && now.Sub(a.epochStart) >= a.pol.RekeyRequest {
			tok.ReqRekey = true
			a.reqRekeySent = true
		}
	}
	tr := &Transfer{Token2: tok, ApplData: applData}
	key := a.tx.key
	out, err := encodeTransfer(tr, a.pol.Authenticator, func(tbp []byte) (*Authenticator, error) {
		var nonce []byte
		if a.icv != ICVHMACSHA256 {
			var err error
			if nonce, err = newNonce(a.sh.rnd); err != nil {
				return nil, err
			}
		}
		v, err := computeICV(a.icv, key, nonce, tbp)
		if err != nil {
			return nil, err
		}
		return &Authenticator{Nonce: nonce, Alg: a.icv.id(), ICV: v}, nil
	})
	if err != nil {
		return nil, err
	}
	a.tx.lastTime, a.tx.lastSeq, a.tx.have = t, seq, true
	a.tx.msgs++
	// Transitions after the PDU is built (old keys protect it).
	if newClientKey != nil {
		z, err := newClientKey.Shared(a.peerPub)
		if err != nil {
			return nil, err
		}
		a.salt = rekeySalt(tr.TBP, a.salt)
		ks, err := deriveKeys(a.icv, a.salt, z)
		if err != nil {
			return nil, err
		}
		a.dhKey.Destroy()
		a.dhKey = newClientKey
		a.tx.key, a.tx.msgs = ks.client, 0
		a.pendingRx = ks.server
		a.rekeyOut, a.rekeyOutAt, a.rekeyWanted = true, now, false
		a.event(EventRekeyStarted, ClassInfo, "", "")
	}
	if tok.ChangedKey {
		a.tx.key, a.tx.msgs = a.pendingTx, 0
		a.pendingTx, a.pendingChg = nil, false
		a.epoch++
		a.epochStart = now
		a.reqRekeySent = false
		a.event(EventRekeyCompleted, ClassInfo, "", "")
	}
	return out, nil
}

func asn1Truncate(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

// Open verifies a ClearTransfer or EncrTransfer (content octets) and returns
// the ApplData TLV. On a *SecurityError the environment sends DtSecAbort
// and closes the association.
func (a *Association) Open(content []byte, encrypted bool) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	appl, se := a.open(content, encrypted)
	if se != nil {
		a.reportError(se)
		return nil, se
	}
	return appl, nil
}

func (a *Association) open(content []byte, encrypted bool) ([]byte, *SecurityError) {
	if a.state != stEstablished && a.state != stReleasing {
		return nil, dtErr(DDProtocolError, errors.New("association not established"))
	}
	t, err := ParseTransfer(encrypted, content, a.pol.Authenticator)
	if err != nil {
		return nil, dtErr(DDProtocolError, err)
	}
	if encrypted {
		return nil, dtErr(DDEncryptionNotSelected, errors.New("EncrTransfer received, encryption not selected"))
	}
	au := t.Auth
	if alg, ok := icvAlgOf(au.Alg); !ok || alg != a.icv {
		return nil, dtAlarm(AlarmInvalidICVAlgorithm, fmt.Errorf("ICV algorithm %v", au.Alg.Algorithm))
	}
	if a.icv != ICVHMACSHA256 && au.Nonce == nil {
		return nil, dtErr(DDGMACNonceRequired, errors.New("GMAC without nonce"))
	}
	want, err := computeICV(a.icv, a.rx.key, au.Nonce, t.TBP)
	if err != nil || !hmac.Equal(want, au.ICV) {
		return nil, dtAlarm(AlarmInvalidICV, errors.New("ICV does not verify"))
	}
	tk := &t.Token2
	if !versionIsV1(tk.HasVersion, tk.Version) {
		return nil, dtErr(DDUnexpectedVersion, errors.New("version other than v1"))
	}
	if !a.fresh(tk.Time) {
		return nil, dtErr(DDInvalidTimeValue, fmt.Errorf("time %s", tk.TimeRaw))
	}
	r := &a.rx
	if r.have {
		switch {
		case tk.Time.Before(r.lastTime):
			return nil, dtErr(DDInvalidTimeValue, errors.New("time earlier than the preceding SecPDU"))
		case tk.Time.Equal(r.lastTime) && tk.Seq <= r.lastSeq:
			return nil, dtAlarm(AlarmReplay, errors.New("time and sequence number received before"))
		case tk.Time.Equal(r.lastTime) && tk.Seq != r.lastSeq+1:
			return nil, dtErr(DDInvalidSequenceNumber, fmt.Errorf("seq %d after %d", tk.Seq, r.lastSeq))
		case tk.Time.After(r.lastTime) && tk.Seq != 0:
			return nil, dtErr(DDInvalidSequenceNumber, fmt.Errorf("seq %d after a time change", tk.Seq))
		}
	} else if tk.Seq != 0 {
		return nil, dtErr(DDInvalidSequenceNumber, fmt.Errorf("first seq %d", tk.Seq))
	}
	if tk.AssoID != a.assoID {
		return nil, dtErr(DDProtocolError, fmt.Errorf("assoID %q", tk.AssoID))
	}
	if tk.IV != nil {
		return nil, dtErr(DDProtocolError, errors.New("iv in a clear transfer"))
	}
	// Key management flags (14.4.3 f) to i)).
	var rekeyKeys *keySet
	switch a.role {
	case RoleClient:
		if tk.Rekey != nil {
			return nil, dtErr(DDProtocolError, errors.New("rekey from the server"))
		}
		if tk.ChangedKey && !a.rekeyOut {
			return nil, dtErr(DDUnexpectedChangedKey, errors.New("changedKey without an outstanding rekey"))
		}
	case RoleServer:
		if tk.ChangedKey {
			if a.pol.T100Diagnostics {
				return nil, dtErr(DDUnexpectedChangedKey, errors.New("changedKey from the client"))
			}
			return nil, dtErr(DDProtocolError, errors.New("changedKey from the client"))
		}
		if tk.ReqRekey {
			return nil, dtErr(DDProtocolError, errors.New("reqRekey from the client"))
		}
		if tk.Rekey != nil {
			if a.pendingChg {
				return nil, dtErr(DDUnexpectedDHPublicKey, errors.New("second rekey before changedKey"))
			}
			kind, _ := a.group.kind()
			if err := dh.CheckPublic(kind, dh.Uncompressed, tk.Rekey); err != nil {
				return nil, dtErr(DDProtocolError, err)
			}
			z, err := a.dhKey.Shared(tk.Rekey)
			if err != nil {
				return nil, dtErr(DDProtocolError, err)
			}
			salt := rekeySalt(t.TBP, a.salt)
			ks, err := deriveKeys(a.icv, salt, z)
			if err != nil {
				return nil, dtErr(DDNoReasonGiven, err)
			}
			a.salt = salt
			rekeyKeys = &ks
		}
	}
	// Commit.
	r.lastTime, r.lastSeq, r.have = tk.Time, tk.Seq, true
	r.msgs++
	switch {
	case rekeyKeys != nil:
		a.rx.key, a.rx.msgs = rekeyKeys.client, 0
		a.pendingTx, a.pendingChg = rekeyKeys.server, true
		a.event(EventRekeyStarted, ClassInfo, "", "rekey received")
	case a.role == RoleClient && tk.ChangedKey:
		a.rx.key, a.rx.msgs = a.pendingRx, 0
		a.pendingRx, a.rekeyOut = nil, false
		a.epoch++
		a.epochStart = a.now()
		a.event(EventRekeyCompleted, ClassInfo, "", "")
	case a.role == RoleClient && tk.ReqRekey:
		a.rekeyWanted = true
	}
	return t.ApplData, nil
}

// RekeyDue reports, on a client, that a rekey is wanted and no PDU has
// carried it yet; an idle environment can then send a request to carry it.
func (a *Association) RekeyDue() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.role != RoleClient || a.state != stEstablished || a.rekeyOut {
		return false
	}
	return a.rekeyWanted || a.now().Sub(a.epochStart) >= a.pol.RekeyInterval
}

// RequestRekey asks for a rekey on the next PDU (client) or sets reqRekey
// on the next PDU (server).
func (a *Association) RequestRekey() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.role == RoleClient {
		a.rekeyWanted = true
	} else {
		a.reqRekeySent = false
		a.epochStart = time.Time{}
		if a.pol.RekeyRequest == 0 {
			a.pol = func(p Policy) *Policy { p.RekeyRequest = time.Nanosecond; return &p }(*a.pol)
		}
	}
}

// RekeyOverdue reports a client rekey outstanding for longer than d.
func (a *Association) RekeyOverdue(d time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rekeyOut && a.now().Sub(a.rekeyOutAt) > d
}

// ---------------------------------------------------------------------
// Release and abort

// ReleaseRequest builds the ReleaseReq SecPDU.
func (a *Association) ReleaseRequest() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != stEstablished {
		return nil, errors.New("e2e: release in wrong state")
	}
	a.state = stReleasing
	return a.signed3(KindReleaseReq, -1, nil)
}

// ProcessReleaseRequest verifies the peer's ReleaseReq.
func (a *Association) ProcessReleaseRequest(content []byte) error {
	return a.processRelease(KindReleaseReq, content)
}

// ReleaseResponse builds the ReleaseRsp SecPDU and closes the association.
func (a *Association) ReleaseResponse() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	out, err := a.signed3(KindReleaseRsp, -1, nil)
	a.state = stClosed
	a.event(EventReleaseCompleted, ClassInfo, "", "")
	a.release()
	return out, err
}

// ProcessReleaseResponse verifies the peer's ReleaseRsp and closes.
func (a *Association) ProcessReleaseResponse(content []byte) error {
	err := a.processRelease(KindReleaseRsp, content)
	a.mu.Lock()
	a.state = stClosed
	if err == nil {
		a.event(EventReleaseCompleted, ClassInfo, "", "")
	}
	a.release()
	a.mu.Unlock()
	return err
}

func (a *Association) processRelease(kind Kind, content []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := ParseSigned(kind, content)
	if err != nil {
		return err
	}
	if err := a.verifyToken3(s); err != nil {
		a.event(EventAbortReceived, ClassWarning, "", "unverifiable "+kind.String()+": "+err.Error())
		return fmt.Errorf("e2e: %v: %w", kind, err)
	}
	if kind == KindReleaseReq {
		a.state = stReleasing
	}
	return nil
}

// DtSecAbort builds the DtSecAbort for a data-transfer error and closes.
func (a *Association) DtSecAbort(se *SecurityError) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := se.WireDiag(a.pol.AlarmDiagnostic)
	a.event(EventAbortSent, ClassWarning, DtDiagName(d), "DtSecAbort")
	a.state = stClosed
	a.release()
	return a.signed3(KindDtSecAbort, d, nil)
}

// ApplAbort builds an ApplAbort (abort by the protected protocol, applData
// optional) and closes.
func (a *Association) ApplAbort(applData []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.event(EventAbortSent, ClassWarning, "", "ApplAbort")
	a.state = stClosed
	a.release()
	return a.signed3(KindApplAbort, -1, applData)
}

// Close forgets the association's keys.
func (a *Association) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = stClosed
	a.release()
}

// release returns the identifier and drops key material; called with mu.
func (a *Association) release() {
	if a.ownPart != "" {
		peer := a.peerKey
		if a.role == RoleServer {
			peer += "|" + a.clientPart
		}
		a.sh.assoIDs.put(peer, a.ownPart)
		a.ownPart = ""
	}
	a.dhKey.Destroy()
	for _, k := range [][]byte{a.tx.key, a.rx.key, a.pendingRx, a.pendingTx, a.salt} {
		clear(k)
	}
	a.tx.key, a.rx.key, a.pendingRx, a.pendingTx, a.salt = nil, nil, nil, nil, nil
}
