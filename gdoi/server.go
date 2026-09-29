package gdoi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Group is the policy and keys a key server hands out for one group: its
// TEKs, each with the time it becomes usable and the time it expires. A
// key rotation adds the next TEK with an activation delay, so members that
// register before the change hold both, and removes the old one once it
// has expired. Safe for concurrent use.
type Group struct {
	mu   sync.Mutex
	teks []groupTEK
}

type groupTEK struct {
	tek                TEK
	activates, expires time.Time // expires is zero for a TEK that does not
}

// Add adds a TEK to the group. Its ActivationDelay and Lifetime count
// from now. A TEK whose SPI the group already uses is refused.
func (g *Group) Add(t TEK) error {
	if err := t.checkPolicy(); err != nil {
		return err
	}
	now := time.Now()
	e := groupTEK{tek: t, activates: now.Add(t.ActivationDelay)}
	if t.Lifetime > 0 {
		e.expires = now.Add(t.Lifetime)
	}
	e.tek.AlgorithmKey, e.tek.IntegrityKey = clone(t.AlgorithmKey), clone(t.IntegrityKey)
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.teks {
		if x.tek.SPI == t.SPI {
			return fmt.Errorf("gdoi: SPI %d is already in use in the group", t.SPI)
		}
	}
	g.teks = append(g.teks, e)
	return nil
}

// Remove withdraws the TEK with the given SPI: members stop receiving it
// at their next registration, and drop it then.
func (g *Group) Remove(spi uint32) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, x := range g.teks {
		if x.tek.SPI == spi {
			g.teks = append(g.teks[:i], g.teks[i+1:]...)
			return
		}
	}
}

// snapshot returns the TEKs still valid at now, with the lifetime and
// activation delay they have left, oldest activation first. Expired ones
// are dropped from the group.
func (g *Group) snapshot(now time.Time) []TEK {
	g.mu.Lock()
	defer g.mu.Unlock()
	kept := g.teks[:0]
	var out []TEK
	for _, x := range g.teks {
		if !x.expires.IsZero() && !now.Before(x.expires) {
			continue
		}
		kept = append(kept, x)
		t := x.tek
		t.AlgorithmKey, t.IntegrityKey = clone(t.AlgorithmKey), clone(t.IntegrityKey)
		t.ActivationDelay = max(0, x.activates.Sub(now))
		t.Lifetime = 0
		if !x.expires.IsZero() {
			t.Lifetime = x.expires.Sub(now)
		}
		out = append(out, t)
	}
	g.teks = kept
	sort.SliceStable(out, func(i, j int) bool { return out[i].ActivationDelay < out[j].ActivationDelay })
	return out
}

// ServerConfig configures a key server.
type ServerConfig struct {
	// Credentials authenticate the key server to members, and members to
	// it. Certificate credentials serve members that authenticate with
	// certificates; PSK serves members with pre-shared keys; both may be
	// set. Credentials.PSK is not used by a server: see PSK.
	Credentials
	// PSK returns the pre-shared key of the member at addr, nil when it
	// has none. Main mode commits to the key before the member names
	// itself, so the address is all there is to choose by.
	PSK func(addr net.Addr) []byte
	// Authorize decides whether an authenticated member may have a
	// group's keys (RFC 6407 3.1). Required: a key server hands keys only
	// to members it has been told to.
	Authorize func(member Peer, group GroupID) bool
	// Suites are the phase 1 algorithms accepted (DefaultSuites when
	// empty); a member's first offer among them is chosen.
	Suites []Suite
	// OnRegister is told of every completed registration, and OnReject of
	// every refused one, for the security event log. They must not block.
	OnRegister func(member Peer, group GroupID, teks []TEK)
	OnReject   func(addr net.Addr, err error)
}

// Server is a GDOI key server (group controller/key server, GCKS) serving
// GROUPKEY-PULL registrations for its groups over UDP.
type Server struct {
	cfg    ServerConfig
	sigMet uint16 // the signature method of the certificate credentials, 0 without

	mu     sync.Mutex
	groups map[string]*Group
	peers  map[[8]byte]*responder
	conn   net.PacketConn
}

// maxPeers bounds the phase 1 states kept; beyond it the least recently
// active are dropped.
const maxPeers = 4096

// peerTTL is how long a phase 1 state is kept after its last message.
const peerTTL = 2 * time.Minute

// NewServer returns a key server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.Authorize == nil {
		return nil, errors.New("gdoi: ServerConfig.Authorize is required")
	}
	s := &Server{cfg: cfg, groups: map[string]*Group{}, peers: map[[8]byte]*responder{}}
	if cfg.Key != nil {
		if len(cfg.Certificate) == 0 || cfg.Roots == nil {
			return nil, errors.New("gdoi: certificate credentials need a certificate and Roots")
		}
		m, err := authMethodFor(cfg.Key)
		if err != nil {
			return nil, err
		}
		s.sigMet = m
	}
	if s.sigMet == 0 && cfg.PSK == nil {
		return nil, errors.New("gdoi: a key server needs certificate credentials or a PSK function")
	}
	if len(s.cfg.Suites) == 0 {
		s.cfg.Suites = DefaultSuites
	}
	return s, nil
}

// AddGroup serves group with the TEKs of g.
func (s *Server) AddGroup(id GroupID, g *Group) {
	s.mu.Lock()
	s.groups[id.key()] = g
	s.mu.Unlock()
}

// ListenAndServe serves on addr (":848" when empty).
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		addr = fmt.Sprintf(":%d", DefaultPort)
	}
	c, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	return s.Serve(c)
}

// Serve serves registrations on c until it is closed.
func (s *Server) Serve(c net.PacketConn) error {
	s.mu.Lock()
	s.conn = c
	s.mu.Unlock()
	buf := make([]byte, maxMessage)
	for {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if resp := s.handle(clone(buf[:n]), addr); resp != nil {
			c.WriteTo(resp, addr)
		}
	}
}

// Close stops serving.
func (s *Server) Close() error {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

func (s *Server) reject(addr net.Addr, err error) {
	if s.cfg.OnReject != nil {
		s.cfg.OnReject(addr, err)
	}
}

// handle processes one datagram and returns the reply, if any.
func (s *Server) handle(msg []byte, addr net.Addr) []byte {
	h, err := parseHeader(msg)
	if err != nil {
		s.reject(addr, err)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	r, ok := s.peers[h.ICookie]
	if !ok {
		if h.Exchange != xchgMain || h.RCookie != [8]byte{} {
			return nil // not ours, or long forgotten
		}
		s.expire(now)
		r = &responder{s: s, addr: addr, ic: h.ICookie, rc: randomCookie(), pulls: map[uint32]*pullState{}}
		s.peers[h.ICookie] = r
	} else if r.addr.String() != addr.String() {
		return nil
	} else if r.lastReq != nil && bytes.Equal(msg, r.lastReq) {
		// A retransmitted request gets the reply it had; a retransmitted
		// message 1 still carries no responder cookie.
		r.touched = now
		return r.lastResp
	} else if h.RCookie != r.rc {
		return nil
	}
	r.touched = now
	resp, err := r.step(h, msg)
	if err != nil {
		s.reject(addr, err)
		var n *refusal
		if errors.As(err, &n) {
			// Before phase 1 completes a notification goes in the clear
			// (RFC 2409 5.7); after, it is protected.
			var k *keys
			if r.state == stateEstablished {
				k = r.k
			}
			resp = informational(k, r.ic, r.rc, n.notify)
		}
		// A failed exchange is over: its state goes.
		if r.state < stateEstablished {
			delete(s.peers, r.ic)
		}
		return resp
	}
	r.lastReq, r.lastResp = msg, resp
	return resp
}

// expire drops phase 1 states idle past peerTTL, and the oldest when there
// are too many.
func (s *Server) expire(now time.Time) {
	for k, r := range s.peers {
		if now.Sub(r.touched) > peerTTL {
			delete(s.peers, k)
		}
	}
	for len(s.peers) >= maxPeers {
		var oldest [8]byte
		var t time.Time
		for k, r := range s.peers {
			if t.IsZero() || r.touched.Before(t) {
				oldest, t = k, r.touched
			}
		}
		delete(s.peers, oldest)
	}
}

// refusal is an error the member is told of with a notification.
type refusal struct {
	notify uint16
	err    error
}

func (r *refusal) Error() string { return r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

func refuse(n uint16, format string, args ...any) error {
	return &refusal{notify: n, err: fmt.Errorf("gdoi: "+format, args...)}
}

const (
	stateSA = iota // waiting for the key exchange
	stateKE        // waiting for the authentication
	stateEstablished
)

// responder is the state of one member's phase 1 SA at the key server.
type responder struct {
	s       *Server
	addr    net.Addr
	ic, rc  [8]byte
	state   int
	touched time.Time

	saI    []byte
	suite  Suite
	auth   uint16
	psk    []byte
	dh     *dh
	gxi    []byte
	ni, nr []byte
	skeyid []byte
	k      *keys
	iv     []byte
	peer   Peer

	lastReq, lastResp []byte
	pulls             map[uint32]*pullState
}

type pullState struct {
	iv                []byte
	ni, nr            []byte
	group             GroupID
	teks              []TEK
	done              bool
	lastReq, lastResp []byte
}

func (r *responder) step(h *header, msg []byte) ([]byte, error) {
	switch {
	case h.Exchange == xchgMain && r.state == stateSA && h.RCookie == [8]byte{}:
		return r.mainSA(msg)
	case h.Exchange == xchgMain && r.state == stateSA:
		return r.mainKE(msg)
	case h.Exchange == xchgMain && r.state == stateKE:
		return r.mainAuth(msg)
	case h.Exchange == xchgPull && r.state == stateEstablished:
		return r.pull(h, msg)
	case h.Exchange == xchgInfo:
		return nil, nil
	}
	return nil, fmt.Errorf("gdoi: unexpected exchange %d in state %d", h.Exchange, r.state)
}

// mainSA answers main mode message 1: the member's first offer the server
// accepts, returned unchanged.
func (r *responder) mainSA(msg []byte) ([]byte, error) {
	_, ps, _, _, err := (*keys)(nil).open(msg, nil)
	if err != nil {
		return nil, err
	}
	sa, ok := find(ps, pSA)
	if !ok {
		return nil, malformed("main mode request without an SA")
	}
	offers, err := parsePhase1SA(sa.Body)
	if err != nil {
		return nil, err
	}
	for _, t := range offers {
		if !r.s.accepts(t.suite) {
			continue
		}
		switch {
		case t.auth == authPSK && r.s.cfg.PSK != nil:
			if r.psk = r.s.cfg.PSK(r.addr); len(r.psk) == 0 {
				continue
			}
		case t.auth != authPSK && t.auth == r.s.sigMet:
		default:
			continue
		}
		r.saI, r.suite, r.auth = clone(sa.Body), t.suite, t.auth
		// The reply carries the initiator's DOI with its chosen transform.
		chosen := phase1SAWithDOI(binary.BigEndian.Uint32(sa.Body), []payload{{Type: pTrans, Body: t.body}})
		return message(header{ICookie: r.ic, RCookie: r.rc, Exchange: xchgMain},
			[]payload{{Type: pSA, Body: chosen}}), nil
	}
	return nil, refuse(notifyNoProposalChosen, "no acceptable phase 1 proposal from %v", r.addr)
}

func (s *Server) accepts(t Suite) bool {
	for _, a := range s.cfg.Suites {
		if a == t {
			return true
		}
	}
	return false
}

// mainKE answers main mode message 3 with the server's key exchange value
// and nonce, and derives the keys.
func (r *responder) mainKE(msg []byte) ([]byte, error) {
	_, ps, _, _, err := (*keys)(nil).open(msg, nil)
	if err != nil {
		return nil, err
	}
	ke, ok1 := find(ps, pKE)
	nonce, ok2 := find(ps, pNonce)
	if !ok1 || !ok2 {
		return nil, malformed("main mode request without KE and nonce")
	}
	if len(nonce.Body) < 8 || len(nonce.Body) > 256 {
		return nil, malformed("nonce of %d octets", len(nonce.Body))
	}
	if r.dh, err = newDH(r.suite.Group); err != nil {
		return nil, err
	}
	gxy, err := r.dh.shared(ke.Body)
	if err != nil {
		return nil, err
	}
	r.gxi, r.ni, r.nr = clone(ke.Body), clone(nonce.Body), randomBytes(nonceLen)
	hf := r.suite.newHash()
	if r.auth == authPSK {
		r.skeyid = prf(hf, r.psk, r.ni, r.nr)
	} else {
		r.skeyid = prf(hf, append(clone(r.ni), r.nr...), gxy)
	}
	if r.k, err = deriveKeys(r.suite, r.skeyid, gxy, r.ic[:], r.rc[:]); err != nil {
		return nil, err
	}
	r.iv = phase1IV(hf, r.gxi, r.dh.pub)
	r.state = stateKE
	return message(header{ICookie: r.ic, RCookie: r.rc, Exchange: xchgMain},
		[]payload{{Type: pKE, Body: r.dh.pub}, {Type: pNonce, Body: r.nr}}), nil
}

// mainAuth checks the member's identity and authentication, and answers
// with the server's.
func (r *responder) mainAuth(msg []byte) ([]byte, error) {
	h, ps, _, iv, err := r.k.open(msg, r.iv)
	if err != nil {
		// Keys derived from a different pre-shared key decrypt the
		// message into garbage: that is how a wrong key shows.
		return nil, refuse(notifyAuthFailed, "member %v: message 5 does not decrypt: %v", r.addr, err)
	}
	if h.Flags&flagEncrypted == 0 {
		return nil, malformed("main mode authentication in the clear")
	}
	idp, ok := find(ps, pID)
	if !ok {
		return nil, refuse(notifyAuthFailed, "member %v: message 5 without identification", r.addr)
	}
	idii, err := parseID(idp.Body)
	if err != nil {
		return nil, refuse(notifyAuthFailed, "member %v: %v", r.addr, err)
	}
	hf := r.k.hash
	hashI := prf(hf, r.skeyid, r.gxi, r.dh.pub, r.ic[:], r.rc[:], r.saI, idii.body())
	peer := Peer{Addr: r.addr, IDType: idii.Type, ID: clone(idii.Data)}
	if r.auth == authPSK {
		hp, ok := find(ps, pHash)
		if !ok || !constantEqual(hp.Body, hashI) {
			return nil, refuse(notifyAuthFailed, "member %v failed pre-shared key authentication", r.addr)
		}
	} else {
		certs, err := parseCerts(ps)
		if err != nil {
			return nil, refuse(notifyInvalidCert, "%v", err)
		}
		leaf, err := r.s.cfg.verifyPeer(idii, certs, time.Now())
		if err != nil {
			return nil, refuse(notifyInvalidCert, "member %v: %v", r.addr, err)
		}
		sp, ok := find(ps, pSig)
		if !ok {
			return nil, malformed("main mode request without a signature")
		}
		if err := verify(r.auth, leaf, hashI, sp.Body); err != nil {
			return nil, refuse(notifyInvalidSignature, "member %v: %v", r.addr, err)
		}
		peer.Certificate = leaf
	}
	r.peer = peer

	idir := r.s.cfg.ownID(localAddr(r.s.conn))
	hashR := prf(hf, r.skeyid, r.dh.pub, r.gxi, r.rc[:], r.ic[:], r.saI, idir.body())
	out := []payload{{Type: pID, Body: idir.body()}}
	if r.auth == authPSK {
		out = append(out, payload{Type: pHash, Body: hashR})
	} else {
		sig, err := sign(r.auth, r.s.cfg.Key, hashR)
		if err != nil {
			return nil, err
		}
		out = append(out, certPayloads(r.s.cfg.Certificate)...)
		out = append(out, payload{Type: pSig, Body: sig})
	}
	resp, last := r.k.sealed(header{ICookie: r.ic, RCookie: r.rc, Exchange: xchgMain}, out, iv)
	r.k.phase1Last = last
	r.state = stateEstablished
	return resp, nil
}

func localAddr(c net.PacketConn) net.Addr {
	if c == nil {
		return nil
	}
	return c.LocalAddr()
}

// pull serves the GROUPKEY-PULL exchange: message 1 with the group's
// policy, message 3 with its keys. Nothing about the member is recorded
// before message 3 proves it holds the server's nonce.
func (r *responder) pull(h *header, msg []byte) ([]byte, error) {
	p := r.pulls[h.MsgID]
	if p != nil && p.lastReq != nil && bytes.Equal(msg, p.lastReq) {
		return p.lastResp, nil
	}
	if p == nil {
		if len(r.pulls) >= 16 {
			return nil, errors.New("gdoi: too many GROUPKEY-PULL exchanges on one phase 1 SA")
		}
		p = &pullState{iv: r.k.phase2IV(h.MsgID)}
	}
	if p.done {
		return nil, errors.New("gdoi: message for a completed GROUPKEY-PULL")
	}
	_, ps, chain, iv, err := r.k.open(msg, p.iv)
	if err != nil {
		return nil, err
	}
	hp, rest, covered, err := hashed(ps, chain)
	if err != nil {
		return nil, err
	}
	a, hf := r.k.a, r.k.hash
	mid := midBytes(h.MsgID)
	hdr := header{ICookie: r.ic, RCookie: r.rc, Exchange: xchgPull, MsgID: h.MsgID}

	if p.ni == nil {
		// Message 1: HASH(1) = prf(SKEYID_a, M-ID | Ni | ID).
		if !constantEqual(hp.Body, prf(hf, a, mid, covered)) {
			return nil, refuse(notifyInvalidHashInfo, "HASH(1) from %v does not verify", r.addr)
		}
		nonce, ok1 := find(rest, pNonce)
		idp, ok2 := find(rest, pID)
		if !ok1 || !ok2 {
			return nil, malformed("GROUPKEY-PULL request without nonce and ID")
		}
		if len(nonce.Body) < 8 || len(nonce.Body) > 128 {
			return nil, malformed("nonce of %d octets", len(nonce.Body))
		}
		id, err := parseID(idp.Body)
		if err != nil {
			return nil, err
		}
		group, err := groupFromID(id)
		if err != nil {
			return nil, refuse(notifyInvalidIDInfo, "%v", err)
		}
		g, ok := r.s.groups[group.key()]
		if !ok {
			return nil, refuse(notifyInvalidIDInfo, "%v asked for unknown %v", r.peer, group)
		}
		if !r.s.cfg.Authorize(r.peer, group) {
			return nil, refuse(notifyInvalidIDInfo, "%v is not authorised for %v", r.peer, group)
		}
		teks := g.snapshot(time.Now())
		sa, err := saBody(teks)
		if err != nil {
			return nil, refuse(notifyInvalidIDInfo, "%v has no keys: %v", group, err)
		}
		p.ni, p.nr, p.group, p.teks = clone(nonce.Body), randomBytes(nonceLen), group, teks
		out := []payload{{Type: pNonce, Body: p.nr}, {Type: pSA, Body: sa}}
		h2 := prf(hf, a, mid, p.ni, encodeChain(out, pNone))
		resp, next := r.k.sealed(hdr, append([]payload{{Type: pHash, Body: h2}}, out...), iv)
		p.iv, p.lastReq, p.lastResp = next, msg, resp
		r.pulls[h.MsgID] = p
		return resp, nil
	}

	// Message 3: HASH(3) = prf(SKEYID_a, M-ID | Ni_b | Nr_b [| GAP]).
	if !constantEqual(hp.Body, prf(hf, a, mid, p.ni, p.nr, covered)) {
		return nil, refuse(notifyInvalidHashInfo, "HASH(3) from %v does not verify", r.addr)
	}
	out := []payload{{Type: pKD, Body: kdBody(p.teks)}}
	h4 := prf(hf, a, mid, p.ni, p.nr, encodeChain(out, pNone))
	resp, _ := r.k.sealed(hdr, append([]payload{{Type: pHash, Body: h4}}, out...), iv)
	p.done, p.lastReq, p.lastResp = true, msg, resp
	if r.s.cfg.OnRegister != nil {
		r.s.cfg.OnRegister(r.peer, p.group, p.teks)
	}
	// The state stays, so a retransmitted message 3 gets message 4 again
	// (the cache at the top); anything else for this exchange is refused.
	return resp, nil
}
