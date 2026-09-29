package gdoi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

// MemberConfig configures a group member's registrations with a key
// server (the GCKS).
type MemberConfig struct {
	// Server is the key server, "host:port" (port 848 when omitted).
	Server string
	// Credentials authenticate this member to the key server and the key
	// server to it.
	Credentials
	// AuthorizeServer decides whether the authenticated key server is one
	// this member takes keys from: RFC 6407 requires a member to list its
	// authorised key servers, since any peer the roots vouch for could
	// otherwise hand it keys. Required with certificate credentials. With
	// a pre-shared key, holding the key is the authorisation, and nil
	// accepts it.
	AuthorizeServer func(Peer) error
	// Suites are the phase 1 algorithms offered, in order of preference
	// (DefaultSuites when empty).
	Suites []Suite
	// Retransmit is how long to wait for a reply before sending a request
	// again (1 s when 0), and Attempts how many times to send it (4 when
	// 0).
	Retransmit time.Duration
	Attempts   int
}

// keyLog, when set (by tests), is given each phase 1 SA's initiator cookie
// and encryption key, the pair Wireshark decrypts IKEv1 with.
var keyLog func(icookie [8]byte, encKey []byte)

// ErrTimeout is a key server that did not answer.
var ErrTimeout = errors.New("gdoi: key server did not answer")

func (c *MemberConfig) check() (uint16, error) {
	auth, err := c.authMethod()
	if err != nil {
		return 0, err
	}
	if auth != authPSK && c.AuthorizeServer == nil {
		return 0, errors.New("gdoi: MemberConfig.AuthorizeServer is required with certificate credentials")
	}
	for _, s := range c.Suites {
		if !s.valid() {
			return 0, fmt.Errorf("gdoi: suite %+v is not supported", s)
		}
	}
	return auth, nil
}

// Registration is the result of one GROUPKEY-PULL: the group's current
// TEKs, the key server that issued them, and when.
type Registration struct {
	Group    GroupID
	Server   Peer
	TEKs     []TEK
	Received time.Time
}

// Register runs one registration: a phase 1 exchange authenticating the
// member and the key server to each other (IKE main mode, RFC 2409), then
// a GROUPKEY-PULL for group (RFC 6407 3), and returns the group's TEKs.
func Register(ctx context.Context, cfg MemberConfig, group GroupID) (*Registration, error) {
	auth, err := cfg.check()
	if err != nil {
		return nil, err
	}
	if len(cfg.Suites) == 0 {
		cfg.Suites = DefaultSuites
	}
	if cfg.Retransmit <= 0 {
		cfg.Retransmit = time.Second
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 4
	}
	addr := cfg.Server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, strconv.Itoa(DefaultPort))
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("gdoi: %w", err)
	}
	defer conn.Close()
	m := &initiator{cfg: &cfg, auth: auth, conn: conn}
	peer, err := m.phase1(ctx)
	if err != nil {
		return nil, err
	}
	teks, err := m.pull(ctx, group)
	if err != nil {
		return nil, err
	}
	return &Registration{Group: group, Server: peer, TEKs: teks, Received: time.Now()}, nil
}

type initiator struct {
	cfg    *MemberConfig
	auth   uint16
	conn   net.Conn
	ic, rc [8]byte
	k      *keys
}

// roundTrip sends req until a reply the match accepts arrives, or an
// informational message refusing the exchange. Replies to other exchanges
// are ignored.
func (m *initiator) roundTrip(ctx context.Context, req []byte, match func(*header) bool) ([]byte, error) {
	buf := make([]byte, maxMessage)
	for attempt := 0; attempt < m.cfg.Attempts; attempt++ {
		if _, err := m.conn.Write(req); err != nil {
			return nil, fmt.Errorf("gdoi: %w", err)
		}
		deadline := time.Now().Add(m.cfg.Retransmit)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		m.conn.SetReadDeadline(deadline)
		for {
			n, err := m.conn.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return nil, fmt.Errorf("gdoi: %w", err)
			}
			h, err := parseHeader(buf[:n])
			if err != nil || h.ICookie != m.ic {
				continue
			}
			msg := clone(buf[:n])
			if h.Exchange == xchgInfo {
				if ne, err := readInformational(m.k, msg); err == nil {
					return nil, ne
				}
				continue
			}
			if match(h) {
				return msg, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	return nil, ErrTimeout
}

// phase1 runs main mode as initiator.
func (m *initiator) phase1(ctx context.Context) (Peer, error) {
	m.ic = randomCookie()
	saI := phase1SABody(m.cfg.Suites, m.auth)
	msg1 := message(header{ICookie: m.ic, Exchange: xchgMain}, []payload{{Type: pSA, Body: saI}})
	resp, err := m.roundTrip(ctx, msg1, func(h *header) bool {
		return h.Exchange == xchgMain && h.RCookie != [8]byte{} && h.Flags&flagEncrypted == 0
	})
	if err != nil {
		return Peer{}, err
	}
	h, ps, _, _, err := m.k.open(resp, nil)
	if err != nil {
		return Peer{}, err
	}
	m.rc = h.RCookie
	sa, ok := find(ps, pSA)
	if !ok {
		return Peer{}, malformed("main mode reply without an SA")
	}
	chosen, err := parsePhase1SA(sa.Body)
	if err != nil {
		return Peer{}, err
	}
	if len(chosen) != 1 || !offered(saI, chosen[0].body) {
		return Peer{}, errors.New("gdoi: key server chose a transform that was not offered")
	}
	suite := chosen[0].suite

	d, err := newDH(suite.Group)
	if err != nil {
		return Peer{}, err
	}
	ni := randomBytes(nonceLen)
	hdr := header{ICookie: m.ic, RCookie: m.rc, Exchange: xchgMain}
	msg3 := message(hdr, []payload{{Type: pKE, Body: d.pub}, {Type: pNonce, Body: ni}})
	resp, err = m.roundTrip(ctx, msg3, func(h *header) bool {
		return h.Exchange == xchgMain && h.RCookie == m.rc && h.Flags&flagEncrypted == 0 && h.Next != pSA
	})
	if err != nil {
		return Peer{}, err
	}
	_, ps, _, _, err = m.k.open(resp, nil)
	if err != nil {
		return Peer{}, err
	}
	ke, ok1 := find(ps, pKE)
	nonce, ok2 := find(ps, pNonce)
	if !ok1 || !ok2 {
		return Peer{}, malformed("main mode reply without KE and nonce")
	}
	nr := nonce.Body
	if len(nr) < 8 || len(nr) > 256 {
		return Peer{}, malformed("nonce of %d octets", len(nr))
	}
	gxy, err := d.shared(ke.Body)
	if err != nil {
		return Peer{}, err
	}
	hf := suite.newHash()
	var skeyid []byte
	if m.auth == authPSK {
		skeyid = prf(hf, m.cfg.PSK, ni, nr)
	} else {
		skeyid = prf(hf, append(clone(ni), nr...), gxy)
	}
	if m.k, err = deriveKeys(suite, skeyid, gxy, m.ic[:], m.rc[:]); err != nil {
		return Peer{}, err
	}
	if keyLog != nil {
		keyLog(m.ic, m.k.encKey)
	}

	idii := m.cfg.ownID(m.conn.LocalAddr())
	hashI := prf(hf, skeyid, d.pub, ke.Body, m.ic[:], m.rc[:], saI, idii.body())
	ps5 := []payload{{Type: pID, Body: idii.body()}}
	if m.auth == authPSK {
		ps5 = append(ps5, payload{Type: pHash, Body: hashI})
	} else {
		sig, err := sign(m.auth, m.cfg.Key, hashI)
		if err != nil {
			return Peer{}, err
		}
		ps5 = append(ps5, certPayloads(m.cfg.Certificate)...)
		ps5 = append(ps5, payload{Type: pSig, Body: sig})
	}
	msg5, iv := m.k.sealed(hdr, ps5, phase1IV(hf, d.pub, ke.Body))
	resp, err = m.roundTrip(ctx, msg5, func(h *header) bool {
		return h.Exchange == xchgMain && h.RCookie == m.rc && h.Flags&flagEncrypted != 0
	})
	if err != nil {
		return Peer{}, err
	}
	_, ps, _, last, err := m.k.open(resp, iv)
	if err != nil {
		return Peer{}, err
	}
	m.k.phase1Last = last
	idp, ok := find(ps, pID)
	if !ok {
		return Peer{}, malformed("main mode reply without identification")
	}
	idir, err := parseID(idp.Body)
	if err != nil {
		return Peer{}, err
	}
	hashR := prf(hf, skeyid, ke.Body, d.pub, m.rc[:], m.ic[:], saI, idir.body())
	peer := Peer{Addr: m.conn.RemoteAddr(), IDType: idir.Type, ID: clone(idir.Data)}
	if m.auth == authPSK {
		hp, ok := find(ps, pHash)
		if !ok || !constantEqual(hp.Body, hashR) {
			return Peer{}, errors.New("gdoi: key server failed pre-shared key authentication")
		}
	} else {
		certs, err := parseCerts(ps)
		if err != nil {
			return Peer{}, err
		}
		leaf, err := m.cfg.verifyPeer(idir, certs, time.Now())
		if err != nil {
			return Peer{}, err
		}
		sp, ok := find(ps, pSig)
		if !ok {
			return Peer{}, malformed("main mode reply without a signature")
		}
		if err := verify(m.auth, leaf, hashR, sp.Body); err != nil {
			return Peer{}, fmt.Errorf("gdoi: key server signature: %w", err)
		}
		peer.Certificate = leaf
	}
	if m.cfg.AuthorizeServer != nil {
		if err := m.cfg.AuthorizeServer(peer); err != nil {
			return Peer{}, fmt.Errorf("gdoi: key server %s not authorised: %w", peer, err)
		}
	}
	return peer, nil
}

// offered reports whether a transform body is one of those in the SA the
// member sent: a responder must return an offer unchanged.
func offered(saI, body []byte) bool {
	ts, err := parsePhase1SA(saI)
	if err != nil {
		return false
	}
	for _, t := range ts {
		if bytes.Equal(t.body, body) {
			return true
		}
	}
	return false
}

// pull runs the GROUPKEY-PULL exchange (RFC 6407 figure 2).
func (m *initiator) pull(ctx context.Context, group GroupID) ([]TEK, error) {
	id, err := group.id()
	if err != nil {
		return nil, err
	}
	mid := randomMsgID()
	hdr := header{ICookie: m.ic, RCookie: m.rc, Exchange: xchgPull, MsgID: mid}
	a, hf := m.k.a, m.k.hash
	ni := randomBytes(nonceLen)
	rest := []payload{{Type: pNonce, Body: ni}, {Type: pID, Body: id.body()}}
	h1 := prf(hf, a, midBytes(mid), encodeChain(rest, pNone))
	msg1, iv := m.k.sealed(hdr, append([]payload{{Type: pHash, Body: h1}}, rest...), m.k.phase2IV(mid))
	match := func(h *header) bool {
		return h.Exchange == xchgPull && h.MsgID == mid && h.RCookie == m.rc && h.Flags&flagEncrypted != 0
	}
	resp, err := m.roundTrip(ctx, msg1, match)
	if err != nil {
		return nil, err
	}
	_, ps, chain, iv, err := m.k.open(resp, iv)
	if err != nil {
		return nil, err
	}
	hp, rest2, covered, err := hashed(ps, chain)
	if err != nil {
		return nil, err
	}
	if !constantEqual(hp.Body, prf(hf, a, midBytes(mid), ni, covered)) {
		return nil, errors.New("gdoi: HASH(2) does not verify")
	}
	nonce, ok1 := find(rest2, pNonce)
	sa, ok2 := find(rest2, pSA)
	if !ok1 || !ok2 {
		return nil, malformed("GROUPKEY-PULL reply without nonce and SA")
	}
	nr := nonce.Body
	if len(nr) < 8 || len(nr) > 128 {
		return nil, malformed("nonce of %d octets", len(nr))
	}
	policy, err := parseSA(sa.Body)
	if err != nil {
		return nil, err
	}
	if len(policy) == 0 {
		return nil, errors.New("gdoi: the group's policy has no IEC 61850 TEK")
	}

	h3 := prf(hf, a, midBytes(mid), ni, nr)
	msg3, iv := m.k.sealed(hdr, []payload{{Type: pHash, Body: h3}}, iv)
	resp, err = m.roundTrip(ctx, msg3, match)
	if err != nil {
		return nil, err
	}
	_, ps, chain, _, err = m.k.open(resp, iv)
	if err != nil {
		return nil, err
	}
	hp, rest4, covered, err := hashed(ps, chain)
	if err != nil {
		return nil, err
	}
	if !constantEqual(hp.Body, prf(hf, a, midBytes(mid), ni, nr, covered)) {
		return nil, errors.New("gdoi: HASH(4) does not verify")
	}
	kd, ok := find(rest4, pKD)
	if !ok {
		return nil, malformed("GROUPKEY-PULL reply without key download")
	}
	material, err := parseKD(kd.Body)
	if err != nil {
		return nil, err
	}
	var teks []TEK
	for _, t := range policy {
		kp, ok := material[t.SPI]
		if !ok {
			return nil, fmt.Errorf("gdoi: no keys for TEK %d", t.SPI)
		}
		t.AlgorithmKey, t.IntegrityKey = kp.algorithm, kp.integrity
		if err := t.checkPolicy(); err != nil {
			return nil, err
		}
		teks = append(teks, *t)
	}
	return teks, nil
}
