package gdoi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The ECP-256 key exchange against the test vectors of RFC 5903 8.1: the
// KE value is x|y, the shared secret the x coordinate.
func TestECP256Vectors(t *testing.T) {
	i := unhex(t, "C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433")
	gi := unhex(t, `DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180
		5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3`)
	gr := unhex(t, `D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63
		56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB`)
	gir := unhex(t, "D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE")
	k, err := ecdh.P256().NewPrivateKey(i)
	if err != nil {
		t.Fatal(err)
	}
	d := &dh{group: groupECP256, ecKey: k, pub: k.PublicKey().Bytes()[1:]}
	if !bytes.Equal(d.pub, gi) {
		t.Errorf("KE value = %x, want %x", d.pub, gi)
	}
	s, err := d.shared(gr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s, gir) {
		t.Errorf("g^xy = %x, want %x", s, gir)
	}
}

// Both ends of every group agree on the secret.
func TestDHAgreement(t *testing.T) {
	for _, g := range []int{groupMODP2048, groupECP256, groupECP384} {
		a, err := newDH(g)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := newDH(g)
		sa, err1 := a.shared(b.pub)
		sb, err2 := b.shared(a.pub)
		if err1 != nil || err2 != nil || !bytes.Equal(sa, sb) {
			t.Errorf("group %d: %v %v", g, err1, err2)
		}
	}
	// Degenerate MODP values are refused.
	a, _ := newDH(groupMODP2048)
	if _, err := a.shared(make([]byte, modpLen)); err == nil {
		t.Error("g^y = 0 accepted")
	}
	one := make([]byte, modpLen)
	one[modpLen-1] = 1
	if _, err := a.shared(one); err == nil {
		t.Error("g^y = 1 accepted")
	}
}

var testOID = asn1.ObjectIdentifier{1, 2, 840, 10070, 61850, 1}

func TestTEKCodec(t *testing.T) {
	sel, _ := asn1.Marshal([]byte{239, 192, 0, 1})
	tek, err := NewTEK(testOID, sel, AuthNone, EncAESGCM128, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tek.ActivationDelay, tek.KDA = 30*time.Second, 75
	sa, err := saBody([]TEK{tek})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseSA(sa)
	if err != nil || len(got) != 1 {
		t.Fatalf("parseSA: %v %v", got, err)
	}
	g := got[0]
	if g.SPI != tek.SPI || !g.OID.Equal(testOID) || !bytes.Equal(g.Selector, sel) || g.Auth != AuthNone ||
		g.Enc != EncAESGCM128 || g.Lifetime != time.Hour || g.ActivationDelay != 30*time.Second || g.KDA != 75 {
		t.Errorf("TEK = %+v", g)
	}
	keys, err := parseKD(kdBody([]TEK{tek}))
	if err != nil {
		t.Fatal(err)
	}
	if kp := keys[tek.SPI]; !bytes.Equal(kp.algorithm, tek.AlgorithmKey) || kp.integrity != nil {
		t.Errorf("KD = %+v", keys)
	}
	// The RFC 8052 key layouts.
	for _, tc := range []struct {
		auth     AuthAlg
		enc      EncAlg
		ilen, al int
	}{
		{AuthHMACSHA256128, EncNone, 32, 0}, {AuthHMACSHA256, EncNone, 32, 0},
		{AuthNone, EncAESGCM128, 0, 20}, {AuthNone, EncAESGCM256, 0, 36},
		{AuthHMACSHA256, EncAESCBC128, 32, 16}, {AuthAESGMAC128, EncNone, 20, 0},
	} {
		k, err := NewTEK(testOID, nil, tc.auth, tc.enc, 0)
		if err != nil || len(k.IntegrityKey) != tc.ilen || len(k.AlgorithmKey) != tc.al {
			t.Errorf("%v/%v: %d/%d octets, %v", tc.auth, tc.enc, len(k.IntegrityKey), len(k.AlgorithmKey), err)
		}
	}
	// Combinations RFC 8052 forbids.
	for _, tc := range []struct {
		auth AuthAlg
		enc  EncAlg
	}{{AuthHMACSHA256, EncAESGCM128}, {AuthNone, EncAESCBC128}, {AuthNone, EncNone}} {
		if _, err := NewTEK(testOID, nil, tc.auth, tc.enc, 0); !errors.Is(err, ErrTEKPolicy) {
			t.Errorf("%v/%v allowed", tc.auth, tc.enc)
		}
	}
	// The session layer's view of a TEK.
	k, _ := NewTEK(testOID, nil, AuthNone, EncAESGCM256, 0)
	rk, err := k.RSessionKey()
	if err != nil || rk.ID != k.SPI || len(rk.Material) != 32 || !bytes.Equal(rk.Material, k.AlgorithmKey[:32]) {
		t.Errorf("GCM-256 session key %+v, %v", rk, err)
	}
	k, _ = NewTEK(testOID, nil, AuthHMACSHA256, EncAESCBC256, 0)
	if _, err := k.RSessionKey(); !errors.Is(err, ErrTEKUnsupported) {
		t.Errorf("CBC session key: %v", err)
	}
}

func TestGroupIDCodec(t *testing.T) {
	for _, g := range []GroupID{{KeyID: 1234}, {OID: testOID}, {OID: testOID, Selector: []byte{4, 2, 1, 2}}} {
		id, err := g.id()
		if err != nil {
			t.Fatal(err)
		}
		back, err := groupFromID(id)
		if err != nil || back.key() != g.key() {
			t.Errorf("%v round-tripped to %v, %v", g, back, err)
		}
	}
	id, _ := GroupID{OID: testOID}.id()
	// RFC 8052 figure 2: OID length, DER OID, selector length.
	der, _ := asn1.Marshal(testOID)
	want := append([]byte{byte(len(der))}, der...)
	want = append(want, 0, 0)
	if id.Type != IDOID || !bytes.Equal(id.Data, want) {
		t.Errorf("ID_OID data = % x, want % x", id.Data, want)
	}
}

// --- End to end ---

type pki struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newPKI(t testing.TB, name string) *pki {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{cert: c, key: k}
}

func (p *pki) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.cert)
	return pool
}

var serial int64 = 10

func (p *pki) issue(t testing.TB, cn string, key crypto.Signer) Credentials {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn, Organization: []string{"substation"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, key.Public(), p.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return Credentials{Certificate: []*x509.Certificate{c}, Key: key, Roots: p.pool()}
}

func ecKey(t testing.TB, c elliptic.Curve) crypto.Signer {
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	rsaOnce sync.Once
	rsaKeys [2]*rsa.PrivateKey
)

func rsaKey(t testing.TB, i int) crypto.Signer {
	rsaOnce.Do(func() {
		for j := range rsaKeys {
			rsaKeys[j], _ = rsa.GenerateKey(rand.Reader, 2048)
		}
	})
	return rsaKeys[i]
}

type rig struct {
	srv    *Server
	addr   string
	group  GroupID
	g      *Group
	events chan string
}

// newRig starts a key server with one group holding one TEK.
func newRig(t *testing.T, cfg ServerConfig) *rig {
	t.Helper()
	r := &rig{group: GroupID{OID: testOID}, g: &Group{}, events: make(chan string, 64)}
	if cfg.Authorize == nil {
		cfg.Authorize = func(Peer, GroupID) bool { return true }
	}
	cfg.OnReject = func(_ net.Addr, err error) { r.events <- "reject: " + err.Error() }
	cfg.OnRegister = func(p Peer, g GroupID, _ []TEK) { r.events <- "register: " + p.String() }
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tek, err := NewTEK(testOID, nil, AuthNone, EncAESGCM128, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.g.Add(tek); err != nil {
		t.Fatal(err)
	}
	s.AddGroup(r.group, r.g)
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(c)
	t.Cleanup(func() { s.Close() })
	r.srv, r.addr = s, c.LocalAddr().String()
	return r
}

func register(t *testing.T, r *rig, cfg MemberConfig) (*Registration, error) {
	t.Helper()
	cfg.Server = r.addr
	if cfg.Retransmit == 0 {
		cfg.Retransmit = 300 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Register(ctx, cfg, r.group)
}

func checkRegistration(t *testing.T, r *rig, reg *Registration) {
	t.Helper()
	want := r.g.snapshot(time.Now())
	if len(reg.TEKs) != len(want) {
		t.Fatalf("%d TEKs, want %d", len(reg.TEKs), len(want))
	}
	got := reg.TEKs[0]
	if got.SPI != want[0].SPI || !bytes.Equal(got.AlgorithmKey, want[0].AlgorithmKey) ||
		got.Enc != EncAESGCM128 || got.Lifetime <= 59*time.Minute || got.Lifetime > time.Hour {
		t.Errorf("TEK %+v, want SPI %d", got, want[0].SPI)
	}
}

func TestRegisterWithCertificates(t *testing.T) {
	ca := newPKI(t, "substation CA")
	for _, tc := range []struct {
		name       string
		ksKey, gmK crypto.Signer
		suites     []Suite
	}{
		{"ECDSA-256", ecKey(t, elliptic.P256()), ecKey(t, elliptic.P256()), nil},
		{"ECDSA-384", ecKey(t, elliptic.P384()), ecKey(t, elliptic.P384()),
			[]Suite{{KeyBits: 256, Hash: hashSHA384, Group: groupECP384}}},
		{"RSA", rsaKey(t, 0), rsaKey(t, 1), nil},
		{"MODP-2048", ecKey(t, elliptic.P256()), ecKey(t, elliptic.P256()),
			[]Suite{{KeyBits: 128, Hash: hashSHA256, Group: groupMODP2048}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ksCred := ca.issue(t, "ks1", tc.ksKey)
			r := newRig(t, ServerConfig{Credentials: ksCred, Suites: append(tc.suites, DefaultSuites...)})
			var authorised Peer
			reg, err := register(t, r, MemberConfig{
				Credentials: ca.issue(t, "ied1", tc.gmK),
				Suites:      tc.suites,
				AuthorizeServer: func(p Peer) error {
					authorised = p
					if p.Certificate.Subject.CommonName != "ks1" {
						return errors.New("not our key server")
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			checkRegistration(t, r, reg)
			if authorised.Certificate == nil || reg.Server.Certificate.Subject.CommonName != "ks1" {
				t.Errorf("server identity %v", reg.Server)
			}
			if ev := <-r.events; !strings.Contains(ev, "register: CN=ied1") {
				t.Errorf("key server event %q", ev)
			}
		})
	}
}

func TestRegisterWithPSK(t *testing.T) {
	psk := []byte("substation pre-shared secret")
	r := newRig(t, ServerConfig{PSK: func(net.Addr) []byte { return psk }})
	reg, err := register(t, r, MemberConfig{Credentials: Credentials{PSK: psk}})
	if err != nil {
		t.Fatal(err)
	}
	checkRegistration(t, r, reg)

	// The wrong key fails authentication, and the member is told.
	_, err = register(t, r, MemberConfig{Credentials: Credentials{PSK: []byte("wrong secret")}})
	var ne *NotifyError
	if !errors.As(err, &ne) || ne.Type != notifyAuthFailed {
		t.Errorf("wrong PSK: %v", err)
	}
}

func TestAuthorization(t *testing.T) {
	ca := newPKI(t, "substation CA")
	ksCred := ca.issue(t, "ks1", ecKey(t, elliptic.P256()))
	r := newRig(t, ServerConfig{Credentials: ksCred, Authorize: func(p Peer, g GroupID) bool {
		return p.Certificate.Subject.CommonName == "ied1"
	}})
	anyKS := func(Peer) error { return nil }

	// A member the key server does not authorise gets no keys.
	_, err := register(t, r, MemberConfig{Credentials: ca.issue(t, "intruder", ecKey(t, elliptic.P256())), AuthorizeServer: anyKS})
	var ne *NotifyError
	if !errors.As(err, &ne) || ne.Type != notifyInvalidIDInfo {
		t.Errorf("unauthorised member: %v", err)
	}
	// Nor does one asking for a group the server does not have.
	cred := ca.issue(t, "ied1", ecKey(t, elliptic.P256()))
	cfg := MemberConfig{Credentials: cred, AuthorizeServer: anyKS, Server: r.addr, Retransmit: 300 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Register(ctx, cfg, GroupID{KeyID: 99}); !errors.As(err, &ne) || ne.Type != notifyInvalidIDInfo {
		t.Errorf("unknown group: %v", err)
	}
	// A member refuses a key server it has not been told to trust...
	if _, err := register(t, r, MemberConfig{Credentials: cred, AuthorizeServer: func(Peer) error {
		return errors.New("no")
	}}); err == nil || !strings.Contains(err.Error(), "not authorised") {
		t.Errorf("unauthorised key server: %v", err)
	}
	// ...and must be told, with certificates.
	if _, err := register(t, r, MemberConfig{Credentials: cred}); err == nil {
		t.Error("a member without AuthorizeServer registered")
	}
	// A member from another authority fails certificate verification.
	other := newPKI(t, "other CA")
	stranger := other.issue(t, "ied1", ecKey(t, elliptic.P256()))
	stranger.Roots = ca.pool()
	if _, err := register(t, r, MemberConfig{Credentials: stranger, AuthorizeServer: anyKS}); !errors.As(err, &ne) || ne.Type != notifyInvalidCert {
		t.Errorf("foreign member: %v", err)
	}
	// And a member refuses a key server from another authority.
	r2 := newRig(t, ServerConfig{Credentials: other.issue(t, "ks-evil", ecKey(t, elliptic.P256()))})
	cred2 := cred
	if _, err := register(t, r2, MemberConfig{Credentials: cred2, AuthorizeServer: anyKS}); err == nil {
		t.Error("a key server from another authority was accepted")
	}
}

// lossy is a UDP relay between a member and a key server that drops the
// first copy of every datagram, in both directions, so every message is
// only delivered on retransmission.
type lossy struct {
	c    net.PacketConn
	to   *net.UDPAddr
	seen map[string]bool
}

func newLossy(t *testing.T, to string, mangle func([]byte)) string {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); up.Close() })
	ks, _ := net.ResolveUDPAddr("udp", to)
	var mu sync.Mutex
	seen := map[string]bool{}
	var member net.Addr
	pass := func(b []byte) bool {
		mu.Lock()
		defer mu.Unlock()
		k := string(b)
		if seen[k] {
			return true
		}
		seen[k] = true
		return false
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			member = a
			mu.Unlock()
			if pass(buf[:n]) {
				up.WriteTo(buf[:n], ks)
			}
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			b := clone(buf[:n])
			if mangle != nil {
				mangle(b)
			}
			mu.Lock()
			m := member
			mu.Unlock()
			if pass(buf[:n]) {
				c.WriteTo(b, m)
			}
		}
	}()
	return c.LocalAddr().String()
}

// Every message lost once: the exchange completes on retransmissions, and
// the key server answers a repeated request with the reply it gave.
func TestRetransmission(t *testing.T) {
	psk := []byte("substation pre-shared secret")
	r := newRig(t, ServerConfig{PSK: func(net.Addr) []byte { return psk }})
	cfg := MemberConfig{Credentials: Credentials{PSK: psk}, Retransmit: 200 * time.Millisecond, Attempts: 5}
	cfg.Server = newLossy(t, r.addr, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reg, err := Register(ctx, cfg, r.group)
	if err != nil {
		t.Fatal(err)
	}
	checkRegistration(t, r, reg)
}

// A key server reply altered on the way is refused.
func TestTamperedReply(t *testing.T) {
	psk := []byte("substation pre-shared secret")
	r := newRig(t, ServerConfig{PSK: func(net.Addr) []byte { return psk }})
	cfg := MemberConfig{Credentials: Credentials{PSK: psk}, Retransmit: 200 * time.Millisecond, Attempts: 3}
	// Flip a bit in the last ciphertext block of every encrypted reply.
	cfg.Server = newLossy(t, r.addr, func(b []byte) {
		if len(b) > headerLen && b[19]&flagEncrypted != 0 {
			b[len(b)-1] ^= 1
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Register(ctx, cfg, r.group); err == nil {
		t.Fatal("a tampered exchange completed")
	}
}

// Nothing a peer sends makes the key server or the codec panic.
func FuzzServerHandle(f *testing.F) {
	f.Add(make([]byte, 28))
	sa := phase1SABody(DefaultSuites, authPSK)
	f.Add(message(header{ICookie: [8]byte{1}, Exchange: xchgMain}, []payload{{Type: pSA, Body: sa}}))
	s, err := NewServer(ServerConfig{PSK: func(net.Addr) []byte { return []byte("k") },
		Authorize: func(Peer, GroupID) bool { return true }})
	if err != nil {
		f.Fatal(err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	f.Fuzz(func(t *testing.T, b []byte) {
		s.handle(b, addr)
		parseSA(b)
		parseKD(b)
		parseSAT(b)
		parsePhase1SA(b)
		if id, err := parseID(b); err == nil {
			groupFromID(id)
		}
	})
}
