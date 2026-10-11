package e2e

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

var (
	clientAE = AETitle{APTitle: asn1.OID{1, 3, 9999, 1}, AEQualifier: 1}
	serverAE = AETitle{APTitle: asn1.OID{1, 3, 9999, 2}, AEQualifier: 7}
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	root    *pkitest.CA
	inter   *pkitest.CA
	cli     *ClientConfig
	srv     *ServerConfig
	clk     *clock
	events  []Event
	eventMu sync.Mutex
}

func newFixture(t *testing.T, cliKey, srvKey pkitest.KeyType) *fixture {
	t.Helper()
	f := &fixture{clk: &clock{t: time.Now()}}
	f.root = pkitest.NewRoot("root", pkitest.ECDSAP256)
	f.inter = f.root.NewIntermediate("issuing", pkitest.ECDSAP256)
	cl := f.inter.NewE2ELeaf(clientAE.APTitle, clientAE.AEQualifier, pkitest.LeafOptions{KeyType: cliKey})
	sl := f.root.NewE2ELeaf(serverAE.APTitle, serverAE.AEQualifier, pkitest.LeafOptions{KeyType: srvKey})
	trust := pki.NewTrustStore(f.root.Cert)
	onEvent := func(e Event) { f.eventMu.Lock(); f.events = append(f.events, e); f.eventMu.Unlock() }
	f.cli = &ClientConfig{
		Local:  Identity{AE: clientAE, Certificate: cl.DER, Path: [][]byte{f.inter.Cert.Raw}, Signer: cl.Key},
		Policy: Policy{Trust: trust}, Peer: serverAE, Clock: f.clk.now, OnEvent: onEvent,
	}
	f.srv = &ServerConfig{
		Local:  Identity{AE: serverAE, Certificate: sl.DER, Signer: sl.Key},
		Policy: Policy{Trust: trust}, Clock: f.clk.now, OnEvent: onEvent,
	}
	return f
}

func content(t *testing.T, tlv []byte) []byte {
	t.Helper()
	c, err := asn1.NewDecoder(tlv).Expect(asn1.TagSequence)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var appl = []byte{0x28, 0x08, 0x02, 0x01, 0x03, 0xa0, 0x03, 0x81, 0x01, 0x00}

func establish(t *testing.T, f *fixture) (*Association, *Association) {
	t.Helper()
	c, err := NewClient(f.cli)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(f.srv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := c.HandshakeRequest(appl)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.ProcessHandshakeRequest(content(t, req), clientAE)
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	if !bytes.Equal(got, appl) {
		t.Fatal("applData lost")
	}
	acc, err := s.HandshakeAccept(appl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ProcessHandshakeAccept(content(t, acc), serverAE); err != nil {
		t.Fatalf("client: %v", err)
	}
	return c, s
}

func transfer(t *testing.T, from, to *Association) {
	t.Helper()
	pdu, err := from.Seal(appl)
	if err != nil {
		t.Fatal(err)
	}
	got, err := to.Open(content(t, pdu), false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, appl) {
		t.Fatal("applData changed")
	}
}

func TestAssociation(t *testing.T) {
	for _, kt := range []struct {
		name     string
		cli, srv pkitest.KeyType
		group    Group
		icv      ICVAlg
	}{
		{"ecdsa-p256-hmac", pkitest.ECDSAP256, pkitest.ECDSAP256, GroupP256, ICVHMACSHA256},
		{"rsa-modp-gmac128", pkitest.RSA2048, pkitest.RSA2048, GroupMODP2048, ICVGMACAES128},
		{"mixed-gmac256", pkitest.RSA2048, pkitest.ECDSAP256, GroupP256, ICVGMACAES256},
	} {
		t.Run(kt.name, func(t *testing.T) {
			f := newFixture(t, kt.cli, kt.srv)
			f.cli.Policy.DHGroups = []Group{kt.group}
			f.cli.Policy.ICVAlgs = []ICVAlg{kt.icv}
			c, s := establish(t, f)
			if c.AssoID() != s.AssoID() || c.Peer().ICV != kt.icv || s.Peer().Group != kt.group {
				t.Fatalf("negotiation: %q %q %+v", c.AssoID(), s.AssoID(), c.Peer())
			}
			for i := 0; i < 5; i++ {
				transfer(t, c, s)
				transfer(t, s, c)
			}
			f.clk.add(time.Second)
			transfer(t, c, s)
			// Release.
			rq, err := c.ReleaseRequest()
			if err != nil {
				t.Fatal(err)
			}
			if err := s.ProcessReleaseRequest(content(t, rq)); err != nil {
				t.Fatal(err)
			}
			rs, err := s.ReleaseResponse()
			if err != nil {
				t.Fatal(err)
			}
			if err := c.ProcessReleaseResponse(content(t, rs)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRekey(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f.cli.Policy.RekeyInterval = 15 * time.Minute
	c, s := establish(t, f)
	transfer(t, c, s)
	f.clk.add(16 * time.Minute)
	// The client's next PDU carries rekey under the old keys; it then sends
	// with new keys at once.
	transfer(t, c, s)
	if !c.rekeyOut || !s.pendingChg {
		t.Fatal("rekey not in progress")
	}
	transfer(t, c, s) // new client keys
	transfer(t, s, c) // changedKey under old server keys
	if c.rekeyOut || s.pendingChg {
		t.Fatal("rekey not completed")
	}
	transfer(t, s, c) // new server keys
	transfer(t, c, s)
	if c.Peer().KeyEpoch != 1 || s.Peer().KeyEpoch != 1 {
		t.Fatalf("epochs %d %d", c.Peer().KeyEpoch, s.Peer().KeyEpoch)
	}
}

func TestServerRequestsRekey(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f.srv.Policy.RekeyRequest = 20 * time.Minute
	c, s := establish(t, f)
	f.clk.add(21 * time.Minute)
	transfer(t, s, c) // reqRekey
	if !c.RekeyDue() {
		t.Fatal("client did not register reqRekey")
	}
	transfer(t, c, s) // rekey
	transfer(t, s, c) // changedKey
	transfer(t, c, s)
	transfer(t, s, c)
	if c.Peer().KeyEpoch != 1 {
		t.Fatal("no new epoch")
	}
}

func wantHS(t *testing.T, err error, diag int, alarm Alarm) {
	t.Helper()
	se, ok := AsSecurityError(err)
	if !ok {
		t.Fatalf("not a security error: %v", err)
	}
	if se.Diag != diag || se.Alarm != alarm {
		t.Fatalf("got diag %s alarm %v (%v), want %s %v", HandshakeDiagName(se.Diag), se.Alarm, se.Err, HandshakeDiagName(diag), alarm)
	}
}

func TestHandshakeNegative(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)

	// Address mismatch: the client claims another AE title.
	c, _ := NewClient(f.cli)
	s, _ := NewServer(f.srv)
	req, _ := c.HandshakeRequest(appl)
	_, err := s.ProcessHandshakeRequest(content(t, req), AETitle{APTitle: asn1.OID{1, 3, 9999, 9}, AEQualifier: 1})
	wantHS(t, err, -1, AlarmAddressMismatch)
	rej, err := s.SecReject(func() *SecurityError { se, _ := AsSecurityError(err); return se }())
	if err != nil {
		t.Fatal(err)
	}
	re := c.ProcessRejection(KindHandshakeSecReject, content(t, rej))
	if re.Diag != -1 || !re.Authenticated {
		t.Fatalf("rejection %+v", re)
	}

	// Replay of the same request.
	c, _ = NewClient(f.cli)
	s1, _ := NewServer(f.srv)
	s2, _ := NewServer(f.srv)
	req, _ = c.HandshakeRequest(appl)
	if _, err := s1.ProcessHandshakeRequest(content(t, req), clientAE); err != nil {
		t.Fatal(err)
	}
	_, err = s2.ProcessHandshakeRequest(content(t, req), clientAE)
	wantHS(t, err, -1, AlarmReplay)

	// Tampered signature.
	c, _ = NewClient(f.cli)
	s, _ = NewServer(f.srv)
	req, _ = c.HandshakeRequest(appl)
	bad := append([]byte(nil), req...)
	bad[len(bad)-1] ^= 1
	_, err = s.ProcessHandshakeRequest(content(t, bad), clientAE)
	wantHS(t, err, -1, AlarmInvalidSignature)

	// Stale time.
	c, _ = NewClient(f.cli)
	s, _ = NewServer(f.srv)
	req, _ = c.HandshakeRequest(appl)
	f.clk.add(11 * time.Minute)
	_, err = s.ProcessHandshakeRequest(content(t, req), clientAE)
	wantHS(t, err, HDInvalidTimeValue, AlarmNone)

	// Unsupported protected protocol.
	f2 := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f2.cli.Protocol = "IEC 61850-8-2"
	c, _ = NewClient(f2.cli)
	s, _ = NewServer(f2.srv)
	req, _ = c.HandshakeRequest(appl)
	_, err = s.ProcessHandshakeRequest(content(t, req), clientAE)
	wantHS(t, err, HDProtectedProtocolNotSupported, AlarmNone)

	// Unknown CA.
	f3 := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f3.srv.Policy.Trust = pki.NewTrustStore(pkitest.NewRoot("other", pkitest.ECDSAP256).Cert)
	c, _ = NewClient(f3.cli)
	s, _ = NewServer(f3.srv)
	req, _ = c.HandshakeRequest(appl)
	_, err = s.ProcessHandshakeRequest(content(t, req), clientAE)
	wantHS(t, err, HDInvalidCertificationPath, AlarmNone)

	// Unsupported group on the server.
	f4 := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f4.cli.Policy.DHGroups = []Group{GroupMODP2048}
	f4.srv.Policy.DHGroups = []Group{GroupP256}
	c, _ = NewClient(f4.cli)
	s, _ = NewServer(f4.srv)
	req, _ = c.HandshakeRequest(appl)
	_, err = s.ProcessHandshakeRequest(content(t, req), clientAE)
	wantHS(t, err, HDDHGroupNotSupported, AlarmNone)

	// No common ICV algorithm.
	f5 := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f5.cli.Policy.ICVAlgs = []ICVAlg{ICVGMACAES256}
	f5.srv.Policy.ICVAlgs = []ICVAlg{ICVHMACSHA256}
	c, _ = NewClient(f5.cli)
	s, _ = NewServer(f5.srv)
	req, _ = c.HandshakeRequest(appl)
	_, err = s.ProcessHandshakeRequest(content(t, req), clientAE)
	wantHS(t, err, HDICVAlgorithmsNotSupported, AlarmNone)
}

func TestAcceptNegative(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	c, _ := NewClient(f.cli)
	s, _ := NewServer(f.srv)
	req, _ := c.HandshakeRequest(appl)
	if _, err := s.ProcessHandshakeRequest(content(t, req), clientAE); err != nil {
		t.Fatal(err)
	}
	acc, _ := s.HandshakeAccept(appl)
	// The server answers as another AE.
	_, err := c.ProcessHandshakeAccept(content(t, acc), AETitle{APTitle: asn1.OID{1, 3, 9999, 2}, AEQualifier: 8})
	wantHS(t, err, -1, AlarmAddressMismatch)
	se, _ := AsSecurityError(err)
	ab, err := c.HandshakeSecAbort(se)
	if err != nil {
		t.Fatal(err)
	}
	re := s.ProcessRejection(KindHandshakeSecAbort, content(t, ab))
	if !re.Authenticated || re.Diag != -1 {
		t.Fatalf("%+v", re)
	}
}

func wantDT(t *testing.T, err error, diag int, alarm Alarm) {
	t.Helper()
	se, ok := AsSecurityError(err)
	if !ok {
		t.Fatalf("not a security error: %v", err)
	}
	if se.Diag != diag || se.Alarm != alarm {
		t.Fatalf("got %s / %v (%v), want %s / %v", DtDiagName(se.Diag), se.Alarm, se.Err, DtDiagName(diag), alarm)
	}
}

func TestDataNegative(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	c, s := establish(t, f)
	pdu, _ := c.Seal(appl)
	if _, err := s.Open(content(t, pdu), false); err != nil {
		t.Fatal(err)
	}
	// Replay of the same PDU.
	_, err := s.Open(content(t, pdu), false)
	wantDT(t, err, -1, AlarmReplay)

	c, s = establish(t, f)
	pdu, _ = c.Seal(appl)
	bad := append([]byte(nil), pdu...)
	bad[len(bad)-1] ^= 1
	_, err = s.Open(content(t, bad), false)
	wantDT(t, err, -1, AlarmInvalidICV)

	// EncrTransfer when encryption was not selected.
	enc, _ := encodeTransfer(&Transfer{Encrypted: true, Token2: ClearToken2{AssoID: s.AssoID(),
		TimeRaw: asn1.FormatTime62351(f.clk.now()), Seq: 9}, ApplData: []byte{1, 2, 3}}, AuthAnnexB,
		func([]byte) (*Authenticator, error) {
			return &Authenticator{Alg: ICVHMACSHA256.id(), ICV: make([]byte, 32)}, nil
		})
	_, err = s.Open(content(t, enc), true)
	wantDT(t, err, DDEncryptionNotSelected, AlarmNone)

	// Skipped sequence number: build two PDUs, deliver the second.
	c, s = establish(t, f)
	p1, _ := c.Seal(appl)
	p2, _ := c.Seal(appl)
	_ = p1
	_, err = s.Open(content(t, p2), false)
	wantDT(t, err, DDInvalidSequenceNumber, AlarmNone)

	// Stale time.
	c, s = establish(t, f)
	pdu, _ = c.Seal(appl)
	f.clk.add(11 * time.Minute)
	_, err = s.Open(content(t, pdu), false)
	wantDT(t, err, DDInvalidTimeValue, AlarmNone)
	f.clk.add(-11 * time.Minute)

	// changedKey without an outstanding rekey, received by the client: a
	// server with a forced pending flag emits one.
	c, s = establish(t, f)
	s.mu.Lock()
	s.pendingChg, s.pendingTx = true, append([]byte(nil), s.tx.key...)
	s.mu.Unlock()
	pdu, _ = s.Seal(appl)
	_, err = c.Open(content(t, pdu), false)
	wantDT(t, err, DDUnexpectedChangedKey, AlarmNone)

	// The abort is signed and authenticated by the peer.
	c, s = establish(t, f)
	ab, err := s.DtSecAbort(dtErr(DDInvalidSequenceNumber, errors.New("x")))
	if err != nil {
		t.Fatal(err)
	}
	re := c.ProcessRejection(KindDtSecAbort, content(t, ab))
	if !re.Authenticated || re.Diag != DDInvalidSequenceNumber {
		t.Fatalf("%+v", re)
	}
}

func TestSequenceAcrossTime(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	c, s := establish(t, f)
	for i := 0; i < 3; i++ {
		transfer(t, c, s)
	}
	f.clk.add(time.Millisecond)
	transfer(t, c, s)
	if c.tx.lastSeq != 0 {
		t.Fatalf("seq after a time change = %d", c.tx.lastSeq)
	}
	// A clock step backwards holds the time and keeps counting.
	f.clk.add(-time.Second)
	transfer(t, c, s)
	if c.tx.lastSeq != 1 {
		t.Fatalf("seq while held = %d", c.tx.lastSeq)
	}
}

func TestConfigValidation(t *testing.T) {
	f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f.cli.Local.AE.AEQualifier = 2 // certificate names qualifier 1
	if err := f.cli.Validate(); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	f2 := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f2.srv.Policy.RekeyInterval = time.Minute
	if err := f2.srv.Validate(); err == nil {
		t.Fatal("short rekey interval accepted")
	}
	f3 := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
	f3.srv.Policy.Encryption = EncryptionRequire
	if err := f3.srv.Validate(); err == nil {
		t.Fatal("encryption accepted")
	}
}
