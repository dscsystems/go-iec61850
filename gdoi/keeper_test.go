package gdoi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/gdoi"
	"github.com/dscsystems/go-iec61850/rsession"
)

var goosePublishers = asn1.ObjectIdentifier{1, 2, 840, 10070, 61850, 2}

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	n    int64
}

func newAuthority(t *testing.T) *authority {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &authority{cert: c, key: k, n: 1}
}

func (a *authority) credentials(t *testing.T, cn string) gdoi.Credentials {
	a.n++
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(a.n), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &k.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	return gdoi.Credentials{Certificate: []*x509.Certificate{c}, Key: k, Roots: pool}
}

// events collects a member's events.
type events struct {
	mu sync.Mutex
	ev []gdoi.Event
}

func (e *events) add(ev gdoi.Event) {
	e.mu.Lock()
	e.ev = append(e.ev, ev)
	e.mu.Unlock()
}

func (e *events) has(kind gdoi.EventKind, spi uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.ev {
		if ev.Kind == kind && (spi == 0 || ev.SPI == spi) {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Two members take the group's keys from the key server into their
// session key stores and exchange R-GOOSE under them; the key server
// rotates the key, and they follow it; the old key, withdrawn, stops
// being accepted.
func TestMembersFollowKeyRotation(t *testing.T) {
	ca := newAuthority(t)
	group := gdoi.GroupID{OID: goosePublishers}
	g := &gdoi.Group{}
	tek1, err := gdoi.NewTEK(goosePublishers, nil, gdoi.AuthNone, gdoi.EncAESGCM128, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g.Add(tek1)
	ks, err := gdoi.NewServer(gdoi.ServerConfig{
		Credentials: ca.credentials(t, "ks1"),
		Authorize:   func(p gdoi.Peer, gid gdoi.GroupID) bool { return p.Certificate.Subject.CommonName != "intruder" },
	})
	if err != nil {
		t.Fatal(err)
	}
	ks.AddGroup(group, g)
	c, _ := net.ListenPacket("udp", "127.0.0.1:0")
	go ks.Serve(c)
	defer ks.Close()

	member := func(name string, store *rsession.KeyStore) (*events, context.CancelFunc) {
		cfg := gdoi.MemberConfig{Server: c.LocalAddr().String(), Credentials: ca.credentials(t, name),
			AuthorizeServer: func(p gdoi.Peer) error {
				if p.Certificate.Subject.CommonName != "ks1" {
					return errors.New("unknown key server")
				}
				return nil
			}, Retransmit: 300 * time.Millisecond}
		m := gdoi.NewMember(cfg, group, store)
		m.Refresh = 200 * time.Millisecond
		ev := &events{}
		m.OnEvent = ev.add
		ctx, cancel := context.WithCancel(context.Background())
		go m.Run(ctx)
		return ev, cancel
	}
	pubKeys, subKeys := &rsession.KeyStore{}, &rsession.KeyStore{}
	pubEv, stopPub := member("ied-publisher", pubKeys)
	defer stopPub()
	subEv, stopSub := member("ied-subscriber", subKeys)
	defer stopSub()
	waitFor(t, "the first key", func() bool {
		return pubEv.has(gdoi.Installed, tek1.SPI) && subEv.has(gdoi.Installed, tek1.SPI)
	})

	rx, err := rsession.Open(rsession.Config{Listen: "127.0.0.1:0", Keys: subKeys})
	if err != nil {
		t.Fatal(err)
	}
	defer rx.Close()
	tx, err := rsession.Open(rsession.Config{Remote: rx.LocalAddr().String(), Keys: pubKeys})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	exchange := func() *rsession.SPDU {
		t.Helper()
		if err := tx.Send(rsession.SIGOOSE, rsession.Payload{Type: rsession.PayloadGOOSE, AppID: 1, APDU: []byte{0x61, 0}}); err != nil {
			t.Fatal(err)
		}
		got := make(chan *rsession.SPDU, 1)
		go func() {
			if s, _, err := rx.Receive(); err == nil {
				got <- s
			}
		}()
		select {
		case s := <-got:
			return s
		case <-time.After(2 * time.Second):
			t.Fatalf("nothing received; receiver stats %+v", rx.Stats())
		}
		return nil
	}
	if s := exchange(); s.KeyID != tek1.SPI || !s.Encrypted {
		t.Fatalf("first exchange under key %d, want %d", s.KeyID, tek1.SPI)
	}

	// Rotation: the next key is distributed a second before it is used.
	tek2, _ := gdoi.NewTEK(goosePublishers, nil, gdoi.AuthNone, gdoi.EncAESGCM128, time.Hour)
	tek2.ActivationDelay = time.Second
	if err := g.Add(tek2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the next key", func() bool {
		return pubEv.has(gdoi.Installed, tek2.SPI) && subEv.has(gdoi.Installed, tek2.SPI)
	})
	if s := exchange(); s.KeyID != tek2.SPI {
		t.Errorf("after rotation the publisher sends under key %d, want %d", s.KeyID, tek2.SPI)
	}

	// Withdrawal: members drop the old key at their next registration, and
	// an SPDU under it is refused.
	g.Remove(tek1.SPI)
	waitFor(t, "the old key's removal", func() bool { return subEv.has(gdoi.Removed, tek1.SPI) })
	k1, _ := tek1.RSessionKey()
	stale, _ := rsession.Marshal(&rsession.SPDU{SI: rsession.SIGOOSE, Number: 1000,
		Payloads: []rsession.Payload{{Type: rsession.PayloadGOOSE, APDU: []byte{0x61, 0}}}}, &k1, nil)
	conn, _ := net.Dial("udp", rx.LocalAddr().String())
	defer conn.Close()
	before := rx.Stats().UnknownKey
	conn.Write(stale)
	go rx.Receive()
	waitFor(t, "the stale key to be refused", func() bool { return rx.Stats().UnknownKey > before })

	// Stopping a member removes its keys.
	stopSub()
	waitFor(t, "the subscriber's keys to go", func() bool {
		_, ok := subKeys.Lookup(tek2.SPI)
		return !ok
	})
}
