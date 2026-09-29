package rsession_test

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/goose"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/rsession"
	"github.com/dscsystems/go-iec61850/sv"
)

var key16 = []byte("0123456789ABCDEF")

func keys(t *testing.T, ks ...rsession.Key) *rsession.KeyStore {
	t.Helper()
	s, err := rsession.NewKeyStore(ks...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// pair opens a receiving session on a free loopback port and a sending
// one aimed at it.
func pair(t *testing.T, rx, tx rsession.Config) (recv, send *rsession.Session) {
	t.Helper()
	rx.Listen = "127.0.0.1:0"
	recv, err := rsession.Open(rx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recv.Close() })
	tx.Remote = recv.LocalAddr().String()
	send, err = rsession.Open(tx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { send.Close() })
	return recv, send
}

// receive waits for the next accepted SPDU.
func receive(t *testing.T, s *rsession.Session) *rsession.SPDU {
	t.Helper()
	type res struct {
		spdu *rsession.SPDU
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		spdu, _, err := s.Receive()
		ch <- res{spdu, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatal(r.err)
		}
		return r.spdu
	case <-time.After(2 * time.Second):
		t.Fatal("nothing received")
	}
	return nil
}

func TestSessionSecuredExchange(t *testing.T) {
	for _, k := range []rsession.Key{
		{ID: 7, Material: key16, Sig: rsession.SigHMACSHA256_128},
		{ID: 7, Material: key16, Sec: rsession.SecAES128GCM},
	} {
		recv, send := pair(t, rsession.Config{Keys: keys(t, k)}, rsession.Config{Keys: keys(t, k)})
		apdu := []byte{0x61, 0x02, 0x80, 0x00}
		if err := send.Send(rsession.SIGOOSE, rsession.Payload{Type: rsession.PayloadGOOSE, AppID: 1, APDU: apdu}); err != nil {
			t.Fatal(err)
		}
		got := receive(t, recv)
		if got.KeyID != 7 || len(got.Payloads) != 1 || !bytes.Equal(got.Payloads[0].APDU, apdu) {
			t.Errorf("%v/%v: received %+v", k.Sec, k.Sig, got)
		}
	}
}

// A receiver refuses unsecured SPDUs unless told otherwise, and SPDUs
// under keys it does not hold, and says why.
func TestSessionPolicy(t *testing.T) {
	var mu sync.Mutex
	var rejected []error
	onReject := func(r rsession.Reject) {
		mu.Lock()
		rejected = append(rejected, r.Err)
		mu.Unlock()
	}
	good := rsession.Key{ID: 1, Material: key16, Sig: rsession.SigHMACSHA256_128}
	recv, err := rsession.Open(rsession.Config{Listen: "127.0.0.1:0", Keys: keys(t, good), OnReject: onReject})
	if err != nil {
		t.Fatal(err)
	}
	defer recv.Close()
	to := recv.LocalAddr().String()
	send := func(ks *rsession.KeyStore) {
		t.Helper()
		s, err := rsession.Open(rsession.Config{Remote: to, Keys: ks})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.Send(rsession.SIGOOSE, rsession.Payload{Type: rsession.PayloadGOOSE, APDU: []byte{0x61, 0}}); err != nil {
			t.Fatal(err)
		}
	}
	send(nil) // unsecured
	send(keys(t, rsession.Key{ID: 2, Material: key16, Sig: rsession.SigHMACSHA256_128}))
	send(keys(t, rsession.Key{ID: 1, Material: bytes.Repeat([]byte{9}, 16), Sig: rsession.SigHMACSHA256_128}))
	send(keys(t, good))
	if got := receive(t, recv); got.KeyID != 1 {
		t.Errorf("accepted %+v", got)
	}
	st := recv.Stats()
	if st.Unsecured != 1 || st.UnknownKey != 1 || st.Unauthentic != 1 || st.Accepted != 1 {
		t.Errorf("stats = %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(rejected) != 3 || !errors.Is(rejected[0], rsession.ErrUnsecured) ||
		!errors.Is(rejected[1], rsession.ErrUnknownKey) || !errors.Is(rejected[2], rsession.ErrAuthentication) {
		t.Errorf("rejections = %v", rejected)
	}

	// Unsecured traffic is accepted when the receiver allows it.
	open, send2 := pair(t, rsession.Config{AllowUnsecured: true}, rsession.Config{})
	if err := send2.Send(rsession.SISV, rsession.Payload{Type: rsession.PayloadSV, APDU: []byte{0x60, 0}}); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, open); got.KeyID != 0 || got.SI != rsession.SISV {
		t.Errorf("unsecured SPDU = %+v", got)
	}
}

// A captured secured SPDU sent again is refused.
func TestSessionReplay(t *testing.T) {
	k := rsession.Key{ID: 1, Material: key16, Sig: rsession.SigHMACSHA256_128}
	recv, err := rsession.Open(rsession.Config{Listen: "127.0.0.1:0", Keys: keys(t, k)})
	if err != nil {
		t.Fatal(err)
	}
	defer recv.Close()
	b, err := rsession.Marshal(&rsession.SPDU{SI: rsession.SIGOOSE, Number: 10,
		Payloads: []rsession.Payload{{Type: rsession.PayloadGOOSE, APDU: []byte{0x61, 0}}}}, &k, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", recv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for range 3 {
		c.Write(b)
	}
	if got := receive(t, recv); got.Number != 10 {
		t.Fatalf("received %+v", got)
	}
	// SPDUs are checked as they are received; keep receiving.
	go func() {
		for {
			if _, _, err := recv.Receive(); err != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for recv.Stats().Replayed < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if st := recv.Stats(); st.Replayed != 2 || st.Accepted != 1 {
		t.Errorf("stats = %+v, want the two copies refused", st)
	}
}

// The GOOSE publisher and subscriber of this module run over a session as
// they do over Ethernet, retransmissions included.
func TestGOOSEOverSession(t *testing.T) {
	k := rsession.Key{ID: 3, Material: key16, Sec: rsession.SecAES128GCM}
	recv, send := pair(t, rsession.Config{Keys: keys(t, k)}, rsession.Config{Keys: keys(t, k)})

	got := make(chan *goose.Message, 8)
	stop, err := goose.NewSubscriber(recv).Subscribe(goose.Filter{GoCbRef: "IED1LD0/LLN0$GO$gcb1"},
		func(m *goose.Message) { got <- m })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	pub, err := goose.NewPublisher(send, goose.PublisherConfig{
		AppID: 0x3001, GoCbRef: "IED1LD0/LLN0$GO$gcb1", DatSet: "IED1LD0/LLN0$DS1", ConfRev: 1,
		Retrans: []time.Duration{20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	if err := pub.Publish([]*mms.Value{mms.NewBool(true), mms.NewInt32(1234)}); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		select {
		case m := <-got:
			if m.AppID != 0x3001 || m.StNum != 1 || m.SqNum != uint32(i) || len(m.Values) != 2 ||
				!m.Values[0].Bool() || m.Values[1].Int64() != 1234 {
				t.Errorf("message %d = %+v", i, m)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("message %d not received", i)
		}
	}
}

func TestSVOverSession(t *testing.T) {
	k := rsession.Key{ID: 4, Material: key16, Sig: rsession.SigHMACSHA256_256}
	k.Material = bytes.Repeat([]byte{3}, 32)
	recv, send := pair(t, rsession.Config{Keys: keys(t, k)}, rsession.Config{Keys: keys(t, k)})
	got := make(chan *sv.ASDU, 4)
	stop, err := sv.NewSubscriber(recv).Subscribe(sv.Filter{}, func(a *sv.ASDU) { got <- a })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	pdu := &sv.PDU{AppID: 0x4001, ASDUs: []*sv.ASDU{{SvID: "RSV1", SmpCnt: 17, ConfRev: 1, Sample: []byte{1, 2, 3, 4}}}}
	if err := send.WriteFrame(&ethernet.Frame{EtherType: ethernet.EtherTypeSV, Payload: pdu.Marshal()}); err != nil {
		t.Fatal(err)
	}
	select {
	case a := <-got:
		if a.SvID != "RSV1" || a.SmpCnt != 17 || !bytes.Equal(a.Sample, []byte{1, 2, 3, 4}) {
			t.Errorf("ASDU = %+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no ASDU")
	}
}

// A session joined to a multicast group receives what is sent to it.
// Skipped where the host has no multicast route (a container without one,
// say).
func TestSessionMulticast(t *testing.T) {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	group := net.JoinHostPort("239.255.61.50", strconv.Itoa(port))
	k := rsession.Key{ID: 1, Material: key16, Sig: rsession.SigHMACSHA256_128}
	rx, err := rsession.Open(rsession.Config{Groups: []string{group}, Keys: keys(t, k)})
	if err != nil {
		t.Skipf("cannot join a multicast group here: %v", err)
	}
	defer rx.Close()
	tx, err := rsession.Open(rsession.Config{Remote: group, Keys: keys(t, k), TTL: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	got := make(chan *rsession.SPDU, 1)
	go func() {
		if s, _, err := rx.Receive(); err == nil {
			got <- s
		}
	}()
	for range 5 {
		if err := tx.Send(rsession.SIGOOSE, rsession.Payload{Type: rsession.PayloadGOOSE, APDU: []byte{0x61, 0}}); err != nil {
			t.Skipf("cannot send multicast here: %v", err)
		}
		select {
		case s := <-got:
			if s.KeyID != 1 || !s.Signed {
				t.Errorf("received %+v", s)
			}
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Skip("multicast is not looped back on this host (no route, or a firewall drops it)")
}
