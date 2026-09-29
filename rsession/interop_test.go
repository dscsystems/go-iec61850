package rsession_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/goose"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/rsession"
	"github.com/dscsystems/go-iec61850/sv"
)

// The interop tests run libiec61850's R-GOOSE and R-SV (interop/c/
// rsession_peer.c, built against libiec61850 with mbedtls) against this
// package, both ways. Set IEC61850_C_RSESSION_PEER to the peer binary.

type mode struct {
	name string
	key  *rsession.Key
}

var key32 = bytes.Repeat([]byte{0x5A}, 32)

func peerBinary(t *testing.T) string {
	bin := os.Getenv("IEC61850_C_RSESSION_PEER")
	if bin == "" {
		t.Skip("set IEC61850_C_RSESSION_PEER to the rsession_peer binary")
	}
	return bin
}

// peerArgs are the key arguments of rsession_peer for a mode.
func peerArgs(m mode) []string {
	if m.key == nil {
		return []string{"0", "-", "0", "0"}
	}
	return []string{"1", hex.EncodeToString(m.key.Material),
		strconv.Itoa(int(m.key.Sec)), strconv.Itoa(int(m.key.Sig))}
}

func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func config(m mode) rsession.Config {
	var cfg rsession.Config
	if m.key == nil {
		cfg.AllowUnsecured = true
		return cfg
	}
	k := *m.key
	k.ID = 1
	ks, _ := rsession.NewKeyStore(k)
	cfg.Keys = ks
	return cfg
}

// runPeer runs rsession_peer and returns its output.
func runPeer(t *testing.T, ctx context.Context, bin string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput()
	return string(out), err
}

// libiec61850 publishes: unsecured, HMAC-SHA256-128, AES-GCM. It writes
// HMAC-SHA256-256 with a 16 in the length octet before a 32-octet MAC,
// which no receiver can parse, so that mode is only tested the other way.
var fromLibiec = []mode{
	{"unsecured", nil},
	{"HMAC-SHA256-128", &rsession.Key{Material: key16, Sig: rsession.SigHMACSHA256_128}},
	{"AES-128-GCM", &rsession.Key{Material: key16, Sec: rsession.SecAES128GCM}},
	{"AES-256-GCM", &rsession.Key{Material: key32, Sec: rsession.SecAES256GCM}},
}

// libiec61850 receives: HMAC-SHA256-128 and -256, AES-GCM. It refuses a
// version 2 SPDU without a key.
var toLibiec = []mode{
	{"HMAC-SHA256-128", &rsession.Key{Material: key16, Sig: rsession.SigHMACSHA256_128}},
	{"HMAC-SHA256-256", &rsession.Key{Material: key32, Sig: rsession.SigHMACSHA256_256}},
	{"AES-128-GCM", &rsession.Key{Material: key16, Sec: rsession.SecAES128GCM}},
	{"AES-256-GCM", &rsession.Key{Material: key32, Sec: rsession.SecAES256GCM}},
}

func TestInteropGOOSEFromLibiec(t *testing.T) {
	bin := peerBinary(t)
	for _, m := range fromLibiec {
		t.Run(m.name, func(t *testing.T) {
			cfg := config(m)
			cfg.Listen = "127.0.0.1:0"
			s, err := rsession.Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got := make(chan *goose.Message, 16)
			stop, _ := goose.NewSubscriber(s).Subscribe(goose.Filter{GoCbRef: "GOISIM/LLN0$GO$gcb1"},
				func(msg *goose.Message) { got <- msg })
			defer stop()
			port := strconv.Itoa(s.LocalAddr().(*net.UDPAddr).Port)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := append([]string{"goose-pub", "127.0.0.1", port}, peerArgs(m)...)
			if out, err := runPeer(t, ctx, bin, append(args, "3")...); err != nil {
				t.Fatalf("peer: %v\n%s", err, out)
			}
			for i := range 3 {
				select {
				case msg := <-got:
					if msg.AppID != 0x3001 || len(msg.Values) != 3 || msg.Values[0].Int64() != 1234 ||
						!msg.Values[1].Bool() || msg.Values[2].Text() != "r-goose" {
						t.Errorf("message %d = %+v", i, msg)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("message %d not received; stats %+v", i, s.Stats())
				}
			}
		})
	}
}

func TestInteropGOOSEToLibiec(t *testing.T) {
	bin := peerBinary(t)
	for _, m := range toLibiec {
		t.Run(m.name, func(t *testing.T) {
			port := freePort(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := append([]string{"goose-sub", "127.0.0.1", strconv.Itoa(port)}, peerArgs(m)...)
			cmd := exec.CommandContext(ctx, bin, append(args, "3")...)
			out := &syncBuffer{}
			cmd.Stdout, cmd.Stderr = out, out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitFor(t, out, "listening")

			cfg := config(m)
			cfg.Remote = fmt.Sprintf("127.0.0.1:%d", port)
			s, err := rsession.Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			pub, err := goose.NewPublisher(s, goose.PublisherConfig{
				AppID: 0x3001, GoCbRef: "GOISIM/LLN0$GO$gcb1", DatSet: "GOISIM/LLN0$DS1", GoID: "GOISIM", ConfRev: 1,
				Retrans: []time.Duration{50 * time.Millisecond},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer pub.Close()
			if err := pub.Publish([]*mms.Value{mms.NewInt32(1234), mms.NewBool(true), mms.NewVisibleString("r-goose")}); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			text := out.String()
			if err != nil {
				t.Fatalf("libiec61850 did not receive 3 messages: %v\n%s", err, text)
			}
			if !strings.Contains(text, "GOOSE st=1 sq=0 valid=1") || !strings.Contains(text, "1234,true,r-goose") {
				t.Errorf("libiec61850 decoded:\n%s", text)
			}
		})
	}
}

// The sample libiec61850 publishes: two FLOAT32, 1.5 and -2.25.
func floats(v ...float32) []byte {
	var b []byte
	for _, f := range v {
		b = binary.BigEndian.AppendUint32(b, math.Float32bits(f))
	}
	return b
}

func TestInteropSVFromLibiec(t *testing.T) {
	bin := peerBinary(t)
	for _, m := range fromLibiec {
		t.Run(m.name, func(t *testing.T) {
			cfg := config(m)
			cfg.Listen = "127.0.0.1:0"
			s, err := rsession.Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got := make(chan *sv.ASDU, 16)
			stop, _ := sv.NewSubscriber(s).Subscribe(sv.Filter{}, func(a *sv.ASDU) { got <- a })
			defer stop()
			port := strconv.Itoa(s.LocalAddr().(*net.UDPAddr).Port)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := append([]string{"sv-pub", "127.0.0.1", port}, peerArgs(m)...)
			if out, err := runPeer(t, ctx, bin, append(args, "3")...); err != nil {
				t.Fatalf("peer: %v\n%s", err, out)
			}
			for i := range 3 {
				select {
				case a := <-got:
					if a.SvID != "RSV1" || a.SmpCnt != uint16(i) || !bytes.Equal(a.Sample, floats(1.5, -2.25)) {
						t.Errorf("ASDU %d = %+v", i, a)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("ASDU %d not received; stats %+v", i, s.Stats())
				}
			}
		})
	}
}

func TestInteropSVToLibiec(t *testing.T) {
	bin := peerBinary(t)
	for _, m := range toLibiec {
		t.Run(m.name, func(t *testing.T) {
			port := freePort(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := append([]string{"sv-sub", "127.0.0.1", strconv.Itoa(port)}, peerArgs(m)...)
			cmd := exec.CommandContext(ctx, bin, append(args, "3")...)
			out := &syncBuffer{}
			cmd.Stdout, cmd.Stderr = out, out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitFor(t, out, "listening")

			cfg := config(m)
			cfg.Remote = fmt.Sprintf("127.0.0.1:%d", port)
			s, err := rsession.Open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			for i := range 3 {
				pdu := &sv.PDU{AppID: 0x4001, ASDUs: []*sv.ASDU{{SvID: "RSV1", SmpCnt: uint16(i), ConfRev: 1,
					Sample: floats(1.5, -2.25)}}}
				if err := s.WriteFrame(&ethernet.Frame{EtherType: ethernet.EtherTypeSV, Payload: pdu.Marshal()}); err != nil {
					t.Fatal(err)
				}
				time.Sleep(20 * time.Millisecond)
			}
			err = cmd.Wait()
			text := out.String()
			if err != nil {
				t.Fatalf("libiec61850 did not receive 3 ASDUs: %v\n%s", err, text)
			}
			for i := range 3 {
				if !strings.Contains(text, fmt.Sprintf("SV svID=RSV1 smpCnt=%d v0=1.5 v1=-2.25", i)) {
					t.Errorf("libiec61850 decoded:\n%s", text)
					break
				}
			}
		})
	}
}

// syncBuffer is a bytes.Buffer the peer's output is copied into while the
// test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// waitFor waits until the peer's output contains s.
func waitFor(t *testing.T, out *syncBuffer, s string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), s) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer never printed %q:\n%s", s, out.String())
}
