package gdoi

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The Wireshark check captures a registration and has tshark, whose IKEv1
// dissector was written independently of this package, decrypt and
// dissect it: every message must dissect without a malformed payload, and
// the decrypted ones must hold the payloads the exchange puts there. It
// checks the ISAKMP framing, the phase 1 key derivation (Wireshark derives
// the IVs itself from the key exchange values and the negotiated hash) and
// the CBC chaining through phase 1 and the GROUPKEY-PULL.
//
// Set IEC61850_TSHARK to a tshark binary, or IEC61850_TSHARK_IMAGE to a
// Docker image that has one (interop/run.sh builds go-iec61850-tshark).

// datagram is one captured message.
type datagram struct {
	fromMember bool
	b          []byte
}

// capture relays between a member and a key server, recording every
// datagram.
func capture(t *testing.T, to string) (string, func() []datagram) {
	c, _ := net.ListenPacket("udp", "127.0.0.1:0")
	up, _ := net.ListenPacket("udp", "127.0.0.1:0")
	t.Cleanup(func() { c.Close(); up.Close() })
	ks, _ := net.ResolveUDPAddr("udp", to)
	var mu sync.Mutex
	var log []datagram
	var member net.Addr
	go func() {
		buf := make([]byte, 65536)
		for {
			n, a, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			member = a
			log = append(log, datagram{true, clone(buf[:n])})
			mu.Unlock()
			up.WriteTo(buf[:n], ks)
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := up.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			log = append(log, datagram{false, clone(buf[:n])})
			m := member
			mu.Unlock()
			c.WriteTo(buf[:n], m)
		}
	}()
	return c.LocalAddr().String(), func() []datagram {
		mu.Lock()
		defer mu.Unlock()
		return append([]datagram(nil), log...)
	}
}

// writePcap writes the datagrams as IPv4/UDP packets between 10.0.0.1
// (the member) and 10.0.0.2 (the key server), port 848 both ways.
func writePcap(path string, ds []datagram) error {
	var b bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], 228) // LINKTYPE_IPV4
	b.Write(hdr)
	for i, d := range ds {
		src, dst := []byte{10, 0, 0, 1}, []byte{10, 0, 0, 2}
		if !d.fromMember {
			src, dst = dst, src
		}
		udp := make([]byte, 8)
		binary.BigEndian.PutUint16(udp[0:], DefaultPort)
		binary.BigEndian.PutUint16(udp[2:], DefaultPort)
		binary.BigEndian.PutUint16(udp[4:], uint16(8+len(d.b)))
		ip := make([]byte, 20)
		ip[0], ip[8], ip[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(ip[2:], uint16(20+8+len(d.b)))
		copy(ip[12:], src)
		copy(ip[16:], dst)
		var sum uint32
		for j := 0; j < 20; j += 2 {
			sum += uint32(binary.BigEndian.Uint16(ip[j:]))
		}
		for sum > 0xffff {
			sum = sum&0xffff + sum>>16
		}
		binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
		pkt := append(append(ip, udp...), d.b...)
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(1700000000+i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
		b.Write(rec)
		b.Write(pkt)
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func tshark(t *testing.T, dir string, args ...string) string {
	t.Helper()
	var cmd *exec.Cmd
	// The decryption keys are in dir/prefs/ikev1_decryption_table, the
	// preference file Wireshark reads them from.
	if bin := os.Getenv("IEC61850_TSHARK"); bin != "" {
		for i, a := range args {
			args[i] = strings.ReplaceAll(a, "/w/", dir+"/")
		}
		cmd = exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "WIRESHARK_CONFIG_DIR="+filepath.Join(dir, "prefs"))
	} else if img := os.Getenv("IEC61850_TSHARK_IMAGE"); img != "" {
		cmd = exec.Command("docker", append([]string{"run", "--rm", "-v", dir + ":/w",
			"-e", "WIRESHARK_CONFIG_DIR=/w/prefs", img, "tshark"}, args...)...)
	} else {
		t.Skip("set IEC61850_TSHARK or IEC61850_TSHARK_IMAGE")
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("tshark: %v\n%s", err, out)
	}
	return string(out)
}

func TestWiresharkDissectsRegistration(t *testing.T) {
	if os.Getenv("IEC61850_TSHARK") == "" && os.Getenv("IEC61850_TSHARK_IMAGE") == "" {
		t.Skip("set IEC61850_TSHARK or IEC61850_TSHARK_IMAGE")
	}
	ca := newPKI(t, "substation CA")
	for _, tc := range []struct {
		name  string
		suite Suite
		cred  func() (Credentials, Credentials)
	}{
		{"ECDSA/AES-256/ECP-256", Suite{KeyBits: 256, Hash: hashSHA256, Group: groupECP256}, func() (Credentials, Credentials) {
			return ca.issue(t, "ks1", ecKey(t, elliptic.P256())), ca.issue(t, "ied1", ecKey(t, elliptic.P256()))
		}},
		{"PSK/AES-128/MODP-2048", Suite{KeyBits: 128, Hash: hashSHA256, Group: groupMODP2048}, func() (Credentials, Credentials) {
			return Credentials{}, Credentials{PSK: []byte("substation pre-shared secret")}
		}},
		{"RSA/AES-256/SHA-384/ECP-384", Suite{KeyBits: 256, Hash: hashSHA384, Group: groupECP384}, func() (Credentials, Credentials) {
			return ca.issue(t, "ks1", rsaKey(t, 0)), ca.issue(t, "ied1", rsaKey(t, 1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ksCred, gmCred := tc.cred()
			scfg := ServerConfig{Credentials: ksCred, Suites: []Suite{tc.suite}}
			if gmCred.PSK != nil {
				scfg.PSK = func(net.Addr) []byte { return gmCred.PSK }
			}
			r := newRig(t, scfg)
			phase1DOI = 1
			defer func() { phase1DOI = doiGDOI }()
			var logged [][2][]byte
			keyLog = func(ic [8]byte, k []byte) { logged = append(logged, [2][]byte{clone(ic[:]), k}) }
			defer func() { keyLog = nil }()
			relay, captured := capture(t, r.addr)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := Register(ctx, MemberConfig{Server: relay, Credentials: gmCred, Suites: []Suite{tc.suite},
				AuthorizeServer: func(Peer) error { return nil }}, r.group)
			if err != nil {
				t.Fatal(err)
			}
			ds := captured()
			if len(ds) != 10 || len(logged) != 1 {
				t.Fatalf("%d datagrams, %d keys logged; want 10 and 1", len(ds), len(logged))
			}
			dir := t.TempDir()
			os.Chmod(dir, 0o755)
			if err := writePcap(filepath.Join(dir, "gdoi.pcap"), ds); err != nil {
				t.Fatal(err)
			}
			if keep := os.Getenv("IEC61850_GDOI_PCAP_DIR"); keep != "" {
				name := strings.NewReplacer("/", "_").Replace(tc.name)
				writePcap(filepath.Join(keep, name+".pcap"), ds)
				os.WriteFile(filepath.Join(keep, name+".keys"),
					[]byte(hex.EncodeToString(logged[0][0])+","+hex.EncodeToString(logged[0][1])+"\n"), 0o644)
			}
			// A UAT buffer field is bare hex; a quoted one is read as text.
			prefs := filepath.Join(dir, "prefs")
			os.Mkdir(prefs, 0o755)
			if err := os.WriteFile(filepath.Join(prefs, "ikev1_decryption_table"),
				[]byte(hex.EncodeToString(logged[0][0])+","+hex.EncodeToString(logged[0][1])+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			out := tshark(t, dir, "-r", "/w/gdoi.pcap", "-d", "udp.port==848,isakmp", "-V")
			frames := strings.Split(out, "\nFrame ")
			if len(frames) != 10 {
				t.Fatalf("tshark shows %d frames:\n%s", len(frames), out)
			}
			for _, bad := range []string{"Malformed", "Expert Info (Error", "Decryption failed", "Bogus"} {
				if strings.Contains(out, bad) {
					t.Errorf("tshark reports %q:\n%s", bad, out)
				}
			}
			// What each encrypted message must hold. Wireshark only shows
			// the payloads of one it decrypted, so finding them means it
			// derived the same IVs from the key and the exchange.
			sig := "Payload: Signature (9)"
			if gmCred.PSK != nil {
				sig = "Payload: Hash (8)"
			}
			want := map[int][]string{
				4: {"Payload: Identification (5)", sig},
				5: {"Payload: Identification (5)", sig},
				// Wireshark predates RFC 8052: ID_OID is "Future use (13)"
				// to it and GDOI_PROTO_IEC_61850 "Unassigned (3)". The
				// identification data is the RFC 8052 layout: OID length,
				// the DER OID of 1.2.840.10070.61850.1, selector length 0.
				6: {"Payload: Hash (8)", "Payload: Nonce (10)", "Payload: Identification (5)",
					"ID type: Future use (13)", "Identification Data:0b06092a8648ce5683e31a010000"},
				7: {"Payload: Hash (8)", "Payload: Nonce (10)", "Payload: Security Association (1)",
					"Payload: SA TEK Payload (16)", "Protocol ID: Unassigned (3)"},
				8: {"Payload: Hash (8)"},
				9: {"Payload: Hash (8)", "Payload: Key Download (17)", "Number of Key Packets: 1",
					"TEK_ALGORITHM_KEY"},
			}
			for i, subs := range want {
				f := frames[i]
				for _, s := range subs {
					if !strings.Contains(f, s) {
						t.Errorf("frame %d lacks %q:\n%s", i+1, s, f)
					}
				}
			}
			if testing.Verbose() {
				t.Logf("tshark:\n%s", out)
			}
		})
	}
}
