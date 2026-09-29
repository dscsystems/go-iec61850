package rsession

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
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

// testKey is the key the libiec61850 vectors were made with.
var testKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

func store(t testing.TB, keys ...Key) *KeyStore {
	t.Helper()
	s, err := NewKeyStore(keys...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// SPDUs sent by libiec61850 1.6's R-GOOSE publisher (the interop peer in
// interop/c), captured from the wire. Each carries one goosePdu for
// "GOISIM/LLN0$GO$gcb1" with the data set {1234, true, "r-goose"}, APPID
// 0x3001, protocol version 2. libiec61850 writes the element's APDU
// length two more than the APDU (0x64 for a 98-octet goosePdu), and fixed
// header lengths (0x18, 0x12) whatever the security information holds.
const (
	libiecUnsecured = `
01 40 a1 18 80 12 00 00 00 7c 00 00 00 00 00 02
00 00 00 00 00 00 00 00 00 00 00 00 00 00 68 81
00 30 01 00 64 61 60 80 13 47 4f 49 53 49 4d 2f
4c 4c 4e 30 24 47 4f 24 67 63 62 31 81 02 07 d0
82 0f 47 4f 49 53 49 4d 2f 4c 4c 4e 30 24 44 53
31 83 06 47 4f 49 53 49 4d 84 08 6a bb ff 92 dc
6a 7e 0a 85 01 01 86 01 00 87 01 00 88 01 01 89
01 00 8a 01 03 ab 10 85 02 04 d2 83 01 01 8a 07
72 2d 67 6f 6f 73 65`
	// Key 1, HMAC-SHA256-128.
	libiecHMAC128 = `
01 40 a1 18 80 12 00 00 00 7c 00 00 00 00 00 02
00 00 00 00 00 00 00 00 00 01 00 00 00 00 68 81
00 30 01 00 64 61 60 80 13 47 4f 49 53 49 4d 2f
4c 4c 4e 30 24 47 4f 24 67 63 62 31 81 02 07 d0
82 0f 47 4f 49 53 49 4d 2f 4c 4c 4e 30 24 44 53
31 83 06 47 4f 49 53 49 4d 84 08 6a bb ff 93 37
8d 4f 0a 85 01 01 86 01 00 87 01 00 88 01 01 89
01 00 8a 01 03 ab 10 85 02 04 d2 83 01 01 8a 07
72 2d 67 6f 6f 73 65 85 10 11 c8 cf 15 31 17 43
ca 22 99 5a 3b de 3e cd 07`
	// Key 1, AES-128-GCM.
	libiecGCM128 = `
01 40 a1 18 80 12 00 00 00 7c 00 00 00 00 00 02
00 00 00 00 00 00 00 00 00 01 0c 09 95 6b 01 11
a4 1a a5 36 d1 17 a2 00 00 00 68 3f d8 a3 f0 80
d6 f8 3e 88 61 25 dd ac 43 67 1f b2 26 d4 5c 2e
6f c5 9a 82 42 f8 d1 e0 70 7c fd 70 be 5b ed 64
0f 5f 55 d8 bf 4c b4 8e 78 b6 f7 47 fe 58 24 9c
84 ba bd 81 f5 e2 bb 49 ba e4 15 b6 7d e1 04 d6
87 ae f7 25 73 79 eb fa 84 c1 8f 57 2c cb 18 79
12 85 6a eb 6c 84 9e a1 9a c8 0e 90 ce d6 7a 30
45 a4 01 85 10 d7 63 00 98 cf 43 88 83 52 72 d1
eb fa 0d 89 b2`
)

func checkLibiecGOOSE(t *testing.T, s *SPDU) {
	t.Helper()
	if s.SI != SIGOOSE || s.Version != 2 || len(s.Payloads) != 1 {
		t.Fatalf("SPDU = %+v", s)
	}
	p := s.Payloads[0]
	if p.Type != PayloadGOOSE || p.AppID != 0x3001 || p.Simulation {
		t.Errorf("payload header = %+v", p)
	}
	if len(p.APDU) != 98 || p.APDU[0] != 0x61 || !bytes.Contains(p.APDU, []byte("GOISIM/LLN0$GO$gcb1")) ||
		!bytes.HasSuffix(p.APDU, []byte("r-goose")) {
		t.Errorf("APDU = % x", p.APDU)
	}
}

func TestUnmarshalLibiecVectors(t *testing.T) {
	s, err := Unmarshal(unhex(t, libiecUnsecured), nil)
	if err != nil {
		t.Fatalf("unsecured: %v", err)
	}
	checkLibiecGOOSE(t, s)
	if s.KeyID != 0 || s.Signed || s.Encrypted {
		t.Errorf("unsecured SPDU reported as secured: %+v", s)
	}

	keys := store(t, Key{ID: 1, Material: testKey, Sig: SigHMACSHA256_128})
	s, err = Unmarshal(unhex(t, libiecHMAC128), keys)
	if err != nil {
		t.Fatalf("HMAC-SHA256-128: %v", err)
	}
	checkLibiecGOOSE(t, s)
	if !s.Signed || s.KeyID != 1 {
		t.Errorf("signed SPDU = %+v", s)
	}

	keys = store(t, Key{ID: 1, Material: testKey, Sec: SecAES128GCM})
	s, err = Unmarshal(unhex(t, libiecGCM128), keys)
	if err != nil {
		t.Fatalf("AES-128-GCM: %v", err)
	}
	checkLibiecGOOSE(t, s)
	if !s.Encrypted {
		t.Errorf("encrypted SPDU = %+v", s)
	}
}

// Any change to a secured SPDU, header included, fails verification.
func TestTamperingDetected(t *testing.T) {
	for _, tc := range []struct {
		name string
		vec  string
		key  Key
	}{
		{"HMAC", libiecHMAC128, Key{ID: 1, Material: testKey, Sig: SigHMACSHA256_128}},
		{"GCM", libiecGCM128, Key{ID: 1, Material: testKey, Sec: SecAES128GCM}},
	} {
		keys := store(t, tc.key)
		orig := unhex(t, tc.vec)
		for i := range orig {
			b := bytes.Clone(orig)
			b[i] ^= 0x01
			if _, err := Unmarshal(b, keys); err == nil {
				t.Errorf("%s: flipping octet %d went unnoticed", tc.name, i)
			}
		}
	}
	// The wrong key material, under the right identifier.
	other := bytes.Repeat([]byte{0x55}, 16)
	if _, err := Unmarshal(unhex(t, libiecHMAC128), store(t, Key{ID: 1, Material: other, Sig: SigHMACSHA256_128})); !errors.Is(err, ErrAuthentication) {
		t.Errorf("wrong HMAC key: %v", err)
	}
	if _, err := Unmarshal(unhex(t, libiecGCM128), store(t, Key{ID: 1, Material: other, Sec: SecAES128GCM})); !errors.Is(err, ErrAuthentication) {
		t.Errorf("wrong GCM key: %v", err)
	}
	// A key the receiver does not hold.
	if _, err := Unmarshal(unhex(t, libiecHMAC128), store(t, Key{ID: 2, Material: testKey, Sig: SigHMACSHA256_128})); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown key: %v", err)
	}
	// A signed SPDU checked against a key of another algorithm.
	if _, err := Unmarshal(unhex(t, libiecHMAC128), store(t, Key{ID: 1, Material: testKey, Sig: SigHMACSHA256_256})); !errors.Is(err, ErrAuthentication) {
		t.Errorf("mismatched MAC length: %v", err)
	}
	// A secured SPDU with its trailer cut off is not taken as unsecured.
	b := unhex(t, libiecHMAC128)
	if _, err := Unmarshal(b[:len(b)-18], store(t, Key{ID: 1, Material: testKey, Sig: SigHMACSHA256_128})); !errors.Is(err, ErrAuthentication) {
		t.Errorf("stripped signature: %v", err)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	payloads := []Payload{
		{Type: PayloadGOOSE, AppID: 0x3001, APDU: []byte{0x61, 0x03, 0x80, 0x01, 0x41}},
		{Type: PayloadGOOSE, AppID: 0x3002, Simulation: true, APDU: []byte{0x61, 0x00}},
	}
	material32 := bytes.Repeat([]byte{7}, 32)
	for _, tc := range []struct {
		name    string
		version uint16
		key     *Key
	}{
		{"v2 unsecured", 2, nil},
		{"v1 unsecured", 1, nil},
		{"v2 HMAC-SHA256-80", 2, &Key{ID: 9, Material: testKey, Sig: SigHMACSHA256_80}},
		{"v2 HMAC-SHA256-128", 2, &Key{ID: 9, Material: testKey, Sig: SigHMACSHA256_128}},
		{"v2 HMAC-SHA256-256", 2, &Key{ID: 9, Material: material32, Sig: SigHMACSHA256_256}},
		{"v2 HMAC-SHA3-128", 2, &Key{ID: 9, Material: testKey, Sig: SigHMACSHA3_128}},
		{"v1 HMAC-SHA256-128", 1, &Key{ID: 9, Material: testKey, Sig: SigHMACSHA256_128}},
		{"v2 AES-128-GCM", 2, &Key{ID: 9, Material: testKey, Sec: SecAES128GCM}},
		{"v2 AES-256-GCM", 2, &Key{ID: 9, Material: material32, Sec: SecAES256GCM,
			TimeOfCurrentKey: 1_700_000_000, TimeToNextKey: 3600}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var keys *KeyStore
			if tc.key != nil {
				keys = store(t, *tc.key)
			}
			in := &SPDU{SI: SIGOOSE, Number: 42, Version: tc.version, Payloads: payloads}
			b, err := Marshal(in, tc.key, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.key != nil && tc.key.Sec != SecNone && bytes.Contains(b, payloads[0].APDU) {
				t.Error("the encrypted SPDU carries the APDU in clear")
			}
			out, err := Unmarshal(b, keys)
			if err != nil {
				t.Fatal(err)
			}
			if out.SI != SIGOOSE || out.Number != 42 || out.Version != tc.version || len(out.Payloads) != 2 {
				t.Fatalf("decoded %+v", out)
			}
			for i, p := range out.Payloads {
				w := payloads[i]
				if p.Type != w.Type || p.AppID != w.AppID || p.Simulation != w.Simulation || !bytes.Equal(p.APDU, w.APDU) {
					t.Errorf("payload %d = %+v, want %+v", i, p, w)
				}
			}
			if tc.key != nil {
				if out.KeyID != 9 || out.TimeOfCurrentKey != tc.key.TimeOfCurrentKey || out.TimeToNextKey != tc.key.TimeToNextKey {
					t.Errorf("key fields = %d %d %d", out.KeyID, out.TimeOfCurrentKey, out.TimeToNextKey)
				}
				if out.Signed != (tc.key.Sig != SigNone) || out.Encrypted != (tc.key.Sec != SecNone) {
					t.Errorf("signed %v encrypted %v", out.Signed, out.Encrypted)
				}
			}
			// The header lengths are the ones the layout gives.
			secInfo := 12
			if tc.version == 2 {
				secInfo = 11
				if tc.key != nil && tc.key.Sec != SecNone {
					secInfo += gcmIVLen
				}
			}
			if int(b[3]) != 2+commonLen+secInfo || b[5] != commonLen {
				t.Errorf("header lengths %d, %d", b[3], b[5])
			}
			if got := int(b[6])<<24 | int(b[7])<<16 | int(b[8])<<8 | int(b[9]); got != len(b)-10 {
				t.Errorf("SPDU length %d, %d octets follow it", got, len(b)-10)
			}
		})
	}
}

// Version 1 declares its algorithms in the header, and they must be the
// key's: a header claiming a weaker check than the key's is refused.
func TestVersion1AlgorithmsBound(t *testing.T) {
	k := Key{ID: 3, Material: testKey, Sig: SigHMACSHA256_128}
	b, err := Marshal(&SPDU{SI: SISV, Version: 1, Payloads: []Payload{{Type: PayloadSV, APDU: []byte{0x60, 0}}}}, &k, nil)
	if err != nil {
		t.Fatal(err)
	}
	// sig algorithm octet: 2 + 2 + 2 + 10 + 4 + 2 + 1
	b[23] = byte(SigHMACSHA256_80)
	if _, err := Unmarshal(b, store(t, k)); !errors.Is(err, ErrAlgorithm) {
		t.Errorf("downgraded header: %v", err)
	}
	if _, err := Marshal(&SPDU{Version: 1}, &Key{ID: 3, Material: testKey, Sec: SecAES128GCM}, nil); !errors.Is(err, ErrVersion1Encrypt) {
		t.Errorf("v1 encryption: %v", err)
	}
}

func TestKeyValidation(t *testing.T) {
	for _, tc := range []struct {
		key  Key
		want error
	}{
		{Key{ID: 0, Material: testKey, Sig: SigHMACSHA256_128}, ErrKeyID},
		{Key{ID: 1, Material: testKey}, ErrKeyAlgorithm},
		{Key{ID: 1, Material: testKey, Sec: SecAES128GCM, Sig: SigHMACSHA256_128}, ErrKeyCombination},
		{Key{ID: 1, Material: testKey, Sec: SecAES256GCM}, ErrKeyLength},
		{Key{ID: 1, Material: testKey[:8], Sig: SigHMACSHA256_128}, ErrKeyLength},
		{Key{ID: 1, Material: testKey, Sig: SigAESGMAC128}, ErrKeyUnsupported},
	} {
		if _, err := NewKeyStore(tc.key); !errors.Is(err, tc.want) {
			t.Errorf("%+v: %v, want %v", tc.key, err, tc.want)
		}
	}
	// The store keeps its own copy of the material.
	m := bytes.Clone(testKey)
	s := store(t, Key{ID: 1, Material: m, Sig: SigHMACSHA256_128})
	m[0] = 0xFF
	if k, _ := s.Lookup(1); k.Material[0] != 0 {
		t.Error("the store aliases the caller's key material")
	}
	s.Remove(1)
	if _, ok := s.Lookup(1); ok || s.activeKey() != nil {
		t.Error("a removed key is still there")
	}
}

// No input makes Unmarshal panic; every prefix of a valid SPDU is refused.
func TestUnmarshalTruncated(t *testing.T) {
	keys := store(t, Key{ID: 1, Material: testKey, Sec: SecAES128GCM})
	for _, vec := range []string{libiecUnsecured, libiecGCM128} {
		b := unhex(t, vec)
		for n := 0; n < len(b); n++ {
			if _, err := Unmarshal(b[:n], keys); err == nil && n < len(b)-2 {
				t.Errorf("a %d-octet prefix decoded", n)
			}
		}
	}
}

func FuzzUnmarshal(f *testing.F) {
	for _, v := range []string{libiecUnsecured, libiecHMAC128, libiecGCM128} {
		f.Add(unhex(f, v))
	}
	keys := store(f, Key{ID: 1, Material: testKey, Sig: SigHMACSHA256_128})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Unmarshal(b, keys)
		if err != nil {
			return
		}
		// What decodes re-encodes to something that decodes the same.
		out, err := Marshal(&SPDU{SI: s.SI, Number: s.Number, Version: s.Version, Payloads: s.Payloads}, nil, nil)
		if err != nil {
			return
		}
		if _, err := Unmarshal(out, nil); err != nil {
			t.Fatalf("re-encoded SPDU does not decode: %v", err)
		}
	})
}

func TestReplayWindow(t *testing.T) {
	var w replayWindow
	now := time.Unix(1000, 0)
	accept := func(n uint32) bool { return w.accept(n, now, 64, 10*time.Second) }
	for _, n := range []uint32{5, 6, 8, 7} {
		if !accept(n) {
			t.Errorf("fresh %d refused", n)
		}
	}
	for _, n := range []uint32{5, 6, 7, 8} {
		if accept(n) {
			t.Errorf("replayed %d accepted", n)
		}
	}
	if !accept(100) || accept(30) || !accept(99) {
		t.Error("window after a jump")
	}
	// The counter wraps.
	w = replayWindow{}
	if !accept(0xFFFFFFFE) || !accept(0xFFFFFFFF) || !accept(0) || !accept(1) || accept(0xFFFFFFFF) {
		t.Error("wrap-around")
	}
	// A sender silent past the reset time may start again from zero.
	w = replayWindow{}
	accept(500)
	now = now.Add(5 * time.Second)
	if accept(0) {
		t.Error("restart accepted within the reset time")
	}
	now = now.Add(11 * time.Second)
	if !accept(0) || !accept(1) || accept(0) {
		t.Error("restart after the reset time")
	}
}
