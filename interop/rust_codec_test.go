package interop_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/goose"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/sv"
)

// The Rust peers independently construct the same fixture and assert equality
// when decoding Go's PDU. The Go side compares the decoded fields with the
// fixture, not a re-encoding, so a layout error shared by Go's encoder and
// decoder cannot pass; comparing values allows BER boolean variants.
func TestRustGooseCodec(t *testing.T) {
	root := rustRoot(t)
	tq := mms.TimeQuality(0x8a)
	fixture := &goose.Message{AppID: 0x1000, GoCbRef: "DemoIEDLD0/LLN0$GO$gcbStatus", TimeAllowedToLive: 1000,
		DatSet: "DemoIEDLD0/LLN0$dsStatus", GoID: "interop", T: time.Unix(1700000000, 0).UTC(), TimeQuality: &tq,
		StNum: 0xffffffff, SqNum: 128, Test: true, ConfRev: 1, NumDatSetEntries: 6,
		Values: []*mms.Value{mms.NewBool(true), mms.NewInt32(-123), mms.NewUint32(128), mms.NewFloat32(1.25), mms.NewVisibleString("hello"), mms.NewStructure(mms.NewBool(false), mms.NewOctetString([]byte{0, 128, 255}))}}
	check := func(t *testing.T, pdu []byte) {
		parsed, err := goose.Parse(apdu(pdu))
		if err != nil {
			t.Fatal(err)
		}
		if !sameValues(parsed.Values, fixture.Values) || !parsed.T.Equal(fixture.T) {
			t.Fatalf("Go decoded Rust fixture incorrectly: %+v", parsed)
		}
		got, want := *parsed, *fixture
		got.Values, want.Values, got.T, want.T = nil, nil, time.Time{}, time.Time{}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("Go decoded Rust fixture incorrectly:\n got %+v\nwant %+v", got, want)
		}
	}
	codecBothWays(t, filepath.Join(root, "target/debug/examples/go_interop_goose"), fixture.Marshal()[8:], check)
}

func TestRustSVCodec(t *testing.T) {
	root := rustRoot(t)
	tq := mms.TimeQuality(0x8a)
	a := &sv.ASDU{SvID: "interop", DatSet: "DemoIEDLD0/LLN0$dsMeas", SmpCnt: 65535, ConfRev: 0x80000001,
		RefrTm: time.Unix(1700000000, 0).UTC(), RefrTmQuality: &tq, SmpSynch: sv.SmpSynchGlobal, SmpRate: 4000,
		HasSmpMod: true, SmpMod: sv.SmpPerSec, HasGmIdentity: true, GmIdentity: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Sample: make([]byte, 160)}
	for i := range a.Sample {
		a.Sample[i] = byte(i)
	}
	b := *a
	b.SmpCnt = 0
	fixture := &sv.PDU{AppID: 0x1000, ASDUs: []*sv.ASDU{a, &b}}
	check := func(t *testing.T, pdu []byte) {
		parsed, err := sv.Parse(apdu(pdu))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.AppID != fixture.AppID || len(parsed.ASDUs) != len(fixture.ASDUs) {
			t.Fatalf("Go decoded Rust fixture incorrectly: %+v", parsed)
		}
		for i, a := range parsed.ASDUs {
			got, want := *a, *fixture.ASDUs[i]
			if !got.RefrTm.Equal(want.RefrTm) {
				t.Fatalf("ASDU %d: refrTm %v, want %v", i, got.RefrTm, want.RefrTm)
			}
			got.RefrTm, want.RefrTm = time.Time{}, time.Time{}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("ASDU %d decoded incorrectly:\n got %+v\nwant %+v", i, got, want)
			}
		}
	}
	codecBothWays(t, filepath.Join(root, "target/debug/examples/go_interop_sv"), fixture.Marshal()[8:], check)
}

func sameValues(a, b []*mms.Value) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}

func apdu(pdu []byte) []byte {
	n := len(pdu) + 8
	return append([]byte{0x10, 0, byte(n >> 8), byte(n), 0, 0, 0, 0}, pdu...)
}

func codecBothWays(t *testing.T, binary string, goPDU []byte, check func(*testing.T, []byte)) {
	t.Helper()
	for _, direction := range []string{"RustToGo", "GoToRustToGo"} {
		t.Run(direction, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			args := []string{}
			if direction == "GoToRustToGo" {
				path := filepath.Join(t.TempDir(), "pdu.bin")
				if err := os.WriteFile(path, goPDU, 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, path)
			}
			cmd := exec.CommandContext(ctx, binary, args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("Rust codec: %v: %s", err, stderr.String())
			}
			check(t, output)
		})
	}
}
