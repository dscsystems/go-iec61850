package asn1

import (
	"bytes"
	"testing"
	"time"
)

func TestReadSpanDefinite(t *testing.T) {
	in := []byte{0x30, 0x03, 0x02, 0x01, 0x05, 0x04, 0x00}
	d := NewDecoder(in)
	s, err := d.ReadSpan()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.Full, in[:5]) || !bytes.Equal(s.Content, in[2:5]) || !bytes.Equal(s.ContentEOC, s.Content) || s.Indefinite {
		t.Fatalf("span %+v", s)
	}
	if !d.More() {
		t.Fatal("decoder should have one more element")
	}
}

func TestReadSpanIndefinite(t *testing.T) {
	// SEQUENCE (indefinite) { INTEGER 5, SEQUENCE (indefinite) { NULL } }
	in := []byte{0x30, 0x80, 0x02, 0x01, 0x05, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff}
	d := NewDecoder(in)
	s, err := d.ReadSpan()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Indefinite {
		t.Fatal("expected indefinite")
	}
	if !bytes.Equal(s.Full, in[:13]) {
		t.Fatalf("full % x", s.Full)
	}
	if !bytes.Equal(s.Content, in[2:11]) {
		t.Fatalf("content % x", s.Content)
	}
	if !bytes.Equal(s.ContentEOC, in[2:13]) {
		t.Fatalf("contentEOC % x", s.ContentEOC)
	}
	if tag, ok := d.PeekTag(); !ok || tag != TagBoolean {
		t.Fatal("decoder did not stop after the EOC")
	}
}

func TestReadSpanTruncated(t *testing.T) {
	for _, in := range [][]byte{{0x30, 0x05, 0x02}, {0x30, 0x80, 0x02, 0x01, 0x05}, {0x30}} {
		if _, err := NewDecoder(in).ReadSpan(); err == nil {
			t.Fatalf("% x: expected error", in)
		}
	}
}

func TestTime62351(t *testing.T) {
	ok := map[string]time.Time{
		"2026101113Z":            time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC),
		"202610111304Z":          time.Date(2026, 10, 11, 13, 4, 0, 0, time.UTC),
		"20261011130405Z":        time.Date(2026, 10, 11, 13, 4, 5, 0, time.UTC),
		"20261011130405.5Z":      time.Date(2026, 10, 11, 13, 4, 5, 5e8, time.UTC),
		"20261011130405,123456Z": time.Date(2026, 10, 11, 13, 4, 5, 123456000, time.UTC),
		"20240229235959.000001Z": time.Date(2024, 2, 29, 23, 59, 59, 1000, time.UTC),
	}
	for s, want := range ok {
		got, err := ParseTime62351([]byte(s))
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: got %v, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "20261011130405", "20261011T130405Z", "20261011130405+0100", "20261011130405.Z",
		"20261311130405Z", "20230229130405Z", "2026101113040Z", "20261011130405.5x5Z", "2026101124Z"} {
		if _, err := ParseTime62351([]byte(s)); err == nil {
			t.Errorf("%q: expected error", s)
		}
	}
	for _, c := range []struct {
		t    time.Time
		want string
	}{
		{time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "20260102030405Z"},
		{time.Date(2026, 1, 2, 3, 4, 5, 120e6, time.UTC), "20260102030405.12Z"},
		{time.Date(2026, 1, 2, 3, 4, 5, 7e6+999, time.UTC), "20260102030405.007Z"},
	} {
		if got := string(FormatTime62351(c.t)); got != c.want {
			t.Errorf("format %v = %s, want %s", c.t, got, c.want)
		}
	}
}

func TestNamedBits(t *testing.T) {
	cases := []struct {
		bits []int
		want []byte
	}{
		{nil, []byte{0}},
		{[]int{0}, []byte{7, 0x80}},
		{[]int{0, 1}, []byte{6, 0xc0}},
		{[]int{1}, []byte{6, 0x40}},
		{[]int{2}, []byte{5, 0x20}},
	}
	for _, c := range cases {
		if got := NamedBits(c.bits...); !bytes.Equal(got, c.want) {
			t.Errorf("%v: % x want % x", c.bits, got, c.want)
		}
	}
}
