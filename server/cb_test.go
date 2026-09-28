package server_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// startServerWith serves m on a loopback listener and returns its address.
func startServerWith(t *testing.T, m *model.Model, opts ...server.Option) (string, *server.Server) {
	t.Helper()
	return startServerWithModel(t, server.New(m, opts...))
}

// startServerWithModel serves an already-configured server, for a test that
// had to register handlers or options on it first.
func startServerWithModel(t *testing.T, srv *server.Server) (string, *server.Server) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String(), srv
}

// loadEd21 parses the Edition 2.1 fixture for a test that needs the model
// rather than a server.
func loadEd21(t *testing.T) (*model.Model, error) {
	t.Helper()
	return scl.LoadModel("../testdata/ed21_diverse.cid")
}

// mustRead is a Read that fails the test rather than returning an error.
func mustRead(t *testing.T, c *client.Client, ctx context.Context, ref model.ObjectReference, fc model.FC) *mms.Value {
	t.Helper()
	v, err := c.Read(ctx, ref, fc)
	if err != nil {
		t.Fatalf("Read %s: %v", ref, err)
	}
	return v
}

// The GOOSE, sampled-value and log control blocks the SCL loader carries
// must be visible to a client browsing the server: before, a model with
// GOOSE configuration exposed no GoCB at all.
func TestControlBlocksAreBrowseable(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, tc := range []struct {
		class client.ACSIClass
		want  model.ObjectReference
	}{
		{client.ACSIGoCB, "ED21LD0/LLN0.GO.gcb01"},
		{client.ACSIGsCB, "ED21LD0/LLN0.GS.gscb01"},
		{client.ACSIMSVCB, "ED21LD0/LLN0.MS.msvcb01"},
		{client.ACSILCB, "ED21LD0/LLN0.LG.lcb01"},
		{client.ACSIUSVCB, "ED21LD0/LLN0.US.usvcb01"},
	} {
		got, err := c.Browse(ctx, "ED21LD0", tc.class)
		if err != nil {
			t.Fatalf("Browse %v: %v", tc.class, err)
		}
		found := false
		for _, o := range got {
			if o.Ref == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("%v = %v, want it to include %q", tc.class, got, tc.want)
		}
	}
}

// A GOOSE control block serves its SCL configuration: the dataset,
// configuration revision, identity and multicast address.
func TestGoCBReadback(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	read := func(ref model.ObjectReference, fc model.FC) *mms.Value {
		t.Helper()
		return mustRead(t, c, ctx, ref, fc)
	}
	if got := read("ED21LD0/LLN0.gcb01.GoID", model.GO).Text(); got != "ED21LD0/LLN0.gcb01" {
		t.Errorf("GoID = %q, want the SCL appID", got)
	}
	if got := read("ED21LD0/LLN0.gcb01.DatSet", model.GO).Text(); got != "Measurements" {
		t.Errorf("DatSet = %q, want Measurements", got)
	}
	if got := read("ED21LD0/LLN0.gcb01.ConfRev", model.GO).Int64(); got != 1 {
		t.Errorf("ConfRev = %d, want 1", got)
	}
	mac := read("ED21LD0/LLN0.gcb01.DstMAC", model.GO).Bytes()
	if len(mac) != 6 || mac[0] != 0x01 || mac[3] != 0x03 {
		t.Errorf("DstMAC = %x, want 010ccd030001", mac)
	}
	if got := read("ED21LD0/LLN0.gcb01.APPID", model.GO).Int64(); got != 0x2000 {
		t.Errorf("APPID = %d, want 8192", got)
	}
	// The GSSE variant is served under GS, not GO.
	if got := read("ED21LD0/LLN0.gscb01.GoID", model.GS).Text(); got != "ED21LD0/LLN0.gscb01" {
		t.Errorf("GsCB GoID = %q, want the SCL appID", got)
	}
}

// The sampled-value control block serves SmvOpts as the SmvOptFlds bit
// string, one bit per optional ASDU field.
func TestMSVCBOptFlds(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	v, err := c.Read(ctx, "ED21LD0/LLN0.msvcb01.SmvOptFlds", model.MS)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v.BitLen() != 10 {
		t.Fatalf("SmvOptFlds bit length = %d, want 10", v.BitLen())
	}
	// refreshTime, sampleSynchronized, sampleRate, timestamp, synchSourceId
	for _, bit := range []int{0, 1, 2, 5, 6} {
		if !v.Bit(bit) {
			t.Errorf("SmvOptFlds bit %d clear, want set", bit)
		}
	}
	// dataSet, security
	for _, bit := range []int{3, 4} {
		if v.Bit(bit) {
			t.Errorf("SmvOptFlds bit %d set, want clear", bit)
		}
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.msvcb01.SmpMod"), model.MS).Text(); got != "SmpPerSec" {
		t.Errorf("SmpMod = %q, want SmpPerSec", got)
	}
}

// A log control block serves its dataset, log reference and the buffer
// period, and stays writable only in the sense that the standard allows.
func TestLCBReadback(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if !mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.lcb01.LogEna"), model.LG).Bool() {
		t.Error("LogEna should be true: the SCL enables the log")
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.lcb01.LogRef"), model.LG).Text(); got != "ED21/LLN0.EventLog" {
		t.Errorf("LogRef = %q, want the SCL logName", got)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.lcb01.BufTime"), model.LG).Int64(); got != 500 {
		t.Errorf("BufTime = %d, want 500", got)
	}
	if !mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.lcb01.ReasonCode"), model.LG).Bool() {
		t.Error("ReasonCode should default to true")
	}
}

// BRCB.Owner has to exist: it was in the read-only list, so a client could
// be refused a write and then be told the attribute did not exist.
func TestBRCBOwnerExists(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	v, err := c.Read(ctx, model.ObjectReference("ED21LD0/LLN0.brcb0101.Owner"), model.BR)
	if err != nil {
		t.Fatalf("reading BRCB.Owner: %v", err)
	}
	if len(v.Bytes()) != 0 {
		t.Errorf("Owner = %q on an unreserved block, want empty", v.Text())
	}
}

// A device whose SCL declares its setting groups gets an SGCB with that
// count, active group and reservation time, without WithSettingGroups.
func TestDeclaredSettingGroups(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.SGCB.NumOfSG"), model.SP).Int64(); got != 2 {
		t.Errorf("NumOfSG = %d, want the declared 2", got)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.SGCB.ActSG"), model.SP).Int64(); got != 1 {
		t.Errorf("ActSG = %d, want the declared 1", got)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.SGCB.ResvTms"), model.SP).Int64(); got != 30000 {
		t.Errorf("ResvTms = %d, want the declared 30000", got)
	}
	// The active group's value is the one the SCL resolved.
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/GGIO1.IntRange.setVal"), model.SG).Float64(); got != 50.5 {
		t.Errorf("IntRange.setVal = %v, want the active group's 50.5", got)
	}
}

// Each setting group holds the value the document gave it, and selecting a
// group serves that group's value.
func TestSettingGroupValuesPerGroup(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.Write(ctx, model.ObjectReference("ED21LD0/LLN0.SGCB.ActSG"), model.SP, mms.NewUint8(2)); err != nil {
		t.Fatalf("selecting group 2: %v", err)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/GGIO1.IntRange.setVal"), model.SG).Float64(); got != 60.5 {
		t.Errorf("group 2 setVal = %v, want 60.5", got)
	}
	if err := c.Write(ctx, model.ObjectReference("ED21LD0/LLN0.SGCB.ActSG"), model.SP, mms.NewUint8(1)); err != nil {
		t.Fatalf("selecting group 1: %v", err)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/GGIO1.IntRange.setVal"), model.SG).Float64(); got != 50.5 {
		t.Errorf("group 1 setVal = %v, want 50.5", got)
	}
}

// An attribute under a functional constraint the library does not know
// stays readable over MMS, under the peer's own mnemonic.
func TestUnknownFCIsReadableOverMMS(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// The client addresses it with the mnemonic the document used, which
	// ParseFCLenient turns into FCUnknown. It reads: an object this
	// library does not fully understand still has to be observable.
	v, err := c.Read(ctx, model.ObjectReference("ED21LD0/GGIO1.Beh.vendorFCAttr"),
		model.ParseFCLenient("ZX"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if v.Type() != mms.TypeInteger {
		t.Errorf("value type = %v, want an integer", v.Type())
	}
	// A write is refused: the writable constraints are a fixed set, and an
	// unknown one is not writable by default.
	if err := c.Write(ctx, model.ObjectReference("ED21LD0/GGIO1.Beh.vendorFCAttr"),
		model.ParseFCLenient("ZX"), mms.NewInt32(7)); err == nil {
		t.Error("a write under an unknown functional constraint should be refused")
	}
}

// An attribute whose basic type the library does not know is reported with
// an access error, not served as a zero of some invented type. The two are
// worth telling apart: the object is there, and a client told
// object-non-existent will conclude the device does not have it.
func TestUnknownBasicTypeReadIsReportedNotFabricated(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_, err = c.Read(ctx, model.ObjectReference("ED21LD0/GGIO1.VendorDO.stVal"), model.ST)
	if err == nil {
		t.Fatal("an attribute of an unknown basic type served a value")
	}
	if !errors.Is(err, mms.AccessTypeInconsistent) {
		t.Errorf("read failed with %v, want type-inconsistent", err)
	}
	// A known-typed sibling in the same object still reads, so the failure
	// is about the type and not about the object.
	v, err := c.Read(ctx, model.ObjectReference("ED21LD0/GGIO1.VendorDO.opts"), model.ST)
	if err != nil {
		t.Fatalf("a known-typed sibling failed to read: %v", err)
	}
	if v.BitLen() != 10 {
		t.Errorf("bit-string attribute read back with %d bits, want 10", v.BitLen())
	}
}
