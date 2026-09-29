package server_test

import (
	"context"
	"errors"
	"net"
	"strings"
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

// A GOOSE control block serves its SCL configuration under the component
// names of IEC 61850-8-1: a client addresses them by those names.
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
	if read("ED21LD0/LLN0.gcb01.GoEna", model.GO).Bool() {
		t.Error("GoEna = true, want false: the server publishes no GOOSE")
	}
	if got := read("ED21LD0/LLN0.gcb01.GoID", model.GO).Text(); got != "ED21LD0/LLN0.gcb01" {
		t.Errorf("GoID = %q, want the SCL appID", got)
	}
	if got := read("ED21LD0/LLN0.gcb01.DatSet", model.GO).Text(); got != "ED21LD0/LLN0$Measurements" {
		t.Errorf("DatSet = %q, want the dataset reference", got)
	}
	if got := read("ED21LD0/LLN0.gcb01.ConfRev", model.GO).Int64(); got != 1 {
		t.Errorf("ConfRev = %d, want 1", got)
	}
	mac := read("ED21LD0/LLN0.gcb01.DstAddress.Addr", model.GO).Bytes()
	if len(mac) != 6 || mac[0] != 0x01 || mac[3] != 0x03 {
		t.Errorf("DstAddress.Addr = %x, want 010ccd030001", mac)
	}
	if got := read("ED21LD0/LLN0.gcb01.DstAddress.APPID", model.GO).Int64(); got != 0x2000 {
		t.Errorf("DstAddress.APPID = %d, want 8192", got)
	}
	// The whole structure reads too, as a client that reads the block does.
	if got := read("ED21LD0/LLN0.gcb01.DstAddress", model.GO); got.Len() != 4 {
		t.Errorf("DstAddress has %d components, want Addr, PRIORITY, VID, APPID", got.Len())
	}
	if !read("ED21LD0/LLN0.gcb01.FixedOffs", model.GO).Bool() {
		t.Error("FixedOffs = false, want the SCL fixedOffs")
	}
	// The GSSE variant is served under GS, not GO.
	if got := read("ED21LD0/LLN0.gscb01.GsID", model.GS).Text(); got != "ED21LD0/LLN0.gscb01" {
		t.Errorf("GsCB GsID = %q, want the SCL appID", got)
	}
}

// The components of each control block are exactly those IEC 61850-8-1
// defines, in its order. An invented component misleads a client, and a
// name that is not an MMS identifier cannot be addressed at all.
func TestControlBlockComponents(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	server.New(m)
	lln0 := m.Devices[0].Node("LLN0")
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"gcb01", []string{"GoEna", "GoID", "DatSet", "ConfRev", "NdsCom", "DstAddress", "MinTime", "MaxTime", "FixedOffs"}},
		{"gscb01", []string{"GsEna", "GsID"}},
		{"msvcb01", []string{"SvEna", "MsvID", "DatSet", "ConfRev", "SmpRate", "OptFlds", "SmpMod", "DstAddress", "noASDU"}},
		{"usvcb01", []string{"SvEna", "Resv", "UsvID", "DatSet", "ConfRev", "SmpRate", "OptFlds", "SmpMod", "DstAddress", "noASDU"}},
		{"lcb01", []string{"LogEna", "LogRef", "DatSet", "OldEntrTm", "NewEntrTm", "OldEnt", "NewEnt", "TrgOps", "IntgPd"}},
	} {
		do := lln0.Object(tc.name)
		if do == nil {
			t.Errorf("%s not materialised", tc.name)
			continue
		}
		var got []string
		for _, a := range do.Attributes {
			got = append(got, a.Name)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s components = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The sampled-value control block serves SmvOpts as the OptFlds bit
// string, one bit per optional ASDU field, and SmpMod as the enumeration.
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

	v, err := c.Read(ctx, "ED21LD0/LLN0.msvcb01.OptFlds", model.MS)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v.BitLen() != 10 {
		t.Fatalf("OptFlds bit length = %d, want 10", v.BitLen())
	}
	// refreshTime, sampleSynchronized, sampleRate, timestamp, synchSourceId
	for _, bit := range []int{0, 1, 2, 5, 6} {
		if !v.Bit(bit) {
			t.Errorf("OptFlds bit %d clear, want set", bit)
		}
	}
	// dataSet, security
	for _, bit := range []int{3, 4} {
		if v.Bit(bit) {
			t.Errorf("OptFlds bit %d set, want clear", bit)
		}
	}
	// SmpPerSec is 1 in the enumeration.
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.msvcb01.SmpMod"), model.MS).Int64(); got != 1 {
		t.Errorf("SmpMod = %d, want 1 (SmpPerSec)", got)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.msvcb01.MsvID"), model.MS).Text(); got != "ED21MSVCB01" {
		t.Errorf("MsvID = %q, want the SCL smvID", got)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.usvcb01.UsvID"), model.US).Text(); got != "ED21USVCB01" {
		t.Errorf("UsvID = %q, want the SCL smvID", got)
	}
}

// A log control block serves its dataset and log reference. The reference
// names the log in LLN0 of the block's device, the IEC 61850-6 default
// when the LogControl places it nowhere else.
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
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.lcb01.LogRef"), model.LG).Text(); got != "ED21LD0/LLN0$EventLog" {
		t.Errorf("LogRef = %q, want ED21LD0/LLN0$EventLog", got)
	}
	if got := mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.lcb01.DatSet"), model.LG).Text(); got != "ED21LD0/LLN0$Measurements" {
		t.Errorf("DatSet = %q, want the dataset reference", got)
	}
	if got := len(mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LLN0.lcb01.OldEnt"), model.LG).Bytes()); got != 8 {
		t.Errorf("OldEnt is %d octets, want an 8-octet EntryID", got)
	}
}

// A log placed in another logical node or device is referenced there.
func TestLCBLogRefElsewhere(t *testing.T) {
	lc := &model.LogControl{Name: "lcb", LogName: "Events", LogLDInst: "LD1", LogLN: "PRE_GAPC1"}
	ld := &model.LogicalDevice{Name: "IEDLD0", Inst: "LD0"}
	ln := &model.LogicalNode{Name: "LLN0", Class: "LLN0", LogControls: []*model.LogControl{lc}}
	ld.Nodes = []*model.LogicalNode{ln}
	server.New(&model.Model{Name: "IED", Devices: []*model.LogicalDevice{ld}})
	a := ln.Object("lcb").Attribute("LogRef")
	if got := a.Value.Text(); got != "IEDLD1/PRE_GAPC1$Events" {
		t.Errorf("LogRef = %q, want IEDLD1/PRE_GAPC1$Events", got)
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

	// Instance 03: 01 is reserved for a client by the configuration.
	v, err := c.Read(ctx, model.ObjectReference("ED21LD0/LLN0.brcb0103.Owner"), model.BR)
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

// A ClientLN reservation reaches the wire: the reserved instance shows
// ResvTms -1 and its client as Owner, and a client from any other address
// is refused it, while the unreserved instances stay open.
func TestClientLNReservationServed(t *testing.T) {
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

	if got := mustRead(t, c, ctx, "ED21LD0/LLN0.brcb0101.ResvTms", model.BR).Int64(); got != -1 {
		t.Errorf("brcb0101 ResvTms = %d, want -1", got)
	}
	if got := mustRead(t, c, ctx, "ED21LD0/LLN0.brcb0101.Owner", model.BR).Bytes(); string(got) != "\x0a\x00\x00\x32" {
		t.Errorf("brcb0101 Owner = %x, want HMI's 0a000032", got)
	}
	if got := mustRead(t, c, ctx, "ED21LD0/LLN0.brcb0102.ResvTms", model.BR).Int64(); got != 0 {
		t.Errorf("brcb0102 ResvTms = %d, want 0: its ClientLN has no address", got)
	}
	write := func(item string) error {
		res, err := c.MMS().Write(ctx, "ED21LD0", []string{item}, []*mms.Value{model.TrgGI.Value()})
		if err != nil {
			t.Fatalf("write %s: %v", item, err)
		}
		return res[0]
	}
	if err := write("LLN0$BR$brcb0101$TrgOps"); !errors.Is(err, mms.AccessTemporarilyUnavailable) {
		t.Errorf("loopback client writing HMI's instance: %v, want temporarily-unavailable", err)
	}
	if err := write("LLN0$BR$brcb0103$TrgOps"); err != nil {
		t.Errorf("writing a free instance: %v", err)
	}
}
