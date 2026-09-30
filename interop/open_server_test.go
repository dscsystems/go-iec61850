package interop_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/goose"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/sv"
)

const openLD = "IED1_XCBRGenericIO"

func openServer(t *testing.T, ied string) (*client.Client, string, string) {
	t.Helper()
	root := os.Getenv("IEC61850_OPEN_SERVER_ROOT")
	build := os.Getenv("IEC61850_OPEN_SERVER_BUILD")
	if root == "" || build == "" {
		t.Skip("run interop/run-open-server.sh to build and enable the open_server checks")
	}
	runtime := t.TempDir()
	copyFile := func(src, dst string) {
		t.Helper()
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if ied == "IED1_XCBR" {
		copyFile(filepath.Join(build, "plugin/libcbr_simulation.so"), filepath.Join(runtime, "plugin/libcbr_simulation.so"))
		copyFile(filepath.Join(root, "plugin/cbr_simulator.config"), filepath.Join(runtime, "plugin/cbr_simulator.config"))
	}
	copyFile(filepath.Join(root, "vmd-filestore/comtrade_data.cfg"), filepath.Join(runtime, "vmd-filestore/comtrade_data.cfg"))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	cmd := exec.CommandContext(ctx, filepath.Join(build, "open_server"), "-e", "lo", "-i", "127.0.0.1", "-p", strconv.Itoa(port), "-c", filepath.Join(root, "cfg", ied+".cfg"), "-x", filepath.Join(root, "cfg", ied+".ext"))
	cmd.Dir = runtime
	logPath := filepath.Join(runtime, "server.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		cancel()
		log.Close()
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			cancel()
			<-exited
		}
		cancel()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			if len(b) > 10000 {
				b = b[len(b)-10000:]
			}
			t.Logf("reference server log:\n%s", b)
		}
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		b, _ := os.ReadFile(logPath)
		if bytes.Contains(b, []byte("loading plugins finished")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server initialization timed out: %s", b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	c, err := client.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, runtime, addr
}

func openContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func readOpen(t *testing.T, c *client.Client, ref string, fc model.FC) *mms.Value {
	t.Helper()
	v, err := c.Read(openContext(t), model.ObjectReference(openLD+"/"+ref), fc)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func position(t *testing.T, c *client.Client, ln string, want model.Dbpos) {
	t.Helper()
	ctx := openContext(t)
	for {
		v, err := c.Read(ctx, model.ObjectReference(openLD+"/"+ln+".Pos.stVal"), model.ST)
		if err != nil {
			t.Fatal(err)
		}
		if model.DbposFromValue(v) == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s position=%v want %v", ln, v, want)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestOpenServerBreaker(t *testing.T) {
	c, runtime, addr := openServer(t, "IED1_XCBR")
	t.Run("AssociationDirectoryAndTypes", func(t *testing.T) {
		ctx := openContext(t)
		vendor, name, rev, err := c.MMS().Identify(ctx)
		if err != nil || vendor == "" {
			t.Fatalf("Identify: %q %q %q %v", vendor, name, rev, err)
		}
		t.Logf("identity: %q %q %q", vendor, name, rev)
		status, err := c.MMS().Status(ctx, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("status: %+v", status)
		devices, err := c.LogicalDevices(ctx)
		if err != nil || !slices.Contains(devices, openLD) {
			t.Fatalf("devices=%v err=%v", devices, err)
		}
		nodes, err := c.LogicalNodes(ctx, openLD)
		if err != nil {
			t.Fatal(err)
		}
		for _, ln := range []string{"LLN0", "LPHD1", "CSWI1", "XCBR1", "CSWI2", "XSWI2", "CILO1"} {
			if !slices.Contains(nodes, ln) {
				t.Errorf("missing %s", ln)
			}
		}
		spec, err := c.MMS().GetVariableAccessAttributes(ctx, openLD, "CSWI1$CO$Pos$Oper")
		if err != nil || spec.Kind != mms.TypeStructure {
			t.Fatalf("Oper spec=%v err=%v", spec, err)
		}
		tree, err := c.RetrieveModel(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if tree.Attribute(openLD+"/CSWI1.Pos.Oper.origin.orIdent", model.CO) == nil {
			t.Fatal("nested control attribute absent from retrieved model")
		}
	})
	t.Run("TypedAndAsyncReads", func(t *testing.T) {
		for _, tc := range []struct {
			ref  string
			fc   model.FC
			kind mms.Type
		}{{"LLN0.NamPlt.vendor", model.DC, mms.TypeVisibleString}, {"XCBR1.Pos.stVal", model.ST, mms.TypeBitString}, {"XCBR1.Pos.q", model.ST, mms.TypeBitString}, {"XCBR1.Pos.t", model.ST, mms.TypeUTCTime}, {"CSWI1.Pos.ctlModel", model.CF, mms.TypeInteger}, {"CILO1.EnaOpn.stVal", model.ST, mms.TypeBoolean}} {
			v := readOpen(t, c, tc.ref, tc.fc)
			if v.Type() != tc.kind {
				t.Fatalf("%s type=%v", tc.ref, v.Type())
			}
		}
		requests := c.ReadAllAsync(openContext(t), model.ST, openLD+"/XCBR1.Pos.stVal", openLD+"/XSWI2.Pos.stVal")
		for _, r := range requests {
			v, err := r.Result()
			if err != nil || model.DbposFromValue(v) != model.DbposOn {
				t.Fatalf("async=%v err=%v", v, err)
			}
		}
		if _, err := c.Read(openContext(t), openLD+"/Missing.Pos.stVal", model.ST); err == nil {
			t.Fatal("missing object accepted")
		}
	})
	t.Run("WritePolicy", func(t *testing.T) {
		ctx := openContext(t)
		ref := model.ObjectReference(openLD + "/CSWI1.Pos.ctlModel")
		old := readOpen(t, c, "CSWI1.Pos.ctlModel", model.CF)
		if err := c.Write(ctx, ref, model.CF, mms.NewInt32(4)); err == nil {
			t.Fatal("CF write policy was not enforced")
		}
		if value := readOpen(t, c, "CSWI1.Pos.ctlModel", model.CF); !value.Equal(old) {
			t.Fatalf("refused write changed value: %v", value)
		}

		if err := c.Write(ctx, openLD+"/XCBR1.Pos.stVal", model.ST, model.DbposOff.Value()); err == nil {
			t.Fatal("direct status write accepted")
		}
	})
	t.Run("StaticAndDynamicDatasets", func(t *testing.T) {
		ctx := openContext(t)
		ds, err := c.ReadDataSet(ctx, openLD+"/LLN0.Events")
		if err != nil || len(ds.Members) != 1 {
			t.Fatalf("dataset=%v err=%v", ds, err)
		}
		if ds.Members[0].Ref != openLD+"/XCBR1.Pos.stVal" || ds.Members[0].FC != model.ST {
			t.Fatalf("member=%+v", ds.Members[0])
		}
		dynamic := model.ObjectReference(openLD + "/LLN0.goInterop")
		if err := c.CreateDataSet(ctx, dynamic, []client.DataSetEntry{{Ref: openLD + "/XCBR1.Pos.stVal", FC: model.ST}, {Ref: openLD + "/CILO1.EnaOpn.stVal", FC: model.ST}}); err != nil {
			t.Fatal(err)
		}
		ds, err = c.ReadDataSet(ctx, dynamic)
		if err != nil || len(ds.Members) != 2 {
			t.Fatalf("dynamic=%v err=%v", ds, err)
		}
		if err := c.DeleteDataSet(ctx, dynamic); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ReadDataSet(ctx, dynamic); err == nil {
			t.Fatal("deleted dataset readable")
		}
	})
	t.Run("FileReadAndTransferPolicy", func(t *testing.T) {
		ctx := openContext(t)
		entries, err := c.FileDirectory(ctx, "")
		if err != nil || len(entries) == 0 {
			t.Fatalf("directory=%v err=%v", entries, err)
		}
		want, err := os.ReadFile(filepath.Join(runtime, "vmd-filestore/comtrade_data.cfg"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.ReadFile(ctx, "comtrade_data.cfg")
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("file len=%d want=%d err=%v", len(got), len(want), err)
		}
		payload := []byte("Go MMS obtainFile interoperability\n")
		if err := c.MMS().ObtainFile(ctx, fstest.MapFS{"source.txt": {Data: payload}}, "source.txt", "uploaded.txt"); err != nil {
			t.Fatal(err)
		}
		got, err = c.ReadFile(ctx, "uploaded.txt")
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("uploaded=%q err=%v", got, err)
		}
		if err := c.MMS().FileDelete(ctx, "uploaded.txt"); err == nil {
			t.Fatal("server deletion policy not enforced")
		}
		if _, err := c.ReadFile(ctx, "missing.txt"); err == nil {
			t.Fatal("missing file accepted")
		}
	})
	t.Run("BRCBGeneralInterrogationAndIntegrity", func(t *testing.T) {
		ctx := openContext(t)
		rcb, err := c.GetRCB(ctx, openLD+"/LLN0.BR.EventsRCB01")
		if err != nil {
			t.Fatal(err)
		}
		rcb.OptFlds = model.OptFldsDefault | model.OptDataRef | model.OptEntryID | model.OptBufOvfl
		rcb.TrgOps = model.TrgGI | model.TrgIntegrity | model.TrgDataChange
		rcb.IntgPd = 200 * time.Millisecond
		reports := make(chan *client.Report, 64)
		sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) {
			select {
			case reports <- r:
			default:
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Disable(ctx)
		if err := c.TriggerGI(ctx, rcb); err != nil {
			t.Fatal(err)
		}
		var gi, integrity bool
		for !gi || !integrity {
			select {
			case r := <-reports:
				if len(r.Entries) != 1 {
					t.Fatalf("report=%+v", r)
				}
				e := r.Entries[0]
				if e.Ref != openLD+"/XCBR1.Pos.stVal" || e.FC != model.ST || e.Value.Type() != mms.TypeBitString || len(r.EntryID) != 8 {
					t.Fatalf("report=%+v entry=%+v", r, e)
				}
				gi = gi || e.Reason&model.ReasonGI != 0
				integrity = integrity || e.Reason&model.ReasonIntegrity != 0
			case <-ctx.Done():
				t.Fatalf("GI=%v integrity=%v: %v", gi, integrity, ctx.Err())
			}
		}
	})
	t.Run("SBOEnhancedCancelAndInterlocking", func(t *testing.T) {
		ctx := openContext(t)
		breaker, err := c.ControlFor(ctx, openLD+"/CSWI1.Pos")
		if err != nil {
			t.Fatal(err)
		}
		if breaker.Model() != model.CtlSBOEnhanced {
			t.Fatalf("model=%v", breaker.Model())
		}
		if typ, err := breaker.CtlValType(ctx); err != nil || typ != mms.TypeBoolean {
			t.Fatalf("ctlVal=%v err=%v", typ, err)
		}
		if err := breaker.SelectWithValue(ctx, mms.NewBool(false)); err != nil {
			t.Fatal(err)
		}
		if err := breaker.Cancel(ctx); err != nil {
			t.Fatal(err)
		}
		position(t, c, "XCBR1", model.DbposOn)
		swi, err := c.ControlFor(ctx, openLD+"/CSWI2.Pos")
		if err != nil {
			t.Fatal(err)
		}
		err = swi.Operate(ctx, mms.NewBool(false), client.WithInterlockCheck(true))
		var ce *client.ControlError
		if !errors.As(err, &ce) || ce.AddCause != model.AddCauseBlockedByInterlocking {
			t.Fatalf("interlock rejection: %T %v", err, err)
		}
		if err := breaker.Operate(ctx, mms.NewBool(false)); err != nil {
			t.Fatal(err)
		}
		position(t, c, "XCBR1", model.DbposOff)
		if !readOpen(t, c, "CILO1.EnaOpn.stVal", model.ST).Bool() {
			t.Fatal("interlocking did not release after breaker opened")
		}
		if err := swi.Operate(ctx, mms.NewBool(false)); err != nil {
			t.Fatal(err)
		}
		position(t, c, "XSWI2", model.DbposOff)
		if err := swi.Operate(ctx, mms.NewBool(true)); err != nil {
			t.Fatal(err)
		}
		position(t, c, "XSWI2", model.DbposOn)
		if err := breaker.Operate(ctx, mms.NewBool(true)); err != nil {
			t.Fatal(err)
		}
		position(t, c, "XCBR1", model.DbposOn)
	})
	t.Run("GOOSEBothDirectionsAndDataChangeReport", func(t *testing.T) {
		ctx := openContext(t)
		eth, err := ethernet.Open("lo", ethernet.EtherTypeGOOSE)
		if err != nil {
			t.Fatal(err)
		}
		defer eth.Close()
		frames := make(chan *goose.Message, 32)
		stop, err := goose.NewSubscriber(eth).Subscribe(goose.Filter{AppID: 4096}, func(g *goose.Message) {
			select {
			case frames <- g:
			default:
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		rcb, err := c.GetRCB(ctx, openLD+"/LLN0.BR.EventsRCB01")
		if err != nil {
			t.Fatal(err)
		}
		rcb.TrgOps = model.TrgDataChange
		rcb.IntgPd = 0
		reports := make(chan *client.Report, 32)
		sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) {
			select {
			case reports <- r:
			default:
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Disable(ctx)
		tx, err := ethernet.Open("lo")
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Close()
		g := &goose.Message{GoCbRef: "IED2_PTOCGenericIO/LLN0$GO$gcbEvents", DatSet: "IED2_PTOCGenericIO/LLN0$Events", GoID: "events", AppID: 4098, StNum: 1, ConfRev: 2, TimeAllowedToLive: 1000, T: time.Now(), NumDatSetEntries: 2, Values: []*mms.Value{mms.NewBool(false), mms.NewBool(true)}}
		for i := 0; i < 3; i++ {
			g.SqNum = uint32(i)
			if err := tx.WriteFrame(&ethernet.Frame{Dst: [6]byte{1, 12, 205, 1, 0, 2}, Src: [6]byte{2, 0, 0, 0, 0, 1}, EtherType: ethernet.EtherTypeGOOSE, VLAN: &ethernet.VLANTag{Priority: 4, VID: 1}, Payload: g.Marshal()}); err != nil {
				t.Fatal(err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		position(t, c, "XCBR1", model.DbposOff)
		var gooseOff, reportOff bool
		for !gooseOff || !reportOff {
			select {
			case message := <-frames:
				if message.GoCbRef != openLD+"/LLN0$GO$gcbEvents" || len(message.Values) != 1 {
					t.Fatalf("GOOSE=%+v", message)
				}
				gooseOff = gooseOff || model.DbposFromValue(message.Values[0]) == model.DbposOff
			case r := <-reports:
				for _, e := range r.Entries {
					reportOff = reportOff || e.Ref == openLD+"/XCBR1.Pos.stVal" && e.Reason&model.ReasonDataChange != 0 && model.DbposFromValue(e.Value) == model.DbposOff
				}
			case <-ctx.Done():
				t.Fatalf("GOOSE opened=%v dchg report=%v", gooseOff, reportOff)
			}
		}
	})
	t.Run("ConcludeAndAbort", func(t *testing.T) {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		other, err := client.Dial(openContext(t), addr)
		if err != nil {
			t.Fatal(err)
		}
		if err := other.MMS().Abort(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestOpenServerSampledValues(t *testing.T) {
	c, _, _ := openServer(t, "IED3_SMV")
	ctx := openContext(t)
	cb, err := c.GetSVCB(ctx, "IED3_SMVMUnn/LLN0.MSVCB01")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SVCB=%+v", cb)
	if cb.SvID != "xxxxMUnn01" || cb.SmpRate != 80 || cb.DstAddress.AppID != 16384 {
		t.Fatalf("SVCB=%+v", cb)
	}
	eth, err := ethernet.Open("lo", ethernet.EtherTypeSV)
	if err != nil {
		t.Fatal(err)
	}
	defer eth.Close()
	samples := make(chan *sv.ASDU, 32)
	stop, err := sv.NewSubscriber(eth).Subscribe(sv.Filter{AppID: 16384}, func(a *sv.ASDU) {
		select {
		case samples <- a:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	var first *sv.ASDU
	select {
	case first = <-samples:
	case <-ctx.Done():
		t.Fatal("no SV sample")
	}
	t.Run("PayloadAndCounter", func(t *testing.T) {
		if _, err := sv.DecodeLESample(first.Sample); err != nil || len(first.Sample) != 64 {
			t.Fatalf("9-2LE payload: %v bytes=%d", err, len(first.Sample))
		}
		previous := first.SmpCnt
		for n := 0; n < 3; n++ {
			select {
			case a := <-samples:
				if a.SmpCnt != (previous+1)%4000 {
					t.Fatalf("counter %d after %d", a.SmpCnt, previous)
				}
				previous = a.SmpCnt
			case <-ctx.Done():
				t.Fatal("SV counter timed out")
			}
		}
	})
	t.Run("AdvertisedStreamID", func(t *testing.T) {
		if first.SvID != cb.SvID {
			t.Fatalf("wire svID=%q differs from SVCB=%q", first.SvID, cb.SvID)
		}
	})
	t.Run("InitialEnableState", func(t *testing.T) {
		if !cb.SvEna {
			t.Fatal("SV frames received while MMS reports SvEna=false")
		}
	})
	t.Run("EnableAndDisable", func(t *testing.T) {
		ref := model.ObjectReference("IED3_SMVMUnn/LLN0.MSVCB01")
		if cb.Unicast {
			if err := c.ReserveUSVCB(ctx, ref, true); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.EnableSVCB(ctx, ref, cb.Unicast, true); err != nil {
			t.Fatal(err)
		}
		enabled, err := c.GetSVCB(ctx, ref)
		if err != nil || !enabled.SvEna {
			t.Fatalf("enabled=%+v err=%v", enabled, err)
		}
		if err := c.EnableSVCB(ctx, ref, cb.Unicast, false); err != nil {
			t.Fatal(err)
		}
		disabled, err := c.GetSVCB(ctx, ref)
		if err != nil || disabled.SvEna {
			t.Fatalf("disabled=%+v err=%v", disabled, err)
		}
		time.Sleep(250 * time.Millisecond)
		for len(samples) > 0 {
			<-samples
		}
		select {
		case a := <-samples:
			t.Fatalf("sample after disable: %d", a.SmpCnt)
		case <-time.After(250 * time.Millisecond):
		}
	})

}

func TestOpenServerProtectionSettings(t *testing.T) {
	c, _, _ := openServer(t, "FEED1")
	ctx := openContext(t)
	ref := model.ObjectReference("FEED1LD1/PTOC1.StrVal.setMag.f")
	old, err := c.Read(ctx, ref, model.SP)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Write(ctx, ref, model.SP, mms.NewFloat32(750)); err != nil {
		t.Fatal(err)
	}
	defer c.Write(ctx, ref, model.SP, old)
	got, err := c.Read(ctx, ref, model.SP)
	if err != nil || got.Float32() != 750 {
		t.Fatalf("readback=%v err=%v", got, err)
	}
	if err := c.Write(ctx, ref, model.SP, mms.NewFloat32(2000)); err == nil {
		t.Fatal("out-of-range pickup setting accepted")
	}
	got, err = c.Read(ctx, ref, model.SP)
	if err != nil || got.Float32() != 750 {
		t.Fatalf("invalid write changed setting: %v %v", got, err)
	}
}

func TestOpenServerSCL(t *testing.T) {
	root := os.Getenv("IEC61850_OPEN_SERVER_ROOT")
	if root == "" {
		t.Skip("set IEC61850_OPEN_SERVER_ROOT")
	}
	for _, tc := range []struct {
		file string
		ieds []string
	}{{"open_substation.scd", []string{"IED1_XCBR", "IED2_PTOC", "IED3_SMV", "IED4_SMV"}}, {"model_substation.scd", []string{"FEED1", "FEED2", "BUS1", "BUS2", "TR1", "TR2"}}, {"protection_relay.scd", []string{"IED1_XCBR"}}} {
		for _, ied := range tc.ieds {
			t.Run(tc.file+"/"+ied, func(t *testing.T) {
				tree, err := scl.LoadModel(filepath.Join(root, "scd", tc.file), scl.ForIED(ied))
				if err != nil {
					t.Fatal(err)
				}
				if tree.Name != ied || len(tree.Devices) == 0 {
					t.Fatalf("model=%s", tree)
				}
			})
		}
	}
}
