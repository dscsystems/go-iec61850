package interop_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

func rustRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("IEC61850_RUST_ROOT")
	if root == "" {
		t.Skip("set IEC61850_RUST_ROOT to a built Rust checkout (see interop/run-rust.sh)")
	}
	return root
}

func TestGoClientRustServer(t *testing.T) {
	root := rustRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "target/debug/examples/server_from_scl"), "127.0.0.1:0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Signal(os.Interrupt); _ = cmd.Wait() }()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "listening on ") {
				ready <- strings.TrimPrefix(line, "listening on ")
			}
		}
		close(ready)
	}()
	var addr string
	select {
	case addr = <-ready:
		if addr == "" {
			t.Fatal("Rust server exited before listening")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	c, err := client.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	t.Run("IdentifyAndDirectory", func(t *testing.T) {
		vendor, name, rev, err := c.MMS().Identify(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("identity: %q %q %q", vendor, name, rev)
		lds, err := c.LogicalDevices(ctx)
		if err != nil || !slices.Contains(lds, "DemoIEDLD0") {
			t.Fatalf("devices=%v err=%v", lds, err)
		}
		lns, err := c.LogicalNodes(ctx, "DemoIEDLD0")
		if err != nil {
			t.Fatal(err)
		}
		for _, ln := range []string{"LLN0", "LPHD1", "MMXU1", "GGIO1"} {
			if !slices.Contains(lns, ln) {
				t.Errorf("missing %s in %v", ln, lns)
			}
		}
		spec, err := c.MMS().GetVariableAccessAttributes(ctx, "DemoIEDLD0", "MMXU1$MX$TotW")
		if err != nil || spec.Kind != mms.TypeStructure {
			t.Fatalf("spec=%v err=%v", spec, err)
		}
		tree, err := c.RetrieveModel(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if tree.Attribute("DemoIEDLD0/MMXU1.PhV.phsA.cVal.mag.f", model.MX) == nil {
			t.Fatal("nested attribute missing")
		}
	})
	t.Run("TypedReadAndWrite", func(t *testing.T) {
		for _, tc := range []struct {
			ref  model.ObjectReference
			fc   model.FC
			kind mms.Type
		}{
			{"DemoIEDLD0/LLN0.NamPlt.vendor", model.DC, mms.TypeVisibleString},
			{"DemoIEDLD0/MMXU1.TotW.mag.f", model.MX, mms.TypeFloat32},
			{"DemoIEDLD0/MMXU1.TotW.q", model.MX, mms.TypeBitString},
			{"DemoIEDLD0/MMXU1.TotW.t", model.MX, mms.TypeUTCTime},
			{"DemoIEDLD0/GGIO1.Ind1.stVal", model.ST, mms.TypeBoolean},
			{"DemoIEDLD0/GGIO1.SPCSO1.ctlModel", model.CF, mms.TypeInteger},
		} {
			v, err := c.Read(ctx, tc.ref, tc.fc)
			if err != nil || v.Type() != tc.kind {
				t.Fatalf("%s: %v %v", tc.ref, v, err)
			}
		}
		ref := model.ObjectReference("DemoIEDLD0/LLN0.NamPlt.vendor")
		if err := c.Write(ctx, ref, model.DC, mms.NewVisibleString("go-peer")); err != nil {
			t.Fatal(err)
		}
		v, err := c.Read(ctx, ref, model.DC)
		if err != nil || v.Text() != "go-peer" {
			t.Fatalf("readback=%v err=%v", v, err)
		}
		if _, err := c.Read(ctx, "DemoIEDLD0/GGIO1.Missing.stVal", model.ST); err == nil {
			t.Fatal("missing object accepted")
		}
	})
	t.Run("DataSets", func(t *testing.T) {
		ds, err := c.ReadDataSet(ctx, "DemoIEDLD0/LLN0.dsMeas")
		if err != nil || len(ds.Members) != 3 {
			t.Fatalf("ds=%v err=%v", ds, err)
		}
		for _, member := range ds.Members {
			if member.FC != model.MX || member.Value == nil || member.Value.Type() != mms.TypeFloat32 {
				t.Fatalf("dataset member: %+v", member)
			}
		}
		ref := model.ObjectReference("DemoIEDLD0/LLN0.goDynamic")
		if err := c.CreateDataSet(ctx, ref, []client.DataSetEntry{{Ref: "DemoIEDLD0/GGIO1.Ind1.stVal", FC: model.ST}}); err != nil {
			t.Fatal(err)
		}
		ds, err = c.ReadDataSet(ctx, ref)
		if err != nil || len(ds.Members) != 1 {
			t.Fatalf("dynamic=%v err=%v", ds, err)
		}
		if err := c.DeleteDataSet(ctx, ref); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ReadDataSet(ctx, ref); err == nil {
			t.Fatal("deleted dataset readable")
		}
	})
	t.Run("DirectNormalControl", func(t *testing.T) {
		co, err := c.ControlFor(ctx, "DemoIEDLD0/GGIO1.SPCSO1")
		if err != nil {
			t.Fatal(err)
		}
		if co.Model() != model.CtlDirectNormal {
			t.Fatalf("control model=%v", co.Model())
		}
		if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
			t.Fatal(err)
		}
	})
	for _, rc := range []struct{ fc, name string }{{"RP", "urcbMeas"}, {"BR", "brcbMeas"}} {
		t.Run(rc.fc+"Reports", func(t *testing.T) {
			rcb, err := c.GetRCB(ctx, model.ObjectReference(fmt.Sprintf("DemoIEDLD0/LLN0.%s.%s", rc.fc, rc.name)))
			if err != nil {
				t.Fatal(err)
			}
			if rcb.ConfRev != 1 || rcb.DataSet == "" {
				t.Fatalf("RCB=%+v", rcb)
			}
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
			if err := c.TriggerGI(ctx, rcb); err != nil {
				t.Fatal(err)
			}
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			for {
				select {
				case r := <-reports:
					if len(r.Entries) != 3 {
						continue
					}
					allGI := true
					for _, e := range r.Entries {
						if e.Value == nil || e.Value.Type() != mms.TypeFloat32 || e.Ref == "" || e.FC != model.MX {
							t.Fatalf("entry=%+v", e)
						}
						allGI = allGI && e.Reason&model.ReasonGI != 0
					}
					if allGI {
						if r.ConfRev != 1 {
							t.Fatalf("confRev=%d", r.ConfRev)
						}
						if rc.fc == "BR" && len(r.EntryID) == 0 {
							t.Fatal("BRCB entryID absent")
						}
						return
					}
				case <-timer.C:
					t.Fatal("no full GI report within 5s")
				}
			}
		})
	}
	t.Run("Conclude", func(t *testing.T) {
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRustClientGoServer(t *testing.T) {
	root := rustRoot(t)
	m, err := scl.LoadModel(filepath.Join(root, "crates/iec61850-server/examples/models/demo.cid"))
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m, server.WithWritableFCs(model.DC, model.CF))
	srv.OnControl("DemoIEDLD0/GGIO1.SPCSO1", func(*server.ControlCtx) model.AddCause { return model.AddCauseNone })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	for _, mode := range []string{"read", "static-dataset", "dynamic-dataset", "control", "report"} {
		t.Run(mode, func(t *testing.T) {
			output, err := exec.CommandContext(ctx, filepath.Join(root, "target/debug/examples/go_interop_peer"), port, mode).CombinedOutput()
			t.Logf("Rust peer:\n%s", output)
			if err != nil {
				t.Fatalf("Rust client: %v", err)
			}
		})
	}
}
