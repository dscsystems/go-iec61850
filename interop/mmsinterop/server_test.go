package mmsinterop_test

// Direction 2: each stack's client adapters (<stack>-ied-client,
// -ied-controller, -ied-reporter) against this library's server, loaded
// with testdata/interop.icd and testdata/values.json.

import (
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// The fixed browse/read/write/dataset sequence of the IED client adapter.
// Every step succeeds except the write of Mod.stVal[ST]: IEC 61850-7-2
// makes status read-only and this server refuses it, so the adapter exits
// 3 for that one step and the value stays.
func TestServer_IEDClient(t *testing.T) {
	forEachPeer(t, "ied-client", func(t *testing.T, s stack) {
		g := startGoServer(t, server.WithWritableFCs(model.CF, model.DC, model.SP))
		code, lines := runPeerClient(t, s, "ied-client", g.addr)
		skipUnsupported(t, lines)

		for _, l := range lines {
			if l.op() != "" && !l.ok() && !(l.op() == "write" && strings.HasSuffix(l.str("target"), ".Mod.stVal[ST]")) {
				t.Errorf("%s %s failed: %s", l.op(), l.str("target"), l.str("error"))
			}
		}
		if code != 3 {
			t.Errorf("exit code %d, want 3 (all steps ok but the refused ST write)", code)
		}
		mustFind(t, lines, "associate", "")
		dir := mustFind(t, lines, "get-server-directory", "")
		if names, _ := dir["names"].([]any); len(names) != 1 || names[0] != ldInst {
			t.Errorf("server directory %v, want [%s]", dir["names"], ldInst)
		}
		ldDir := mustFind(t, lines, "get-ld-directory", ldInst)
		for _, ln := range []string{"LLN0", "GGIO1", "MMXU1", "MMTR1"} {
			if !containsAny(ldDir["names"], ln) {
				t.Errorf("logical device directory %v has no %s", ldDir["names"], ln)
			}
		}
		lnDir := mustFind(t, lines, "get-ln-directory", ldInst+"/GGIO1")
		for _, do := range []string{"SPS1", "DPS1", "SPCSO1", "SPCSO2", "SPCSO3", "SetInt1"} {
			if !containsAny(lnDir["names"], do) {
				t.Errorf("GGIO1 directory %v has no %s", lnDir["names"], do)
			}
		}
		for target, want := range map[string]any{
			ldInst + "/GGIO1.SPS1.stVal[ST]":  false,
			ldInst + "/MMXU1.TotW.mag.f[MX]":  1234.5,
			ldInst + "/LLN0.Mod.ctlModel[CF]": 1.0,
			ldInst + "/LLN0.Mod.d[DC]":        "mode",
		} {
			if got := mustFind(t, lines, "read", target)["value"]; got != want {
				t.Errorf("read %s = %v, want %v", target, got, want)
			}
		}
		w := mustFind(t, lines, "write", ldInst+"/LLN0.Mod.stVal[ST]")
		if w.ok() {
			t.Error("the write of Mod.stVal[ST] was accepted")
		} else if e := w.str("error"); !strings.Contains(e, "denied") && !strings.Contains(e, "access") {
			t.Errorf("the write of Mod.stVal[ST] failed with %q, want an access error", e)
		}
		if v := g.srv.Read(ldInst+"/LLN0.Mod.stVal", model.ST); v == nil || v.Int64() != 1 {
			t.Errorf("Mod.stVal = %v after the refused write, want 1", v)
		}
		ds := mustFind(t, lines, "read-dataset", ldInst+"/LLN0$dsInterop")
		if vals, _ := ds["values"].([]any); len(vals) != 2 || vals[0] != false || vals[1] != 1.0 {
			t.Errorf("dataset values %v, want [false 1]", ds["values"])
		}
		mustFind(t, lines, "conclude", "")
	})
}

func containsAny(list any, want string) bool {
	items, _ := list.([]any)
	for _, it := range items {
		if it == want {
			return true
		}
	}
	return false
}

// The control adapter against the three control models of the fixture:
// it reads ctlModel, runs the sequence for it with ctlVal true, and reads
// stVal back. The server saw the select (SBOw only) and the operate.
func TestServer_IEDController(t *testing.T) {
	cases := []struct {
		do       string
		ctlModel float64
		steps    []string // the operations between read-ctlmodel and read-stval
		selects  int      // selects the server's handler sees (SBOw)
	}{
		{"SPCSO1", 1, []string{"operate"}, 0},
		{"SPCSO2", 2, []string{"select", "operate"}, 0},
		{"SPCSO3", 4, []string{"select-with-value", "operate"}, 1},
	}
	forEachPeer(t, "ied-controller", func(t *testing.T, s stack) {
		for _, tc := range cases {
			t.Run(tc.do, func(t *testing.T) {
				g := startGoServer(t)
				code, lines := runPeerClient(t, s, "ied-controller", g.addr, "--do", tc.do, "--ctlval", "1")
				skipUnsupported(t, lines)
				if code != 0 {
					t.Errorf("exit code %d", code)
				}
				ref := ldInst + "/GGIO1." + tc.do
				for _, l := range lines {
					if l.op() != "" && !l.ok() {
						t.Errorf("%s %s failed: %s", l.op(), l.str("target"), l.str("error"))
					}
				}
				if got := mustFind(t, lines, "read-ctlmodel", ref+".ctlModel[CF]")["value"]; got != tc.ctlModel {
					t.Errorf("ctlModel %v, want %v", got, tc.ctlModel)
				}
				for _, op := range tc.steps {
					mustFind(t, lines, op, ref)
				}
				if got := mustFind(t, lines, "read-stval", ref+".stVal[ST]")["value"]; got != true {
					t.Errorf("stVal read back %v, want true", got)
				}
				if v := g.srv.Read(model.ObjectReference(ref+".stVal"), model.ST); v == nil || !v.Bool() {
					t.Errorf("server stVal = %v, want true", v)
				}
				var selects, operates int
				for _, cc := range g.controlsOn(tc.do) {
					if cc.Select {
						selects++
					} else {
						operates++
						if cc.Value == nil || !cc.Value.Bool() {
							t.Errorf("operate ctlVal %v, want true", cc.Value)
						}
					}
				}
				if selects != tc.selects || operates != 1 {
					t.Errorf("server saw %d selects and %d operates, want %d and 1", selects, operates, tc.selects)
				}
				mustFind(t, lines, "conclude", "")
			})
		}
	})
}

// The URCB adapter: it enables urcb01 and waits for a data-change report.
// It raises the change by writing SPS1.stVal[ST], which this server
// refuses (status is read-only); the change is made on the server
// instead, as a process change, once the report control block is
// enabled. The report carries SPS1 alone, with reason data-change.
func TestServer_IEDReporter(t *testing.T) {
	forEachPeer(t, "ied-reporter", func(t *testing.T, s stack) {
		g := startGoServer(t)
		host, port, _ := strings.Cut(g.addr, ":")
		a := startAdapter(t, s, "ied-reporter", "--host", host, "--port", port, "--sps1-initial", "0")
		enabled := a.waitFor(time.Minute, "enable-rcb", func(l line) bool {
			return l.op() == "enable-rcb" || l.op() == "get-rcb" && !l.ok() || l.event() == "error"
		})
		if enabled.event() == "error" {
			skipUnsupported(t, []line{enabled})
			t.Fatalf("adapter error: %s", enabled)
		}
		if !enabled.ok() {
			t.Fatalf("%s %s failed: %s", enabled.op(), enabled.str("target"), enabled.str("error"))
		}
		g.srv.Update(func(tx *server.Tx) {
			tx.SetBool(ldInst+"/GGIO1.SPS1.stVal", true)
		})
		code, lines := a.wait(time.Minute)
		if code != 0 {
			t.Errorf("exit code %d", code)
		}
		rcb := mustFind(t, lines, "get-rcb", ldInst+"/LLN0.RP.urcb01")
		if !rcb.ok() || rcb.str("rptID") != "interop_urcb01" {
			t.Errorf("get-rcb: %s", rcb)
		}
		w := mustFind(t, lines, "write", ldInst+"/GGIO1.SPS1.stVal[ST]")
		if w.ok() {
			t.Error("the write of SPS1.stVal[ST] was accepted")
		}
		r := mustFind(t, lines, "receive-report", "")
		if !r.ok() {
			t.Fatalf("receive-report: %s", r.str("error"))
		}
		if r.str("rptID") != "interop_urcb01" {
			t.Errorf("rptID %q", r.str("rptID"))
		}
		if got := r.String(); !strings.Contains(got, `"inclusion":[true,false]`) ||
			!strings.Contains(got, `"values":[true]`) || !strings.Contains(got, `"reasons":["data-change"]`) {
			t.Errorf("report %s, want SPS1 alone, true, data-change", got)
		}
		if d := mustFind(t, lines, "disable-rcb", ldInst+"/LLN0.RP.urcb01"); !d.ok() {
			t.Errorf("disable-rcb: %s", d.str("error"))
		}
		mustFind(t, lines, "conclude", "")
	})
}
