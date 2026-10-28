package mmsinterop_test

// Direction 1: this library's client against each stack's IED server
// (<stack>-ied-server), which serves testdata/interop.icd with the values
// of testdata/values.json.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// dialPeer starts the stack's IED server and associates with it. It
// returns the client and the server's name for the logical device.
func dialPeer(t *testing.T, s stack) (*client.Client, string) {
	t.Helper()
	addr := startPeerServer(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(10*time.Second))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	lds, err := c.LogicalDevices(ctx)
	if err != nil {
		t.Fatalf("LogicalDevices: %v", err)
	}
	for _, ld := range lds {
		if strings.HasSuffix(ld, ldInst) {
			return c, ld
		}
	}
	t.Fatalf("no logical device ending in %s in %v", ldInst, lds)
	return nil, ""
}

// peerRef turns a values.json reference ("InteropLD/...") into one on the
// peer's logical device.
func peerRef(ld, ref string) model.ObjectReference {
	return model.ObjectReference(ld + strings.TrimPrefix(ref, ldInst))
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// The directory services: the server, logical device and logical node
// directories hold what the SCL declares.
func TestClient_Directory(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		ctx := ctxT(t)
		if want := iedName + ldInst; ld != want {
			t.Errorf("logical device %q, want %q", ld, want)
		}
		lns, err := c.LogicalNodes(ctx, ld)
		if err != nil {
			t.Fatal(err)
		}
		for _, ln := range []string{"LLN0", "GGIO1", "MMXU1", "MMTR1"} {
			if !slices.Contains(lns, ln) {
				t.Errorf("logical node %s missing from %v", ln, lns)
			}
		}
		dos, err := c.LogicalNodeDirectory(ctx, model.ObjectReference(ld+"/GGIO1"), client.ACSIDataObject)
		if err != nil {
			t.Fatal(err)
		}
		for _, do := range []string{"SPS1", "DPS1", "SPCSO1", "SPCSO2", "SPCSO3", "SetInt1"} {
			if !slices.Contains(dos, do) {
				t.Errorf("data object %s missing from GGIO1 %v", do, dos)
			}
		}
	})
}

// GetServerDirectory down to the attributes: the model retrieved from the
// server has every attribute the fixture sets, under the FC the SCL gives
// it.
func TestClient_RetrieveModel(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		got, err := c.RetrieveModel(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := loadModel(t, false)
		for _, k := range loadValues(t).sortedKeys() {
			da := want.Attribute(model.ObjectReference(iedName+k), model.ALL)
			if got.Attribute(peerRef(ld, k), da.FC) == nil {
				t.Errorf("%s[%s] not in the retrieved model", peerRef(ld, k), da.FC)
			}
		}
	})
}

// Every value of values.json reads back typed as the SCL declares it.
func TestClient_ReadFixtureValues(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		m := loadModel(t, false)
		v := loadValues(t)
		for _, k := range v.sortedKeys() {
			t.Run(k, func(t *testing.T) {
				skipGap(t, s.name, "values:"+k)
				da := m.Attribute(model.ObjectReference(iedName+k), model.ALL)
				want, err := typedValue(da, v.Values[k])
				if err != nil {
					t.Fatal(err)
				}
				got, err := c.Read(ctxT(t), peerRef(ld, k), da.FC)
				if err != nil {
					t.Fatalf("read %s[%s]: %v", k, da.FC, err)
				}
				if !sameValue(got, want) {
					t.Errorf("%s[%s] = %v (%s), want %v (%s)", k, da.FC, got, got.Type(), want, want.Type())
				}
			})
		}
	})
}

// sameValue compares two scalars by type and value. Integer widths are
// not compared: a server may describe an Enum as INT8 or as INT32.
func sameValue(a, b *mms.Value) bool {
	if a == nil || b == nil || a.Type() != b.Type() {
		return false
	}
	switch a.Type() {
	case mms.TypeBoolean:
		return a.Bool() == b.Bool()
	case mms.TypeInteger:
		return a.Int64() == b.Int64()
	case mms.TypeUnsigned:
		return a.Uint64() == b.Uint64()
	case mms.TypeFloat32:
		return a.Float32() == b.Float32()
	case mms.TypeFloat64:
		return a.Float64() == b.Float64()
	case mms.TypeVisibleString, mms.TypeMMSString:
		return a.Text() == b.Text()
	case mms.TypeBitString:
		return model.DbposFromValue(a) == model.DbposFromValue(b)
	}
	return a.String() == b.String()
}

// The writable setting of the fixture (ING setVal, FC SP) takes a write
// and reads it back.
func TestClient_WriteSetting(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		ctx := ctxT(t)
		ref := peerRef(ld, "InteropLD/GGIO1.SetInt1.setVal")
		if err := c.Write(ctx, ref, model.SP, mms.NewInt32(42)); err != nil {
			t.Fatalf("write %s[SP]: %v", ref, err)
		}
		v, err := c.Read(ctx, ref, model.SP)
		if err != nil {
			t.Fatal(err)
		}
		if v.Type() != mms.TypeInteger || v.Int64() != 42 {
			t.Errorf("%s[SP] = %v after writing 42", ref, v)
		}
	})
}

// A write of status (FC ST) is refused: IEC 61850-7-2 makes it read-only,
// and the refusal is an MMS DataAccessError, not a broken association.
func TestClient_WriteStatusRefused(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		ctx := ctxT(t)
		ref := peerRef(ld, "InteropLD/GGIO1.SPS1.stVal")
		err := c.Write(ctx, ref, model.ST, mms.NewBool(true))
		if err == nil {
			// libiec61850 allows ST writes when its server is told to.
			t.Logf("%s accepted a write of %s[ST]", s.name, ref)
			return
		}
		var dae mms.DataAccessError
		if !errors.As(err, &dae) {
			t.Errorf("write %s[ST]: %v, want a DataAccessError", ref, err)
		}
		if _, err := c.Read(ctx, ref, model.ST); err != nil {
			t.Errorf("read after the refused write: %v", err)
		}
	})
}

// The fixture dataset reads as one named variable list, in member order:
// with GetDataSetValues as this client sends it, and with the variable
// list's specification asked for in the result.
func TestClient_ReadDataSet(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		t.Run("GetDataSetValues", func(t *testing.T) {
			skipGap(t, s.name, "read-dataset:no-spec")
			ds, err := c.ReadDataSet(ctxT(t), model.ObjectReference(ld+"/LLN0.dsInterop"))
			if err != nil {
				t.Fatal(err)
			}
			vals := make([]*mms.Value, len(ds.Members))
			for i, m := range ds.Members {
				vals[i] = m.Value
			}
			checkDsInterop(t, vals)
		})
		t.Run("specificationWithResult", func(t *testing.T) {
			_, vals, err := c.MMS().ReadNamedVariableListWithSpec(ctxT(t), ld, "LLN0$dsInterop")
			if err != nil {
				t.Fatal(err)
			}
			checkDsInterop(t, vals)
		})
	})
}

// checkDsInterop checks the initial values of dsInterop: SPS1.stVal false
// and Mod.stVal 1.
func checkDsInterop(t *testing.T, vals []*mms.Value) {
	t.Helper()
	if len(vals) != 2 {
		t.Fatalf("dsInterop has %d members, want 2: %v", len(vals), vals)
	}
	if v := vals[0]; v == nil || v.Type() != mms.TypeBoolean || v.Bool() {
		t.Errorf("member 0 (SPS1.stVal) = %v, want false", v)
	}
	if v := vals[1]; v == nil || v.Type() != mms.TypeInteger || v.Int64() != 1 {
		t.Errorf("member 1 (Mod.stVal) = %v, want 1", v)
	}
}

// urcbRef returns the reference of the fixture URCB urcb01 on the peer.
// IEC 61850-6 indexes report instances by default (ReportControl@indexed),
// so libiec61850 and iec61850-rust serve the one instance as urcb0101;
// iec61850bean serves it as urcb01.
func urcbRef(t *testing.T, c *client.Client, ld string) model.ObjectReference {
	t.Helper()
	names, err := c.MMS().GetNameList(ctxT(t), mms.ClassNamedVariable, ld)
	if err != nil {
		t.Fatal(err)
	}
	for _, inst := range []string{"urcb01", "urcb0101"} {
		if slices.Contains(names, "LLN0$RP$"+inst) {
			return model.ObjectReference(ld + "/LLN0.RP." + inst)
		}
	}
	t.Fatalf("no urcb01 or urcb0101 under %s/LLN0$RP", ld)
	return ""
}

// The fixture URCB: its configuration as the SCL gives it, and a general
// interrogation that reports both dataset members with reason GI.
func TestClient_URCB_GI(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		ctx := ctxT(t)
		rcb, err := c.GetRCB(ctx, urcbRef(t, c, ld))
		if err != nil {
			t.Fatal(err)
		}
		if rcb.RptID != "interop_urcb01" {
			t.Errorf("RptID = %q, want interop_urcb01", rcb.RptID)
		}
		if want := ld + "/LLN0$dsInterop"; rcb.DataSet != want && !noteGap(t, s.name, "urcb:datset") {
			t.Errorf("DatSet = %q, want %q", rcb.DataSet, want)
		}
		if rcb.ConfRev != 1 {
			t.Errorf("ConfRev = %d, want 1", rcb.ConfRev)
		}
		reports := make(chan *client.Report, 8)
		rcb.TrgOps = model.TrgDataChange | model.TrgGI
		rcb.OptFlds = model.OptSeqNum | model.OptTimeOfEntry | model.OptReasonCode | model.OptDataSetName
		sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) {
			select {
			case reports <- r:
			default:
			}
		})
		if err != nil {
			t.Fatalf("EnableReporting: %v", err)
		}
		defer sub.Disable(ctx)
		if err := c.TriggerGI(ctx, rcb); err != nil {
			t.Fatalf("TriggerGI: %v", err)
		}
		select {
		case r := <-reports:
			if r.RptID != "interop_urcb01" {
				t.Errorf("report RptID = %q", r.RptID)
			}
			if len(r.Entries) != 2 {
				t.Fatalf("GI report has %d entries, want 2: %+v", len(r.Entries), r.Entries)
			}
			for _, e := range r.Entries {
				if e.Reason&model.ReasonGI == 0 {
					t.Errorf("entry %d reason %v, want gi", e.Index, e.Reason)
				}
			}
			if v := r.Entries[0].Value; v == nil || v.Type() != mms.TypeBoolean {
				t.Errorf("entry 0 = %v, want SPS1.stVal boolean", v)
			}
			if v := r.Entries[1].Value; v == nil || v.Type() != mms.TypeInteger || v.Int64() != 1 {
				t.Errorf("entry 1 = %v, want Mod.stVal 1", v)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("no GI report within 10 s")
		}
	})
}

// The three control models of the fixture, each run as this client runs
// it for the ctlModel it reads, and stVal following the command.
func TestClient_Control(t *testing.T) {
	cases := []struct {
		do    string
		model model.CtlModel
	}{
		{"SPCSO1", model.CtlDirectNormal},
		{"SPCSO2", model.CtlSBONormal},
		{"SPCSO3", model.CtlSBOEnhanced},
	}
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		c, ld := dialPeer(t, s)
		for _, tc := range cases {
			t.Run(tc.do, func(t *testing.T) {
				ctx := ctxT(t)
				ref := model.ObjectReference(ld + "/GGIO1." + tc.do)
				co, err := c.ControlFor(ctx, ref)
				if err != nil {
					t.Fatal(err)
				}
				if co.Model() != tc.model {
					t.Fatalf("ctlModel %v, want %v", co.Model(), tc.model)
				}
				for _, val := range []bool{true, false} {
					if err := co.Operate(ctx, mms.NewBool(val)); err != nil {
						if tc.model == model.CtlSBOEnhanced {
							if why, known := caps.limitation(s.name, "SBOw"); known {
								t.Skipf("known limitation: %s", why)
							}
						}
						t.Fatalf("operate %v: %v", val, err)
					}
					st, err := c.Read(ctx, ref+".stVal", model.ST)
					if err != nil {
						t.Fatal(err)
					}
					if st.Type() != mms.TypeBoolean || st.Bool() != val {
						t.Errorf("stVal = %v after operate %v", st, val)
					}
				}
			})
		}
	})
}

// The generic sampled-value control block MSVCB02, where the stack's
// server exposes SVCBs over MMS (capabilities.json svcbOverMms).
func TestClient_MSVCB(t *testing.T) {
	forEachPeer(t, "ied-server", func(t *testing.T, s stack) {
		if !caps.svcbOverMMS(s.name) {
			t.Skipf("%s does not expose SVCBs over MMS (capabilities.json)", s.name)
		}
		c, ld := dialPeer(t, s)
		cb, err := c.GetSVCB(ctxT(t), model.ObjectReference(ld+"/LLN0.MSVCB02"))
		if err != nil {
			t.Fatal(err)
		}
		if cb.SvID != "InteropSvGeneric" {
			t.Errorf("MsvID = %q, want InteropSvGeneric", cb.SvID)
		}
		if want := ld + "/LLN0$dsSvGeneric"; cb.DataSet != want {
			t.Errorf("DatSet = %q, want %q", cb.DataSet, want)
		}
		if cb.ConfRev != 1 || cb.SmpRate != 1000 || cb.NoASDU != 4 {
			t.Errorf("ConfRev %d SmpRate %d noASDU %d, want 1 1000 4", cb.ConfRev, cb.SmpRate, cb.NoASDU)
		}
		if cb.SmpMod != model.SmpPerSec {
			t.Errorf("SmpMod = %v, want samples per second", cb.SmpMod)
		}
		if cb.SvEna {
			t.Error("SvEna is set on a block nobody enabled")
		}
	})
}
