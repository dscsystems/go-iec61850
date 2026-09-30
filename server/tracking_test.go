package server_test

import (
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// simpleIOWithLTRK is the simpleIO model with an LTRK holding the tracking
// objects of its controls, report blocks and setting group block.
func simpleIOWithLTRK(t *testing.T) *model.Model {
	m := simpleIO(t)
	ld := m.Device("simpleIOGenericIO")
	ld.Nodes = append(ld.Nodes, model.NewLogicalNode("", "LTRK", "1",
		model.WithObjects("SpcTrk", "UrcbTrk", "BrcbTrk", "SgcbTrk")))
	return m
}

// trk reads the tracking object attributes a test checks.
func trk(t *testing.T, c *client.Client, obj string) map[string]*mms.Value {
	t.Helper()
	out := map[string]*mms.Value{}
	for _, a := range []string{"objRef", "serviceType", "errorCode"} {
		out[a] = mustRead(t, c, testCtx(t), model.ObjectReference("simpleIOGenericIO/LTRK1."+obj+"."+a), model.SR)
	}
	return out
}

func checkTrk(t *testing.T, got map[string]*mms.Value, objRef string, svc model.ServiceType, serr model.ServiceError) {
	t.Helper()
	if got["objRef"].Text() != objRef || model.ServiceType(got["serviceType"].Int64()) != svc ||
		model.ServiceError(got["errorCode"].Int64()) != serr {
		t.Errorf("tracked %q service %d error %d, want %q %d %d", got["objRef"].Text(),
			got["serviceType"].Int64(), got["errorCode"].Int64(), objRef, svc, serr)
	}
}

// Every control service lands in the tracking object of its CDC, with the
// command and its outcome.
func TestControlTracking(t *testing.T) {
	addr, srv := startServerWith(t, simpleIOWithLTRK(t))
	srv.OnControl("simpleIOGenericIO/GGIO1.SPCSO2", func(*server.ControlCtx) model.AddCause {
		return model.AddCauseBlockedByInterlocking
	})
	c := dialDemo(t, addr)
	ctx := testCtx(t)

	co, err := c.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO1")
	if err != nil {
		t.Fatal(err)
	}
	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatal(err)
	}
	checkTrk(t, trk(t, c, "SpcTrk"), "simpleIOGenericIO/GGIO1.SPCSO1", model.ServiceOperate, model.ServiceErrorNone)
	if v := mustRead(t, c, ctx, "simpleIOGenericIO/LTRK1.SpcTrk.ctlVal", model.SR); !v.Bool() {
		t.Error("SpcTrk.ctlVal is not the operated true")
	}
	if v := mustRead(t, c, ctx, "simpleIOGenericIO/LTRK1.SpcTrk.ctlNum", model.SR); uint8(v.Uint64()) != co.CtlNum() {
		t.Errorf("SpcTrk.ctlNum = %d, want %d", v.Uint64(), co.CtlNum())
	}
	if v := mustRead(t, c, ctx, "simpleIOGenericIO/LTRK1.SpcTrk.t", model.SR); v.Time().IsZero() {
		t.Error("SpcTrk.t not set")
	}

	co2, err := c.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO2")
	if err != nil {
		t.Fatal(err)
	}
	if err := co2.Operate(ctx, mms.NewBool(true)); err == nil {
		t.Fatal("the interlocked operate succeeded")
	}
	checkTrk(t, trk(t, c, "SpcTrk"), "simpleIOGenericIO/GGIO1.SPCSO2", model.ServiceOperate, model.ServiceErrorAccessViolation)
	if v := mustRead(t, c, ctx, "simpleIOGenericIO/LTRK1.SpcTrk.respAddCause", model.SR); model.AddCause(v.Int64()) != model.AddCauseBlockedByInterlocking {
		t.Errorf("SpcTrk.respAddCause = %d, want blocked-by-interlocking", v.Int64())
	}
}

// A write to a report control block is tracked as SetURCBValues or
// SetBRCBValues, succeeded or refused, with the block's state after it.
func TestRCBTracking(t *testing.T) {
	addr, _ := startServerWith(t, simpleIOWithLTRK(t))
	c := dialDemo(t, addr)
	ctx := testCtx(t)

	if err := c.Write(ctx, "simpleIOGenericIO/LLN0.EventsRCB01.RptEna", model.RP, mms.NewBool(true)); err != nil {
		t.Fatal(err)
	}
	checkTrk(t, trk(t, c, "UrcbTrk"), "simpleIOGenericIO/LLN0.EventsRCB01", model.ServiceSetURCBValues, model.ServiceErrorNone)
	for attr, want := range map[string]string{"rptID": "Events1", "datSet": "simpleIOGenericIO/LLN0.Events"} {
		if v := mustRead(t, c, ctx, model.ObjectReference("simpleIOGenericIO/LTRK1.UrcbTrk."+attr), model.SR); v.Text() != want {
			t.Errorf("UrcbTrk.%s = %q, want %q", attr, v.Text(), want)
		}
	}
	for _, attr := range []string{"rptEna", "resv"} {
		if v := mustRead(t, c, ctx, model.ObjectReference("simpleIOGenericIO/LTRK1.UrcbTrk."+attr), model.SR); !v.Bool() {
			t.Errorf("UrcbTrk.%s = false after enabling", attr)
		}
	}

	if err := c.Write(ctx, "simpleIOGenericIO/LLN0.EventsBRCB01.ConfRev", model.BR, mms.NewUint32(9)); err == nil {
		t.Fatal("ConfRev was written")
	}
	got := trk(t, c, "BrcbTrk")
	if got["objRef"].Text() != "simpleIOGenericIO/LLN0.EventsBRCB01" ||
		model.ServiceType(got["serviceType"].Int64()) != model.ServiceSetBRCBValues || got["errorCode"].Int64() == 0 {
		t.Errorf("BrcbTrk after a refused write: %v", got)
	}
	// The tracking object states what was asked for; the block keeps its
	// own value.
	if v := mustRead(t, c, ctx, "simpleIOGenericIO/LTRK1.BrcbTrk.confRev", model.SR); v.Uint64() != 9 {
		t.Errorf("BrcbTrk.confRev = %d, want the requested 9", v.Uint64())
	}
	if v := mustRead(t, c, ctx, "simpleIOGenericIO/LLN0.EventsBRCB01.ConfRev", model.BR); v.Uint64() != 1 {
		t.Errorf("the BRCB's ConfRev = %d, want the unchanged 1", v.Uint64())
	}
}

// The setting group block's selection is tracked, and so is a refused
// write to a GoCB, which this server serves read-only.
func TestSGCBAndGoCBTracking(t *testing.T) {
	m, err := scl.LoadModel("../testdata/ed21_diverse.cid")
	if err != nil {
		t.Fatal(err)
	}
	ltrk := m.Device("ED21LD0").Node("LTRK1")
	ltrk.Objects = append(ltrk.Objects, model.NewDataObject("SgcbTrk", model.CDCSTS))
	addr, _ := startServerWith(t, m)
	c := dialDemo(t, addr)
	ctx := testCtx(t)
	read := func(obj, attr string) *mms.Value {
		return mustRead(t, c, ctx, model.ObjectReference("ED21LD0/LTRK1."+obj+"."+attr), model.SR)
	}
	check := func(obj, objRef string, svc model.ServiceType, serr model.ServiceError) {
		t.Helper()
		if got := read(obj, "objRef").Text(); got != objRef {
			t.Errorf("%s.objRef = %q, want %q", obj, got, objRef)
		}
		if got := model.ServiceType(read(obj, "serviceType").Int64()); got != svc {
			t.Errorf("%s.serviceType = %d, want %d", obj, got, svc)
		}
		if got := model.ServiceError(read(obj, "errorCode").Int64()); got != serr {
			t.Errorf("%s.errorCode = %d, want %d", obj, got, serr)
		}
	}

	if err := c.Write(ctx, "ED21LD0/LLN0.SGCB.ActSG", model.SP, mms.NewUint8(2)); err != nil {
		t.Fatal(err)
	}
	check("SgcbTrk", "ED21LD0/LLN0.SGCB", model.ServiceSelectActiveSG, model.ServiceErrorNone)
	if v := read("SgcbTrk", "actSG"); v.Uint64() != 2 {
		t.Errorf("SgcbTrk.actSG = %d, want 2", v.Uint64())
	}
	if v := read("SgcbTrk", "numOfSG"); v.Uint64() != 2 {
		t.Errorf("SgcbTrk.numOfSG = %d, want 2", v.Uint64())
	}
	if err := c.Write(ctx, "ED21LD0/LLN0.SGCB.ActSG", model.SP, mms.NewUint8(7)); err == nil {
		t.Fatal("ActSG 7 of 2 accepted")
	}
	check("SgcbTrk", "ED21LD0/LLN0.SGCB", model.ServiceSelectActiveSG, model.ServiceErrorParameterValueInappropriate)

	if err := c.Write(ctx, "ED21LD0/LLN0.gcb01.GoEna", model.GO, mms.NewBool(true)); err == nil {
		t.Fatal("GoEna written on a read-only GoCB")
	}
	check("GocbTrk", "ED21LD0/LLN0.gcb01", model.ServiceSetGoCBValues, model.ServiceErrorAccessViolation)
	if v := read("GocbTrk", "goID"); v.Text() == "" {
		t.Error("GocbTrk.goID not copied from the block")
	}
	if v := read("GocbTrk", "datSet"); v.Text() != "" && strings.Contains(v.Text(), "$") {
		t.Errorf("GocbTrk.datSet = %q, want ACSI notation", v.Text())
	}
}

// A select by reading SBO is tracked as Select, a select another client
// holds as one refused with instance-in-use, and an enhanced-security
// operate's CommandTermination, sent at once or deferred, after it.
func TestSelectAndTerminationTracking(t *testing.T) {
	m := simpleIOWithLTRK(t)
	setCtlModel := func(do string, cm model.CtlModel) {
		da := m.Attribute(model.ObjectReference("simpleIOGenericIO/GGIO1."+do+".ctlModel"), model.CF)
		da.Value = mms.NewInt8(int8(cm))
	}
	setCtlModel("SPCSO3", model.CtlSBONormal)
	setCtlModel("SPCSO4", model.CtlDirectEnhanced)
	addr, srv := startServerWith(t, m)
	finish := make(chan func(model.AddCause), 1)
	deferIt := false
	srv.OnControl("simpleIOGenericIO/GGIO1.SPCSO4", func(cc *server.ControlCtx) model.AddCause {
		if deferIt {
			finish <- cc.DeferTermination()
		}
		return model.AddCauseNone
	})
	a, b := dialDemo(t, addr), dialDemo(t, addr)
	ctx := testCtx(t)

	coA, err := a.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO3")
	if err != nil {
		t.Fatal(err)
	}
	if err := coA.Select(ctx); err != nil {
		t.Fatalf("Select: %v", err)
	}
	checkTrk(t, trk(t, a, "SpcTrk"), "simpleIOGenericIO/GGIO1.SPCSO3", model.ServiceSelect, model.ServiceErrorNone)
	coB, err := b.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO3")
	if err != nil {
		t.Fatal(err)
	}
	if err := coB.Select(ctx); err == nil {
		t.Fatal("a second client selected a selected object")
	}
	checkTrk(t, trk(t, a, "SpcTrk"), "simpleIOGenericIO/GGIO1.SPCSO3", model.ServiceSelect, model.ServiceErrorInstanceInUse)

	co4, err := a.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO4")
	if err != nil {
		t.Fatal(err)
	}
	if err := co4.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("enhanced Operate: %v", err)
	}
	checkTrk(t, trk(t, a, "SpcTrk"), "simpleIOGenericIO/GGIO1.SPCSO4", model.ServiceCommandTermination, model.ServiceErrorNone)

	// Deferred and negative: tracked when the handler finishes it.
	deferIt = true
	done := make(chan error, 1)
	go func() { done <- co4.Operate(ctx, mms.NewBool(false)) }()
	fin := <-finish
	fin(model.AddCauseBlockedByProcess)
	<-done // CommandTermination- is an error to the client
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := trk(t, a, "SpcTrk")
		if model.ServiceType(got["serviceType"].Int64()) == model.ServiceCommandTermination &&
			model.ServiceError(got["errorCode"].Int64()) == model.ServiceErrorFailedDueToServerConstraint {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("SpcTrk after a negative deferred termination: %v", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if v := mustRead(t, a, ctx, "simpleIOGenericIO/LTRK1.SpcTrk.respAddCause", model.SR); model.AddCause(v.Int64()) != model.AddCauseBlockedByProcess {
		t.Errorf("respAddCause = %d, want blocked-by-process", v.Int64())
	}
}
