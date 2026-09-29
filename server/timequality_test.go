package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// lostSync is the quality of a clock that has lost its time source.
const lostSync = mms.TimeClockNotSynchronized | mms.TimeClockFailure | mms.TimeAccuracyUnspecified

// The server stamps its times with its clock's quality, which can change
// while it serves, and 0 is a quality like any other.
func TestServerTimeQuality(t *testing.T) {
	m := logModel()
	t0 := &model.DataAttribute{Name: "t", FC: model.ST, Kind: mms.TypeUTCTime, Value: mms.NewUTCTimeNow()}
	m.Devices[0].Nodes[1].Objects[0].Attributes = append(m.Devices[0].Nodes[1].Objects[0].Attributes, t0)
	srv := server.New(m, server.WithTimeQuality(lostSync))
	ref := model.ObjectReference(logLD + "/GGIO1.Ind1.t")

	stamp := func() mms.TimeQuality {
		srv.Update(func(tx *server.Tx) { tx.SetTimestampNow(ref, model.ST) })
		return srv.Read(ref, model.ST).TimeQualityFlags()
	}
	if got := stamp(); got != lostSync {
		t.Errorf("stamped %08b, want the configured %08b", uint8(got), uint8(lostSync))
	}
	srv.SetTimeQuality(0)
	if got := stamp(); got != 0 {
		t.Errorf("stamped %08b after SetTimeQuality(0), want 0", uint8(got))
	}
	srv.Update(func(tx *server.Tx) {
		if got := tx.Now().TimeQualityFlags(); got != 0 {
			t.Errorf("Tx.Now quality = %08b, want 0", uint8(got))
		}
	})
	if server.New(logModel()).TimeQuality() != mms.DefaultTimeQuality {
		t.Error("an unconfigured server does not use the default quality")
	}
}

// The setting group's LActTm carries the server's clock quality.
func TestSGCBActivationTimeQuality(t *testing.T) {
	m := resvLessSGModel()
	srv := server.New(m, server.WithSettingGroups(2), server.WithTimeQuality(lostSync))
	if got := srv.Read(model.ObjectReference(logLD+"/LLN0.SGCB.LActTm"), model.SP); got == nil || got.TimeQualityFlags() != lostSync {
		t.Errorf("LActTm = %v, want the server's quality", got)
	}
}

// resvLessSGModel is logModel with one setting, so the device gets an SGCB.
func resvLessSGModel() *model.Model {
	m := logModel()
	ggio := m.Devices[0].Nodes[1]
	ggio.Objects = append(ggio.Objects, &model.DataObject{Name: "Set", Attributes: []*model.DataAttribute{
		{Name: "setVal", FC: model.SG, Kind: mms.TypeInteger, Value: mms.NewInt32(1)},
	}})
	return m
}

// The operate timestamp T carries the client's clock quality, and one
// command can state its own.
func TestOperateTimeQuality(t *testing.T) {
	f := newRuleFixture(t)
	c := f.dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	co, err := c.ControlFor(ctx, "RULE/GGIO1.SPCSO1")
	if err != nil {
		t.Fatalf("ControlFor: %v", err)
	}

	if err := co.Operate(ctx, mms.NewBool(true)); err != nil {
		t.Fatalf("Operate: %v", err)
	}
	c.SetTimeQuality(lostSync)
	if err := co.Operate(ctx, mms.NewBool(false)); err != nil {
		t.Fatalf("Operate: %v", err)
	}
	if err := co.Operate(ctx, mms.NewBool(true), client.WithTimeQuality(mms.TimeAccuracy(20))); err != nil {
		t.Fatalf("Operate: %v", err)
	}
	if len(f.got) != 3 {
		t.Fatalf("handler saw %d commands, want 3", len(f.got))
	}
	for i, want := range []mms.TimeQuality{mms.DefaultTimeQuality, lostSync, mms.TimeAccuracy(20)} {
		if got := f.got[i].TQuality; got != want {
			t.Errorf("command %d: T quality %08b, want %08b", i, uint8(got), uint8(want))
		}
	}
}

// A client can propose the IEC 61850 ACSI application context, which the
// server accepts and answers in kind.
func TestACSIApplicationContext(t *testing.T) {
	addr, _ := startServerWith(t, logModel())
	c := dialDemo(t, addr, client.WithApplicationContext(mms.ContextACSI))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.LogicalNodeDirectory(ctx, logLD+"/LLN0", client.ACSILog); err != nil {
		t.Errorf("a request over an ACSI-context association failed: %v", err)
	}
}
