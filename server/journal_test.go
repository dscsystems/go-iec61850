package server_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

const (
	logLD  = "IEDLD0"
	logRef = model.ObjectReference(logLD + "/LLN0.EventLog")
	lcbLG  = "LLN0$LG$lcb"
)

// logModel has one log, EventLog in LLN0, written by lcb from the Events
// dataset of two status points, logging data changes with their reasons.
func logModel() *model.Model {
	ind := func(name string) *model.DataObject {
		return &model.DataObject{Name: name, Attributes: []*model.DataAttribute{
			// dchg on the attribute, as its SCL type would give it: a change
			// raises only the triggers its attribute declares.
			{Name: "stVal", FC: model.ST, Kind: mms.TypeBoolean, Value: mms.NewBool(false),
				TrgOps: model.TrgDataChange},
		}}
	}
	ggio := &model.LogicalNode{Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{ind("Ind1"), ind("Ind2")}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0", Logs: []string{"EventLog"},
		DataSets: []*model.DataSet{{Name: "Events", Entries: []model.FCDA{
			{Ref: logLD + "/GGIO1.Ind1.stVal", FC: model.ST},
			{Ref: logLD + "/GGIO1.Ind2.stVal", FC: model.ST},
		}}},
		LogControls: []*model.LogControl{{
			Name: "lcb", DataSet: "Events", LogName: "EventLog",
			TrgOps: model.TrgDataChange, LogEna: true, ReasonCode: true,
		}},
	}
	ld := &model.LogicalDevice{Name: logLD, Inst: "LD0", Nodes: []*model.LogicalNode{lln0, ggio}}
	return &model.Model{Name: "IED", Devices: []*model.LogicalDevice{ld}}
}

func setInd(srv *server.Server, name string, on bool) {
	srv.Update(func(tx *server.Tx) {
		tx.SetBool(model.ObjectReference(logLD+"/GGIO1."+name+".stVal"), on)
	})
}

func startLogServer(t *testing.T, opts ...server.Option) (*server.Server, *client.Client) {
	t.Helper()
	addr, srv := startServerWith(t, logModel(), opts...)
	return srv, dialDemo(t, addr)
}

func queryAll(t *testing.T, c *client.Client) []client.LogEntry {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entries, err := c.QueryLogByTime(ctx, logRef, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryLogByTime: %v", err)
	}
	return entries
}

// A log is browsable as an ACSI LOG, and the server offers ReadJournal
// because it has one.
func TestLogIsBrowseable(t *testing.T) {
	_, c := startLogServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names, err := c.LogicalNodeDirectory(ctx, logLD+"/LLN0", client.ACSILog)
	if err != nil {
		t.Fatalf("LogicalNodeDirectory: %v", err)
	}
	if len(names) != 1 || names[0] != "EventLog" {
		t.Errorf("logs = %v, want [EventLog]", names)
	}
	entries, err := c.Browse(ctx, logLD, client.ACSILog)
	if err != nil {
		t.Fatalf("Browse: %v", err)
	}
	if len(entries) != 1 || entries[0].Ref != logRef {
		t.Errorf("Browse = %v, want %s", entries, logRef)
	}
	if !c.MMS().Negotiated().Services.Has(mms.ServiceReadJournal) {
		t.Error("a server with logs does not offer readJournal")
	}
}

// A change of a dataset member is logged with its reference, value and
// reason, and the control block's entry range follows the log.
func TestDataChangeIsLogged(t *testing.T) {
	srv, c := startLogServer(t)
	setInd(srv, "Ind1", true)
	setInd(srv, "Ind2", true)

	entries := queryAll(t, c)
	if len(entries) != 2 {
		t.Fatalf("%d entries, want 2", len(entries))
	}
	e := entries[0]
	if len(e.Variables) != 2 {
		t.Fatalf("first entry variables = %+v, want the value and its reason", e.Variables)
	}
	if v := e.Variables[0]; v.Tag != logLD+"/GGIO1$ST$Ind1$stVal" || v.Value == nil || !v.Value.Bool() {
		t.Errorf("logged variable = %s %v, want Ind1 stVal true", v.Tag, v.Value)
	}
	if v := e.Variables[1]; v.Tag != "ReasonCode" || v.Value == nil ||
		model.ReasonFromValue(v.Value)&model.ReasonDataChange == 0 {
		t.Errorf("reason = %s %v, want ReasonCode with data-change", v.Tag, v.Value)
	}
	if time.Since(e.OccurrenceTime) > time.Minute || time.Until(e.OccurrenceTime) > time.Second {
		t.Errorf("occurrence time %v is not now", e.OccurrenceTime)
	}
	if bytes.Equal(entries[0].EntryID, entries[1].EntryID) || len(entries[0].EntryID) != 8 {
		t.Errorf("entry IDs %x and %x, want two distinct 8-octet IDs", entries[0].EntryID, entries[1].EntryID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	read := func(attr string) *mms.Value {
		vals, err := c.MMS().Read(ctx, logLD, lcbLG+"$"+attr)
		if err != nil || len(vals) == 0 {
			t.Fatalf("read %s: %v", attr, err)
		}
		return vals[0]
	}
	if got := read("OldEnt").Bytes(); !bytes.Equal(got, entries[0].EntryID) {
		t.Errorf("OldEnt = %x, want the oldest entry %x", got, entries[0].EntryID)
	}
	if got := read("NewEnt").Bytes(); !bytes.Equal(got, entries[1].EntryID) {
		t.Errorf("NewEnt = %x, want the newest entry %x", got, entries[1].EntryID)
	}
	if got := read("NewEntrTm").Time(); !got.Equal(entries[1].OccurrenceTime) {
		t.Errorf("NewEntrTm = %v, want %v", got, entries[1].OccurrenceTime)
	}

	// Continuing after the first entry returns the second.
	after, err := c.QueryLogAfter(ctx, logRef, entries[0].OccurrenceTime, entries[0].EntryID)
	if err != nil {
		t.Fatalf("QueryLogAfter: %v", err)
	}
	if len(after) != 1 || !bytes.Equal(after[0].EntryID, entries[1].EntryID) {
		t.Errorf("after the first entry: %d entries, want the second", len(after))
	}
}

// A log larger than one PDU arrives whole: the server pages it with
// moreFollows, and the client continues after the last entry of each page.
func TestLogQueryIsPaged(t *testing.T) {
	addr, srv := startServerWith(t, logModel())
	c := dialDemo(t, addr, withMaxPDU(300))
	const n = 40
	for i := range n {
		setInd(srv, "Ind1", i%2 == 0)
	}
	entries := queryAll(t, c)
	if len(entries) != n {
		t.Fatalf("%d entries, want %d", len(entries), n)
	}
	for i, e := range entries {
		want := i%2 == 0
		if len(e.Variables) == 0 || e.Variables[0].Value.Bool() != want {
			t.Fatalf("entry %d out of order or wrong: %+v", i, e.Variables)
		}
	}
}

// A log keeps its capacity, discarding the oldest entries.
func TestLogCapacity(t *testing.T) {
	srv, c := startLogServer(t, server.WithLogCapacity(3))
	for i := range 5 {
		setInd(srv, "Ind1", i%2 == 0)
	}
	entries := queryAll(t, c)
	if len(entries) != 3 {
		t.Fatalf("%d entries, want the capacity of 3", len(entries))
	}
	// The newest three survive: values false, true, false... of i = 2, 3, 4.
	for k, e := range entries {
		if want := (k+2)%2 == 0; e.Variables[0].Value.Bool() != want {
			t.Errorf("entry %d = %v, want %v", k, e.Variables[0].Value, want)
		}
	}
}

// A client controls logging through LogEna, and may change the
// configuration only while logging is off. The server's attributes are
// not writable.
func TestLCBWrites(t *testing.T) {
	srv, c := startLogServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	write := func(attr string, v *mms.Value) error {
		res, err := c.MMS().Write(ctx, logLD, []string{lcbLG + "$" + attr}, []*mms.Value{v})
		if err != nil {
			t.Fatalf("write %s: %v", attr, err)
		}
		return res[0]
	}

	if err := write("DatSet", mms.NewVisibleString(logLD+"/LLN0$Events")); !errors.Is(err, mms.AccessTemporarilyUnavailable) {
		t.Errorf("DatSet while logging: %v, want temporarily-unavailable", err)
	}
	if err := write("LogRef", mms.NewVisibleString("x")); !errors.Is(err, mms.AccessObjectAccessDenied) {
		t.Errorf("LogRef: %v, want object-access-denied", err)
	}
	if err := write("LogEna", mms.NewBool(false)); err != nil {
		t.Fatalf("LogEna false: %v", err)
	}
	setInd(srv, "Ind1", true)
	if got := len(queryAll(t, c)); got != 0 {
		t.Errorf("%d entries logged while disabled, want 0", got)
	}
	if err := write("DatSet", mms.NewVisibleString(logLD+"/LLN0$Nope")); !errors.Is(err, mms.AccessObjectValueInvalid) {
		t.Errorf("DatSet naming no dataset: %v, want object-value-invalid", err)
	}
	if err := write("TrgOps", (model.TrgDataChange | model.TrgDataUpdate).Value()); err != nil {
		t.Errorf("TrgOps while disabled: %v", err)
	}
	if err := write("LogEna", mms.NewBool(true)); err != nil {
		t.Fatalf("LogEna true: %v", err)
	}
	setInd(srv, "Ind2", true)
	if got := len(queryAll(t, c)); got != 1 {
		t.Errorf("%d entries after re-enabling, want 1", got)
	}
}

// Reading a log the server does not have is an error, not an empty log.
func TestUnknownLog(t *testing.T) {
	_, c := startLogServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := c.QueryLogByTime(ctx, logLD+"/LLN0.Nope", time.Time{}, time.Now())
	if err == nil {
		t.Error("reading a log that does not exist succeeded")
	}
}

// The integrity period logs every member, with reason integrity.
func TestLogIntegrityPeriod(t *testing.T) {
	m := logModel()
	lc := m.Devices[0].Nodes[0].LogControls[0]
	lc.TrgOps, lc.IntgPd = model.TrgIntegrity, 50
	addr, _ := startServerWith(t, m)
	c := dialDemo(t, addr)
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries := queryAll(t, c)
		if len(entries) > 0 {
			e := entries[0]
			if len(e.Variables) != 4 {
				t.Fatalf("integrity entry has %d variables, want both members and their reasons", len(e.Variables))
			}
			if r := model.ReasonFromValue(e.Variables[1].Value); r&model.ReasonIntegrity == 0 {
				t.Errorf("reason = %v, want integrity", fmt.Sprint(r))
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no integrity entry logged")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
