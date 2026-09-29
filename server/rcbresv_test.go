package server

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// resvModel has a buffered block whose first instance the configuration
// reserves for 10.0.0.1 and whose second is free, and an unbuffered block
// reserved the same way.
func resvModel() *model.Model {
	stVal := &model.DataAttribute{Name: "stVal", FC: model.ST, Kind: mms.TypeBoolean, Value: mms.NewBool(false)}
	resv := []*model.ClientReservation{{IEDName: "HMI", IP: net.ParseIP("10.0.0.1")}}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0",
		Objects:  []*model.DataObject{{Name: "Ind", Attributes: []*model.DataAttribute{stVal}}},
		DataSets: []*model.DataSet{{Name: "DS", Entries: []model.FCDA{{Ref: "IEDLD0/LLN0.Ind.stVal", FC: model.ST}}}},
		ReportControls: []*model.ReportControl{
			{Name: "brcb", DataSet: "DS", Buffered: true, RptEnabled: 2, Reservations: resv},
			{Name: "urcb", DataSet: "DS", RptEnabled: 1, Reservations: resv},
		},
	}
	ld := &model.LogicalDevice{Name: "IEDLD0", Inst: "LD0", Nodes: []*model.LogicalNode{lln0}}
	return &model.Model{Name: "IED", Devices: []*model.LogicalDevice{ld}}
}

func peer(ip string) *mms.ServerConn {
	return &mms.ServerConn{Peer: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
}

// rcbWrite runs a control block write the way the handler does: the rules,
// then the store, then the effect. It returns the refusal, or 0xff.
func rcbWrite(s *Server, item, attr string, v *mms.Value, conn *mms.ServerConn) byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := s.reports.checkRCBWrite("IEDLD0", item+"$"+attr, attr, v, conn)
	if code != 0xff {
		return code
	}
	rs := s.reports.reg["IEDLD0\x00"+item]
	rs.mu.Lock()
	rs.setAttr(attr, v)
	rs.mu.Unlock()
	s.reports.onRCBWrite("IEDLD0", item+"$"+attr, attr, v, conn)
	return 0xff
}

func rcbAttr(s *Server, item, attr string) *mms.Value {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs := s.reports.reg["IEDLD0\x00"+item]
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.attr(attr)
}

const (
	brcb1 = "LLN0$BR$brcb01"
	brcb2 = "LLN0$BR$brcb02"
	urcb1 = "LLN0$RP$urcb01"
)

// An instance the configuration reserves (ClientLN) is usable only from
// the client's address, shows ResvTms -1 and the client as Owner from the
// start, and keeps the reservation when that client leaves.
func TestConfiguredReservation(t *testing.T) {
	s := New(resvModel())
	hmi, other := peer("10.0.0.1"), peer("10.0.0.2")

	if got := rcbAttr(s, brcb1, "ResvTms").Int64(); got != -1 {
		t.Errorf("ResvTms = %d, want -1 for a configured reservation", got)
	}
	if got := rcbAttr(s, brcb1, "Owner").Bytes(); !bytes.Equal(got, []byte{10, 0, 0, 1}) {
		t.Errorf("Owner = %x, want the reserved client's address 0a000001", got)
	}
	if got := rcbAttr(s, brcb2, "ResvTms").Int64(); got != 0 {
		t.Errorf("unreserved instance ResvTms = %d, want 0", got)
	}
	if !rcbAttr(s, urcb1, "Resv").Bool() {
		t.Error("URCB Resv = false, want the configured reservation shown")
	}

	if code := rcbWrite(s, brcb1, "TrgOps", model.TrgGI.Value(), other); code != byte(mms.AccessTemporarilyUnavailable) {
		t.Errorf("another client writing a reserved block: %d, want temporarily-unavailable", code)
	}
	if code := rcbWrite(s, brcb2, "TrgOps", model.TrgGI.Value(), other); code != 0xff {
		t.Errorf("another client writing the free instance: %d, want success", code)
	}
	if code := rcbWrite(s, brcb1, "TrgOps", model.TrgGI.Value(), hmi); code != 0xff {
		t.Errorf("the reserved client writing its block: %d, want success", code)
	}
	if code := rcbWrite(s, brcb1, "ResvTms", mms.NewInt16(5), hmi); code != byte(mms.AccessObjectAccessDenied) {
		t.Errorf("changing a configured ResvTms: %d, want object-access-denied", code)
	}
	if code := rcbWrite(s, urcb1, "Resv", mms.NewBool(false), hmi); code != byte(mms.AccessObjectAccessDenied) {
		t.Errorf("releasing a configured URCB reservation: %d, want object-access-denied", code)
	}

	// The reservation outlives the client's association.
	s.reports.disableConn(hmi)
	if code := rcbWrite(s, brcb1, "TrgOps", model.TrgGI.Value(), other); code != byte(mms.AccessTemporarilyUnavailable) {
		t.Errorf("after the reserved client left: %d, want still temporarily-unavailable", code)
	}
	if code := rcbWrite(s, brcb1, "TrgOps", model.TrgGI.Value(), peer("10.0.0.1")); code != 0xff {
		t.Errorf("the reserved client reconnecting: %d, want success", code)
	}
}

// A BRCB whose client set ResvTms stays reserved for that client's address
// for ResvTms seconds after its association ends, so it can come back to
// its buffer, and is free after that.
func TestResvTmsOutlivesAssociation(t *testing.T) {
	s := New(resvModel())
	a, other := peer("10.0.0.7"), peer("10.0.0.8")

	if code := rcbWrite(s, brcb2, "ResvTms", mms.NewInt16(-1), a); code != byte(mms.AccessObjectValueInvalid) {
		t.Errorf("a client claiming ResvTms -1: %d, want object-value-invalid", code)
	}
	if code := rcbWrite(s, brcb2, "ResvTms", mms.NewInt16(1), a); code != 0xff {
		t.Fatalf("setting ResvTms: %d", code)
	}
	s.reports.disableConn(a)

	if code := rcbWrite(s, brcb2, "TrgOps", model.TrgGI.Value(), other); code != byte(mms.AccessTemporarilyUnavailable) {
		t.Errorf("another client inside ResvTms: %d, want temporarily-unavailable", code)
	}
	if got := rcbAttr(s, brcb2, "Owner").Bytes(); !bytes.Equal(got, []byte{10, 0, 0, 7}) {
		t.Errorf("Owner inside ResvTms = %x, want the departed client's address", got)
	}
	deadline := time.Now().Add(3 * time.Second)
	for rcbWrite(s, brcb2, "TrgOps", model.TrgGI.Value(), other) != 0xff {
		if time.Now().After(deadline) {
			t.Fatal("the reservation outlived ResvTms")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Without a ResvTms the reservation ends with the association, as before.
func TestNoResvTmsFreesOnDisconnect(t *testing.T) {
	s := New(resvModel())
	a, other := peer("10.0.0.7"), peer("10.0.0.8")
	if code := rcbWrite(s, brcb2, "TrgOps", model.TrgGI.Value(), a); code != 0xff {
		t.Fatalf("first write: %d", code)
	}
	if got := rcbAttr(s, brcb2, "Owner").Bytes(); !bytes.Equal(got, []byte{10, 0, 0, 7}) {
		t.Errorf("Owner = %x, want the writer's address", got)
	}
	s.reports.disableConn(a)
	if code := rcbWrite(s, brcb2, "TrgOps", model.TrgGI.Value(), other); code != 0xff {
		t.Errorf("after the owner left: %d, want the block free", code)
	}
}
