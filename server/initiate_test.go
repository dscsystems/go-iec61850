package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
)

// The Initiate answer states the server's own services, whatever the
// client claimed, and negotiates the parameter CBB down to what both ends
// support (ISO 9506-2). A client that proposes a minimal bitmap must still
// learn that the server reads and writes, and must not be told the server
// does things it does not.
func TestInitiateAnswersWithServerCapabilities(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A client claiming only getNameList, and only str1 + vnam support.
	cbb := asn1.NewBitString(11)
	cbb.SetBit(0, true) // str1
	cbb.SetBit(2, true) // vnam
	cbb.SetBit(4, true) // vadr: the server does not offer it
	init := mms.DefaultInitiate()
	init.Services = mms.NewServiceSupport(mms.ServiceGetNameList)
	init.ParameterCBBRaw = asn1.AppendBitString(nil, cbb)

	c, err := mms.Dial(ctx, addr, mms.Options{Initiate: &init})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()
	got := c.Negotiated()

	for _, svc := range []struct {
		bit  int
		name string
		want bool
	}{
		{mms.ServiceRead, "read", true},
		{mms.ServiceWrite, "write", true},
		{mms.ServiceGetVariableAccessAttributes, "getVariableAccessAttributes", true},
		{mms.ServiceDefineNamedVariableList, "defineNamedVariableList", true},
		{mms.ServiceInformationReport, "informationReport", true},
		{mms.ServiceStatus, "status", false},           // not implemented
		{mms.ServiceCancel, "cancel", false},           // not implemented
		{mms.ServiceReadJournal, "readJournal", false}, // not implemented
		{mms.ServiceFileOpen, "fileOpen", false},       // no file store configured
	} {
		if has := got.Services.Has(svc.bit); has != svc.want {
			t.Errorf("server advertises %s = %v, want %v", svc.name, has, svc.want)
		}
	}

	neg, err := asn1.DecodeBitString(got.ParameterCBBRaw)
	if err != nil {
		t.Fatalf("negotiated CBB: %v", err)
	}
	for bit, want := range map[int]bool{0: true, 1: false, 2: true, 3: false, 4: false, 7: false} {
		if neg.Bit(bit) != want {
			t.Errorf("negotiated CBB bit %d = %v, want %v (intersection of both ends)", bit, neg.Bit(bit), want)
		}
	}
}
