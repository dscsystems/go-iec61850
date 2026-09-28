package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// Exactly one SGCB per logical device. Each setting-group manager appends
// one to LLN0, so two managers for one device left two objects in the
// model: getNameList listed the attributes twice, and the object a read
// resolved was not the one a write updated — a client that wrote ActSG=2
// and read it back saw 1 while the setting values had really switched.
func TestOnlyOneSGCBPerDevice(t *testing.T) {
	m, err := loadEd21(t)
	if err != nil {
		t.Fatal(err)
	}
	// WithSettingGroups and a declared SettingControl both configure the
	// groups, which is the combination that produced two.
	srv := server.New(m, server.WithSettingGroups(2))
	defer srv.Close()

	lln0 := m.Device("ED21LD0").Node("LLN0")
	n := 0
	for _, do := range lln0.Objects {
		if do.Name == "SGCB" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("LLN0 has %d SGCB objects, want exactly 1", n)
	}
	// A write must be visible in the read that follows, which is the
	// property two objects broke.
	addr, _ := serve(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.Write(ctx, model.ObjectReference("ED21LD0/LLN0.SGCB.ActSG"),
		model.SP, mms.NewUint8(2)); err != nil {
		t.Fatalf("writing ActSG: %v", err)
	}
	v, err := c.Read(ctx, model.ObjectReference("ED21LD0/LLN0.SGCB.ActSG"), model.SP)
	if err != nil {
		t.Fatal(err)
	}
	if v.Int64() != 2 {
		t.Errorf("ActSG reads back as %d after writing 2", v.Int64())
	}
}

// serve starts an already-configured server on a loopback listener.
func serve(t *testing.T, srv *server.Server) (string, *server.Server) {
	t.Helper()
	addr, s := startServerWithModel(t, srv)
	return addr, s
}

// An attribute of an unknown basic type inside a structure must fail the
// whole read. Returning the other members would encode a structure with
// fewer components than the type specification declares, and the client
// would line them up against the wrong member names — silent misalignment,
// which is worse than an error.
func TestUnknownTypedMemberDoesNotSilentlyShortenAStructure(t *testing.T) {
	m := &model.Model{Name: "I", Devices: []*model.LogicalDevice{{
		Name: "ILD0", Inst: "LD0", Nodes: []*model.LogicalNode{{
			Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{{
				Name: "Weird", CDC: "VEND", Attributes: []*model.DataAttribute{
					{Name: "a", FC: model.ST, Kind: mms.TypeInteger, Value: mms.NewInt32(1)},
					// An attribute whose basic type is unknown: no value
					// and no type the server could describe.
					{Name: "b", FC: model.ST, Kind: mms.TypeNone, BType: "VendorType"},
					{Name: "c", FC: model.ST, Kind: mms.TypeInteger, Value: mms.NewInt32(3)},
				},
			}},
		}},
	}}}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// A read of the whole data object must fail rather than return a
	// two-member structure for a three-member type.
	if _, err := c.Read(ctx, model.ObjectReference("ILD0/GGIO1.Weird"), model.ST); err == nil {
		t.Error("a data object with an unreadable member read as if all were readable")
	}
	// Reading only the members that can be produced still works, so the
	// failure is per member and not per object.
	v, err := c.Read(ctx, model.ObjectReference("ILD0/GGIO1.Weird.a"), model.ST)
	if err != nil {
		t.Fatalf("a readable member failed: %v", err)
	}
	if v.Int64() != 1 {
		t.Errorf("Weird.a = %d, want 1", v.Int64())
	}
}

// A data object that is not exposed under the functional constraint named
// in the item does not exist under it. Reporting the success sentinel as
// the reason would send the peer an error code outside the 0..11 that
// ISO 9506-2 defines for DataAccessError.
func TestReadUnderAnUnrelatedConstraintIsObjectNonExistent(t *testing.T) {
	do := model.NewDataObject("SPCSO1", model.CDCSPC, model.WithControlModel(model.CtlDirectNormal))
	m := &model.Model{Name: "I", Devices: []*model.LogicalDevice{{
		Name: "ILD0", Inst: "LD0", Nodes: []*model.LogicalNode{{
			Name: "GGIO1", Class: "GGIO", Objects: []*model.DataObject{do},
		}},
	}}}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// The object exists, but not under MX: it has no MX attributes.
	_, err = c.Read(ctx, model.ObjectReference("ILD0/GGIO1.SPCSO1"), model.MX)
	if err == nil {
		t.Fatal("read an object under a constraint it is not exposed under")
	}
	if !errors.Is(err, mms.AccessObjectNonExistent) {
		t.Errorf("read failed with %v, want object-non-existent", err)
	}
}
