package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// The Edition 2 and 2.1 classes of the fixture are served with the shapes
// 7-3 and 8-1 give them: the service tracking objects under FC SR, a
// PhyComAddr as its four-member structure, and arrays of a constructed type
// (HST.hstRangeC, CSG.crvPts) as arrays, both in their values and in the
// type a client is told. An array of structures used to be served as a
// single structure, and an array's type description had no element type.
func TestEd2ClassesServed(t *testing.T) {
	m, err := loadEd21(t)
	if err != nil {
		t.Fatalf("LoadModel: %v", err)
	}
	addr, _ := startServerWith(t, m)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rc := mustRead(t, c, ctx, "ED21LD0/GAPC1.Hst.hstRangeC", model.CF)
	if rc.Type() != mms.TypeArray || rc.Len() != 4 {
		t.Fatalf("hstRangeC = %v of %d, want an array of 4", rc.Type(), rc.Len())
	}
	if e := rc.Index(0); e.Type() != mms.TypeStructure || e.Len() != 2 {
		t.Errorf("hstRangeC[0] = %v of %d, want a Cell of xStart, xEnd", e.Type(), e.Len())
	}
	if pts := mustRead(t, c, ctx, "ED21LD0/GAPC1.Crv.crvPts", model.SP); pts.Type() != mms.TypeArray || pts.Len() != 5 {
		t.Errorf("crvPts = %v of %d, want an array of 5", pts.Type(), pts.Len())
	}
	if hv := mustRead(t, c, ctx, "ED21LD0/GAPC1.Hst.hstVal", model.ST); hv.Type() != mms.TypeArray || hv.Len() != 4 {
		t.Errorf("hstVal = %v of %d, want an array of 4", hv.Type(), hv.Len())
	}
	dst := mustRead(t, c, ctx, "ED21LD0/LTRK1.GocbTrk.dstAddress", model.SR)
	if dst.Type() != mms.TypeStructure || dst.Len() != 4 {
		t.Errorf("dstAddress = %v of %d, want a PhyComAddr structure", dst.Type(), dst.Len())
	}
	if cur := mustRead(t, c, ctx, "ED21LD0/GAPC1.Cur.cur", model.SP); cur.Text() != "EUR" {
		t.Errorf("Cur.cur = %q, want EUR", cur.Text())
	}

	mc := c.MMS()
	spec, err := mc.GetVariableAccessAttributes(ctx, "ED21LD0", "GAPC1$CF$Hst$hstRangeC")
	if err != nil {
		t.Fatalf("hstRangeC type: %v", err)
	}
	if spec.Kind != mms.TypeArray || spec.Elements != 4 || spec.Element == nil ||
		spec.Element.Kind != mms.TypeStructure || len(spec.Element.Components) != 2 {
		t.Errorf("hstRangeC type = %+v, want an array of 4 Cells", spec)
	}
	spec, err = mc.GetVariableAccessAttributes(ctx, "ED21LD0", "GAPC1$ST$Hst$hstVal")
	if err != nil {
		t.Fatalf("hstVal type: %v", err)
	}
	if spec.Kind != mms.TypeArray || spec.Elements != 4 || spec.Element == nil || spec.Element.Kind != mms.TypeInteger {
		t.Errorf("hstVal type = %+v, want an array of 4 integers", spec)
	}
	// The whole node, every constraint of it, describes.
	for _, item := range []string{"GAPC1", "LTRK1", "LTRK1$SR"} {
		if _, err := mc.GetVariableAccessAttributes(ctx, "ED21LD0", item); err != nil {
			t.Errorf("%s type: %v", item, err)
		}
	}
}
