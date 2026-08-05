package server_test

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

func wantAll(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in %v", w, got)
		}
	}
}

func wantNone(t *testing.T, got []string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if slices.Contains(got, u) {
			t.Errorf("unexpected %q in %v", u, got)
		}
	}
}

func TestLogicalNodeDirectoryByClass(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	lln0 := model.ObjectReference("simpleIOGenericIO/LLN0")
	ggio1 := model.ObjectReference("simpleIOGenericIO/GGIO1")

	t.Run("URCB", func(t *testing.T) {
		got, err := c.LogicalNodeDirectory(ctx, lln0, client.ACSIURCB)
		if err != nil {
			t.Fatal(err)
		}
		wantAll(t, got, "EventsRCB01", "EventsRCBPreConf01", "EventsIndexed01")
		// Buffered blocks, data objects and control-block members are other
		// classes or not objects at all.
		wantNone(t, got, "EventsBRCB01", "Mod", "RptID", "RptEna")
		for _, n := range got {
			if strings.Contains(n, "$") {
				t.Errorf("name %q is an MMS item ID, not an object name", n)
			}
		}
	})

	t.Run("BRCB", func(t *testing.T) {
		got, err := c.LogicalNodeDirectory(ctx, lln0, client.ACSIBRCB)
		if err != nil {
			t.Fatal(err)
		}
		wantAll(t, got, "EventsBRCB01", "EventsBRCBPreConf01")
		wantNone(t, got, "EventsRCB01", "RptID")
	})

	t.Run("DataSet", func(t *testing.T) {
		got, err := c.LogicalNodeDirectory(ctx, lln0, client.ACSIDataSet)
		if err != nil {
			t.Fatal(err)
		}
		wantAll(t, got, "Events", "Events2", "Measurements")
	})

	t.Run("DataObject", func(t *testing.T) {
		got, err := c.LogicalNodeDirectory(ctx, ggio1, client.ACSIDataObject)
		if err != nil {
			t.Fatal(err)
		}
		// One entry per data object, deduplicated across its FCs (SPCSO1
		// appears under ST, CO and CF).
		wantAll(t, got, "Mod", "Beh", "Health", "SPCSO1", "SPCSO4", "Ind1")
		wantNone(t, got, "stVal", "Oper", "ctlModel")
		for i, n := range got {
			if slices.Contains(got[:i], n) {
				t.Errorf("duplicate entry %q in %v", n, got)
			}
		}
		// Control blocks live on LLN0, and are not data objects anyway.
		lln0Got, err := c.LogicalNodeDirectory(ctx, lln0, client.ACSIDataObject)
		if err != nil {
			t.Fatal(err)
		}
		wantAll(t, lln0Got, "Mod", "NamPlt")
		wantNone(t, lln0Got, "EventsRCB01", "EventsBRCB01")
	})

	t.Run("classes the node does not hold", func(t *testing.T) {
		for _, class := range []client.ACSIClass{
			client.ACSIGoCB, client.ACSIGsCB, client.ACSIMSVCB,
			client.ACSIUSVCB, client.ACSILCB, client.ACSISGCB,
		} {
			got, err := c.LogicalNodeDirectory(ctx, lln0, class)
			if err != nil {
				t.Fatalf("%s: %v", class, err)
			}
			if len(got) != 0 {
				t.Errorf("%s = %v, want empty", class, got)
			}
		}
	})

	t.Run("logs", func(t *testing.T) {
		// The demo server publishes no journals; an empty directory is a
		// legitimate answer, not an error.
		got, err := c.LogicalNodeDirectory(ctx, lln0, client.ACSILog)
		if err != nil {
			t.Fatalf("LOG directory: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("LOG = %v, want empty", got)
		}
	})

	t.Run("unknown node", func(t *testing.T) {
		got, err := c.LogicalNodeDirectory(ctx, "simpleIOGenericIO/NOSUCHLN", client.ACSIDataObject)
		if err != nil {
			t.Fatalf("unknown LN: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("unknown LN = %v, want empty", got)
		}
	})

	t.Run("bad reference", func(t *testing.T) {
		if _, err := c.LogicalNodeDirectory(ctx, "GGIO1", client.ACSIDataObject); err == nil {
			t.Error("reference without a logical device was accepted")
		}
	})
}

// cbModel carries the control-block classes the demo CID has none of, plus
// a genuine set point, which shares FC SP with the SGCB.
func cbModel() *model.Model {
	da := func(name string, fc model.FC) *model.DataAttribute {
		return &model.DataAttribute{Name: name, FC: fc, Kind: mms.TypeInteger, Value: mms.NewInt32(0)}
	}
	do := func(name string, fc model.FC, attrs ...string) *model.DataObject {
		obj := &model.DataObject{Name: name}
		for _, a := range attrs {
			obj.Attributes = append(obj.Attributes, da(a, fc))
		}
		return obj
	}
	lln0 := &model.LogicalNode{Name: "LLN0", Class: "LLN0", Objects: []*model.DataObject{
		do("SGCB", model.SP, "NumOfSG", "ActSG", "EditSG"),
		do("StrVal", model.SP, "setMag"), // an ordinary set point
		do("gcb01", model.GO, "GoEna", "GoID", "DatSet"),
		do("gscb01", model.GS, "GsEna"),
		do("lcb01", model.LG, "LogEna", "LogRef"),
		do("msvcb01", model.MS, "SvEna", "MsvID"),
		do("usvcb01", model.US, "SvEna", "UsvID"),
		do("Mod", model.ST, "stVal"),
	}}
	ld := &model.LogicalDevice{Name: "CBIED", Inst: "LD0", Nodes: []*model.LogicalNode{lln0}}
	return &model.Model{Name: "CBIED", Devices: []*model.LogicalDevice{ld}}
}

func TestLogicalNodeDirectoryControlBlockClasses(t *testing.T) {
	srv := server.New(cbModel())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ref := model.ObjectReference("CBIED/LLN0")
	for _, tc := range []struct {
		class client.ACSIClass
		want  []string
	}{
		{client.ACSIGoCB, []string{"gcb01"}},
		{client.ACSIGsCB, []string{"gscb01"}},
		{client.ACSILCB, []string{"lcb01"}},
		{client.ACSIMSVCB, []string{"msvcb01"}},
		{client.ACSIUSVCB, []string{"usvcb01"}},
		{client.ACSISGCB, []string{"SGCB"}},
		// The SGCB shares FC SP with set points and must not be counted as
		// a data object; the set point must be.
		{client.ACSIDataObject, []string{"StrVal", "Mod"}},
	} {
		got, err := c.LogicalNodeDirectory(ctx, ref, tc.class)
		if err != nil {
			t.Fatalf("%s: %v", tc.class, err)
		}
		// Order follows the server's name list (grouped by FC), so compare
		// as sets.
		slices.Sort(got)
		want := slices.Clone(tc.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", tc.class, got, want)
		}
	}
}

// Browse is the device-wide form the explorer uses: one pass over the name
// list, covering every logical node and every class asked for, returning
// references the rest of the client API accepts as they are.
func TestBrowseDevice(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const ld = "simpleIOGenericIO"

	t.Run("report control blocks carry their class", func(t *testing.T) {
		found, err := c.Browse(ctx, ld, client.ACSIURCB, client.ACSIBRCB)
		if err != nil {
			t.Fatal(err)
		}
		byRef := map[model.ObjectReference]client.ACSIClass{}
		for _, e := range found {
			byRef[e.Ref] = e.Class
		}
		if got := byRef["simpleIOGenericIO/LLN0.RP.EventsRCB01"]; got != client.ACSIURCB {
			t.Errorf("EventsRCB01 class = %s, want URCB", got)
		}
		if got := byRef["simpleIOGenericIO/LLN0.BR.EventsBRCB01"]; got != client.ACSIBRCB {
			t.Errorf("EventsBRCB01 class = %s, want BRCB", got)
		}
		// The reference is what GetRCB takes.
		rcb, err := c.GetRCB(ctx, "simpleIOGenericIO/LLN0.RP.EventsRCB01")
		if err != nil {
			t.Fatalf("GetRCB on a browsed reference: %v", err)
		}
		if rcb.DataSet == "" {
			t.Error("browsed RCB reference resolved to an empty control block")
		}
	})

	t.Run("data sets", func(t *testing.T) {
		found, err := c.Browse(ctx, ld, client.ACSIDataSet)
		if err != nil {
			t.Fatal(err)
		}
		var refs []string
		for _, e := range found {
			if e.Class != client.ACSIDataSet {
				t.Errorf("%s reported as %s", e.Ref, e.Class)
			}
			refs = append(refs, string(e.Ref))
		}
		wantAll(t, refs, "simpleIOGenericIO/LLN0.Events", "simpleIOGenericIO/LLN0.Measurements")
		// And ReadDataSet takes it unchanged.
		if _, err := c.ReadDataSet(ctx, "simpleIOGenericIO/LLN0.Events"); err != nil {
			t.Errorf("ReadDataSet on a browsed reference: %v", err)
		}
	})

	t.Run("data objects have no functional constraint", func(t *testing.T) {
		found, err := c.Browse(ctx, ld, client.ACSIDataObject)
		if err != nil {
			t.Fatal(err)
		}
		var refs []string
		for _, e := range found {
			refs = append(refs, string(e.Ref))
		}
		// The FC is an argument of Read, not part of a data reference.
		wantAll(t, refs, "simpleIOGenericIO/GGIO1.SPCSO1", "simpleIOGenericIO/LLN0.Mod")
		wantNone(t, refs, "simpleIOGenericIO/GGIO1.ST.SPCSO1", "simpleIOGenericIO/LLN0.RP.EventsRCB01")
		if _, err := c.Read(ctx, "simpleIOGenericIO/GGIO1.SPCSO1.stVal", model.ST); err != nil {
			t.Errorf("Read under a browsed data object: %v", err)
		}
	})

	t.Run("every class at once", func(t *testing.T) {
		all, err := c.Browse(ctx, ld)
		if err != nil {
			t.Fatal(err)
		}
		classes := map[client.ACSIClass]int{}
		for _, e := range all {
			classes[e.Class]++
		}
		for _, want := range []client.ACSIClass{client.ACSIDataObject, client.ACSIURCB, client.ACSIBRCB, client.ACSIDataSet} {
			if classes[want] == 0 {
				t.Errorf("no %s in a full browse", want)
			}
		}
		// One entry per object, whatever else it was matched against.
		seen := map[model.ObjectReference]bool{}
		for _, e := range all {
			if seen[e.Ref] {
				t.Errorf("duplicate reference %s", e.Ref)
			}
			seen[e.Ref] = true
		}
	})

	t.Run("bad device", func(t *testing.T) {
		if _, err := c.Browse(ctx, ""); err == nil {
			t.Error("empty logical device was accepted")
		}
		got, err := c.Browse(ctx, "NoSuchLD", client.ACSIDataObject)
		if err != nil {
			t.Fatalf("unknown device: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("unknown device = %v, want empty", got)
		}
	})
}

func TestBrowseSGCBReference(t *testing.T) {
	srv := server.New(cbModel())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, ln.Addr().String(), client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	found, err := c.Browse(ctx, "CBIED", client.ACSISGCB, client.ACSIGoCB, client.ACSILCB)
	if err != nil {
		t.Fatal(err)
	}
	got := map[client.ACSIClass]model.ObjectReference{}
	for _, e := range found {
		got[e.Class] = e.Ref
	}
	// The setting group control block reference is the one SettingGroups
	// reads, and the control blocks keep their functional constraint.
	for class, want := range map[client.ACSIClass]model.ObjectReference{
		client.ACSISGCB: "CBIED/LLN0.SP.SGCB",
		client.ACSIGoCB: "CBIED/LLN0.GO.gcb01",
		client.ACSILCB:  "CBIED/LLN0.LG.lcb01",
	} {
		if got[class] != want {
			t.Errorf("%s = %q, want %q", class, got[class], want)
		}
	}
	if _, err := c.SettingGroups(ctx, got[client.ACSISGCB]); err != nil {
		t.Errorf("SettingGroups on a browsed reference: %v", err)
	}
}

func TestDataDirectory(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	spcso1 := model.ObjectReference("simpleIOGenericIO/GGIO1.SPCSO1")

	// model.ALL unions the object's views: its status attributes and its
	// control ones.
	all, err := c.DataDirectory(ctx, spcso1, model.ALL)
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, all, "stVal", "q", "t", "ctlNum", "origin", "Oper", "ctlModel")
	wantNone(t, all, "ctlVal", "orCat") // those are a level deeper

	// One functional constraint at a time.
	st, err := c.DataDirectory(ctx, spcso1, model.ST)
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, st, "stVal", "q", "t")
	wantNone(t, st, "Oper", "ctlModel")

	co, err := c.DataDirectory(ctx, spcso1, model.CO)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(co, []string{"Oper"}) {
		t.Errorf("CO children = %v, want [Oper]", co)
	}

	// Nested attributes browse the same way.
	oper, err := c.DataDirectory(ctx, spcso1.Child("Oper"), model.CO)
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, oper, "ctlVal", "origin", "ctlNum", "T", "Test", "Check")
	wantNone(t, oper, "orCat")

	origin, err := c.DataDirectory(ctx, spcso1.Child("Oper").Child("origin"), model.ALL)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(origin, []string{"orCat", "orIdent"}) {
		t.Errorf("origin children = %v, want [orCat orIdent]", origin)
	}

	// A leaf has no children, and an unknown object is empty rather than an
	// error.
	leaf, err := c.DataDirectory(ctx, spcso1.Child("stVal"), model.ST)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf) != 0 {
		t.Errorf("leaf children = %v, want none", leaf)
	}
	if got, err := c.DataDirectory(ctx, "simpleIOGenericIO/GGIO1.NoSuchDO", model.ALL); err != nil || len(got) != 0 {
		t.Errorf("unknown object = %v, %v; want empty and no error", got, err)
	}
	if _, err := c.DataDirectory(ctx, "simpleIOGenericIO/GGIO1", model.ALL); err == nil {
		t.Error("a logical node reference was accepted as a data reference")
	}
}
