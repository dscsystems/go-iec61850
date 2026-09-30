package server_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
)

// TestLTRKAgainstLibiec runs the same services against libiec61850's
// server_example_service_tracking and against this server loaded with
// that example's ICD, and compares what each recorded in its LTRK. The
// example listens on port 102, so interop/run.sh runs this in an
// unprivileged network namespace (unshare -rn). Set IEC61850_C_LTRK_SERVER
// to the example binary and IEC61850_C_LTRK_ICD to simpleIO_ltrk_tests.icd.
func TestLTRKAgainstLibiec(t *testing.T) {
	bin, icd := os.Getenv("IEC61850_C_LTRK_SERVER"), os.Getenv("IEC61850_C_LTRK_ICD")
	if bin == "" || icd == "" {
		t.Skip("set IEC61850_C_LTRK_SERVER and IEC61850_C_LTRK_ICD")
	}
	m, err := scl.LoadModel(icd)
	if err != nil {
		t.Fatal(err)
	}
	ltrk := m.Device("simpleIOGenericIO").Node("LTRK1")
	ours, _ := startServerWith(t, m)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	dial := func(addr string) *client.Client {
		var c *client.Client
		var err error
		for i := 0; i < 50; i++ {
			if c, err = client.Dial(ctx, addr, client.WithTimeout(3*time.Second)); err == nil {
				t.Cleanup(func() { c.Close() })
				return c
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("dial %s: %v", addr, err)
		return nil
	}
	cs := map[string]*client.Client{"libiec61850": dial("127.0.0.1:102"), "go-iec61850": dial(ours)}

	// Attributes that differ by nature: when the service ran, the time the
	// client stamped the command with, and the report bookkeeping of each
	// server.
	//
	// Two more are skipped for libiec61850's sake. It copies a URCB's Resv
	// into rptEna of UrcbTrk, never into resv (reporting.c), and records a
	// resvTms in BrcbTrk its BRCB does not serve (it reads 0 there).
	skip := map[string]bool{"t": true, "T": true, "operTm": true, "timeOfEntry": true, "entryID": true,
		"sqNum": true, "lActTm": true, "owner": true, "resv": true, "resvTms": true}

	var leaves func(prefix string, attrs []*model.DataAttribute, out *[]string)
	leaves = func(prefix string, attrs []*model.DataAttribute, out *[]string) {
		for _, a := range attrs {
			if a.FC != model.SR || skip[a.Name] {
				continue
			}
			if len(a.Children) > 0 {
				leaves(prefix+a.Name+".", a.Children, out)
				continue
			}
			*out = append(*out, prefix+a.Name)
		}
	}
	compare := func(step, obj string) {
		t.Helper()
		do := ltrk.Object(obj)
		if do == nil {
			t.Fatalf("the ICD has no %s", obj)
		}
		var names []string
		leaves("", do.Attributes, &names)
		for _, n := range names {
			ref := model.ObjectReference("simpleIOGenericIO/LTRK1." + obj + "." + n)
			var vals [2]*mms.Value
			for i, who := range []string{"libiec61850", "go-iec61850"} {
				v, err := cs[who].Read(ctx, ref, model.SR)
				if err != nil {
					t.Errorf("%s: %s read %s: %v", step, who, ref, err)
				}
				vals[i] = v
			}
			if !vals[0].Equal(vals[1]) {
				t.Errorf("%s: %s.%s: libiec61850 %v, go-iec61850 %v", step, obj, n, vals[0], vals[1])
			}
		}
	}
	each := func(step string, fn func(c *client.Client) error) {
		t.Helper()
		for who, c := range cs {
			if err := fn(c); err != nil {
				t.Logf("%s: %s: %v", step, who, err)
			}
		}
	}

	// Each server reports its tracking objects through the example's BRCB
	// over the ServiceTracking data set, a service at a time.
	reports := map[string]chan *client.Report{}
	for who, c := range cs {
		ch := make(chan *client.Report, 64)
		reports[who] = ch
		rcb, err := c.GetRCB(ctx, "simpleIOGenericIO/LLN0.BR.brcbServiceTracking01")
		if err != nil {
			t.Fatalf("%s: GetRCB: %v", who, err)
		}
		// objRef is the member that raises data-update on every tracked
		// service; the example's block enables only dchg and qchg.
		rcb.TrgOps |= model.TrgDataUpdate
		if _, err := c.EnableReporting(ctx, rcb, func(r *client.Report) { ch <- r }); err != nil {
			t.Fatalf("%s: EnableReporting: %v", who, err)
		}
	}
	drain := func() {
		for _, ch := range reports {
			for len(ch) > 0 {
				<-ch
			}
		}
	}

	each("URCB enable", func(c *client.Client) error {
		return c.Write(ctx, "simpleIOGenericIO/LLN0.EventsRCB01.RptEna", model.RP, mms.NewBool(true))
	})
	compare("URCB enable", "UrcbTrk")

	// Refused alike by both, as the block is enabled.
	each("URCB RptID while enabled", func(c *client.Client) error {
		return c.Write(ctx, "simpleIOGenericIO/LLN0.EventsRCB01.RptID", model.RP, mms.NewVisibleString("changed"))
	})
	compare("URCB RptID while enabled", "UrcbTrk")

	each("BRCB IntgPd", func(c *client.Client) error {
		return c.Write(ctx, "simpleIOGenericIO/LLN0.Measurements01.IntgPd", model.BR, mms.NewUint32(2000))
	})
	compare("BRCB IntgPd", "BrcbTrk")

	each("operate", func(c *client.Client) error {
		co, err := c.ControlFor(ctx, "simpleIOGenericIO/GGIO1.SPCSO1")
		if err != nil {
			return err
		}
		return co.Operate(ctx, mms.NewBool(true))
	})
	compare("operate", "SpcTrk")
	// Up to the operate's, both servers sent the same reports: one per
	// tracked service, of the tracking object it updated.
	seqs := map[string][]string{}
	for who, ch := range reports {
		deadline := time.After(3 * time.Second)
	collect:
		for {
			select {
			case r := <-ch:
				for _, e := range r.Entries {
					seqs[who] = append(seqs[who], fmt.Sprintf("%s/%v", e.Ref, e.Reason))
					if strings.HasSuffix(string(e.Ref), "LTRK1.SpcTrk") {
						break collect
					}
				}
			case <-deadline:
				t.Errorf("%s sent no report of SpcTrk after the operate; it sent %v", who, seqs[who])
				break collect
			}
		}
	}
	if a, b := strings.Join(seqs["libiec61850"], " "), strings.Join(seqs["go-iec61850"], " "); a != b {
		t.Errorf("tracking reports differ:\n libiec61850 %s\n go-iec61850 %s", a, b)
	} else {
		t.Logf("tracking reports of both: %s", a)
	}
	drain()

	each("ActSG", func(c *client.Client) error {
		return c.Write(ctx, "simpleIOGenericIO/LLN0.SGCB.ActSG", model.SP, mms.NewUint8(2))
	})
	compare("ActSG", "SgcbTrk")

	each("ActSG out of range", func(c *client.Client) error {
		return c.Write(ctx, "simpleIOGenericIO/LLN0.SGCB.ActSG", model.SP, mms.NewUint8(9))
	})
	compare("ActSG out of range", "SgcbTrk")

	each("LogEna", func(c *client.Client) error {
		return c.Write(ctx, "simpleIOGenericIO/LLN0.EventLog.LogEna", model.LG, mms.NewBool(false))
	})
	// The two LCBs differ in TrgOps: the SCL schema defaults TrgOps@gi to
	// true, which this server's loader follows and libiec61850's does not.
	// Each server's LocbTrk has to state its own block's.
	skip["trgOps"] = true
	compare("LogEna", "LocbTrk")
	for who, c := range cs {
		lcb, err1 := c.Read(ctx, "simpleIOGenericIO/LLN0.EventLog.TrgOps", model.LG)
		trk, err2 := c.Read(ctx, "simpleIOGenericIO/LTRK1.LocbTrk.trgOps", model.SR)
		if err1 != nil || err2 != nil || !lcb.Equal(trk) {
			t.Errorf("%s: LocbTrk.trgOps %v (%v), the LCB's %v (%v)", who, trk, err2, lcb, err1)
		}
	}
}
