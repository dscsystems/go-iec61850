package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// tester runs a sequence of feature checks against a live server, printing
// a PASS/FAIL/SKIP line for each and a final summary.
type tester struct {
	c                   *client.Client
	pass, fail, skipped int
}

const stepTimeout = 12 * time.Second

func cmdTest(c *client.Client) bool {
	t := &tester{c: c}
	fmt.Println("Exercising server features...")
	fmt.Println()

	// Discover references once so later steps can reuse them.
	d := t.discover()

	t.step("Identify", func(ctx context.Context) (string, error) {
		v, m, r, err := c.MMS().Identify(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s / %s / %s", v, m, r), nil
	})

	t.step("Browse (getNameList)", func(ctx context.Context) (string, error) {
		lns, err := c.LogicalNodes(ctx, d.domain)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s: %d logical nodes", d.domain, len(lns)), nil
	})

	t.step("RetrieveModel", func(ctx context.Context) (string, error) {
		m, err := c.RetrieveModel(ctx)
		if err != nil {
			return "", err
		}
		n := 0
		for _, ld := range m.Devices {
			n += len(ld.Nodes)
		}
		return fmt.Sprintf("%d devices, %d logical nodes", len(m.Devices), n), nil
	})

	if d.readRef == "" {
		t.skip("Read", "no readable leaf found")
	} else {
		t.step("Read", func(ctx context.Context) (string, error) {
			v, err := c.Read(ctx, d.readRef, d.readFC)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s [%s] = %s", d.readRef, d.readFC, v), nil
		})
	}

	if d.writeRef == "" {
		t.skip("Write + read-back", "no writable attribute found")
	} else {
		t.step("Write + read-back", func(ctx context.Context) (string, error) {
			cur, err := c.Read(ctx, d.writeRef, d.writeFC)
			if err != nil {
				return "", fmt.Errorf("pre-read: %w", err)
			}
			if err := c.Write(ctx, d.writeRef, d.writeFC, cur); err != nil {
				return "", err
			}
			back, err := c.Read(ctx, d.writeRef, d.writeFC)
			if err != nil {
				return "", fmt.Errorf("read-back: %w", err)
			}
			if !back.Equal(cur) {
				return "", fmt.Errorf("read-back %s != written %s", back, cur)
			}
			return fmt.Sprintf("%s round-trips (%s)", d.writeRef, back), nil
		})
	}

	if d.datasetRef == "" {
		t.skip("Read dataset", "no dataset found")
	} else {
		t.step("Read dataset", func(ctx context.Context) (string, error) {
			ds, err := c.ReadDataSet(ctx, d.datasetRef)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s: %d members", d.datasetRef, len(ds.Members)), nil
		})
	}

	if d.datasetRef == "" || d.readRef == "" {
		t.skip("Create/delete dataset", "no template members")
	} else {
		t.step("Create/delete dataset", func(ctx context.Context) (string, error) {
			ref := model.ObjectReference(d.domain + "/LLN0.IedxTmpDS")
			members := []client.DataSetEntry{{Ref: d.readRef, FC: d.readFC}}
			if err := c.CreateDataSet(ctx, ref, members); err != nil {
				return "", fmt.Errorf("create: %w", err)
			}
			ds, err := c.ReadDataSet(ctx, ref)
			if err != nil {
				_ = c.DeleteDataSet(ctx, ref)
				return "", fmt.Errorf("read: %w", err)
			}
			if err := c.DeleteDataSet(ctx, ref); err != nil {
				return "", fmt.Errorf("delete: %w", err)
			}
			return fmt.Sprintf("created, read (%d members) and deleted %s", len(ds.Members), ref), nil
		})
	}

	if d.rcbRef == "" {
		t.skip("Reporting", "no report control block found")
	} else {
		t.step("Reporting (enable, GI, data-change)", t.testReporting(d))
	}

	if d.controlRef == "" {
		t.skip("Control", "no controllable object found")
	} else {
		t.step("Control (operate)", func(ctx context.Context) (string, error) {
			co, err := c.ControlFor(ctx, d.controlRef)
			if err != nil {
				return "", err
			}
			if err := co.Operate(ctx, mms.NewBool(true),
				client.WithOriginator(model.OrCatStationControl, "ied-client-test")); err != nil {
				return "", err
			}
			st, err := c.Read(ctx, d.controlRef.Child("stVal"), model.ST)
			if err == nil && !st.Bool() {
				return "", fmt.Errorf("stVal did not reflect operate")
			}
			return fmt.Sprintf("operated %s (model %s)", d.controlRef, co.Model()), nil
		})
	}

	if d.sgcbRef == "" {
		t.skip("Setting groups", "no SGCB found")
	} else {
		t.step("Setting groups", func(ctx context.Context) (string, error) {
			sg, err := c.SettingGroups(ctx, d.sgcbRef)
			if err != nil {
				return "", err
			}
			if sg.NumOfSG > 1 {
				if err := sg.SelectActiveSG(ctx, sg.ActSG); err != nil {
					return "", fmt.Errorf("select active: %w", err)
				}
			}
			return fmt.Sprintf("NumOfSG=%d ActSG=%d EditSG=%d", sg.NumOfSG, sg.ActSG, sg.EditSG), nil
		})
	}

	t.step("File directory", func(ctx context.Context) (string, error) {
		entries, err := c.FileDirectory(ctx, "")
		if err != nil {
			if isUnsupported(err) {
				return "", errSkip{"file service disabled on server"}
			}
			return "", err
		}
		msg := fmt.Sprintf("%d files", len(entries))
		if len(entries) > 0 {
			data, err := c.ReadFile(ctx, entries[0].Name)
			if err != nil {
				return "", fmt.Errorf("read %s: %w", entries[0].Name, err)
			}
			msg += fmt.Sprintf("; read %s (%d bytes)", entries[0].Name, len(data))
		}
		return msg, nil
	})

	if d.logRef == "" {
		t.skip("Log query", "no log found")
	} else {
		t.step("Log query", func(ctx context.Context) (string, error) {
			entries, err := c.QueryLogByTime(ctx, d.logRef, time.Now().Add(-time.Hour), time.Now())
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s: %d entries in the last hour", d.logRef, len(entries)), nil
		})
	}

	fmt.Println()
	fmt.Printf("Summary: %d passed, %d failed, %d skipped\n", t.pass, t.fail, t.skipped)
	return t.fail == 0
}

// testReporting enables an RCB, expects a GI report, then waits for a
// data-change report driven by the server's simulation.
func (t *tester) testReporting(d discovery) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		reports := make(chan *client.Report, 16)
		rcb, err := t.c.GetRCB(ctx, d.rcbRef)
		if err != nil {
			return "", fmt.Errorf("get RCB: %w", err)
		}
		rcb.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptDataSetName | model.OptConfRev
		rcb.TrgOps = model.TrgDataChange | model.TrgQualityChange | model.TrgGI
		sub, err := t.c.EnableReporting(ctx, rcb, func(r *client.Report) {
			select {
			case reports <- r:
			default:
			}
		})
		if err != nil {
			return "", fmt.Errorf("enable: %w", err)
		}
		defer sub.Disable(context.Background())

		if err := t.c.TriggerGI(ctx, rcb); err != nil {
			return "", fmt.Errorf("GI: %w", err)
		}
		gi := false
		dchg := false
		deadline := time.After(10 * time.Second)
		for !gi || !dchg {
			select {
			case r := <-reports:
				if hasReason(r, model.ReasonGI) {
					gi = true
				}
				if hasReason(r, model.ReasonDataChange) || hasReason(r, model.ReasonQualityChange) {
					dchg = true
				}
				if len(r.Entries) == 0 {
					gi = true // some servers omit reason on GI
				}
			case <-deadline:
				if gi {
					return "GI report received (no data-change within 10s)", nil
				}
				return "", fmt.Errorf("no report received")
			}
		}
		return "GI and data-change reports received", nil
	}
}

func hasReason(r *client.Report, want model.ReasonCode) bool {
	for _, e := range r.Entries {
		if e.Reason&want != 0 {
			return true
		}
	}
	return false
}

// discovery holds references found by probing the server.
type discovery struct {
	domain     string
	readRef    model.ObjectReference
	readFC     model.FC
	writeRef   model.ObjectReference
	writeFC    model.FC
	datasetRef model.ObjectReference
	rcbRef     model.ObjectReference
	controlRef model.ObjectReference
	sgcbRef    model.ObjectReference
	logRef     model.ObjectReference
}

func (t *tester) discover() discovery {
	var d discovery
	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()

	lds, err := t.c.LogicalDevices(ctx)
	if err != nil || len(lds) == 0 {
		fatal("discovery: %v", err)
	}
	d.domain = lds[0]

	names, _ := t.c.MMS().GetNameList(ctx, mms.ClassNamedVariable, d.domain)
	for _, n := range names {
		parts := strings.Split(n, "$")
		switch {
		case d.readRef == "" && len(parts) >= 4 && parts[1] == "MX" && parts[len(parts)-1] == "f":
			d.readRef = mmsToRef(d.domain, parts)
			d.readFC = model.MX
		case d.writeRef == "" && len(parts) >= 4 && parts[1] == "CF" && parts[len(parts)-1] == "ctlModel":
			d.writeRef = mmsToRef(d.domain, parts)
			d.writeFC = model.CF
		case d.controlRef == "" && len(parts) >= 4 && parts[1] == "CO" && parts[len(parts)-1] == "Oper":
			d.controlRef = coRef(d.domain, parts)
		case d.rcbRef == "" && len(parts) == 3 && parts[1] == "RP":
			d.rcbRef = model.ObjectReference(d.domain + "/" + parts[0] + ".RP." + parts[2])
		case d.sgcbRef == "" && len(parts) == 4 && parts[1] == "SP" && parts[2] == "SGCB":
			d.sgcbRef = model.ObjectReference(d.domain + "/" + parts[0] + ".SP.SGCB")
		case d.logRef == "" && len(parts) == 3 && parts[1] == "LG":
			d.logRef = model.ObjectReference(d.domain + "/" + parts[0] + ".LG." + parts[2])
		}
	}
	// If no MX float, fall back to any leaf under ST.
	if d.readRef == "" {
		for _, n := range names {
			parts := strings.Split(n, "$")
			if len(parts) >= 3 && parts[1] == "ST" && parts[len(parts)-1] == "stVal" {
				d.readRef = mmsToRef(d.domain, parts)
				d.readFC = model.ST
				break
			}
		}
	}
	dsNames, _ := t.c.MMS().GetNameList(ctx, mms.ClassNamedVariableList, d.domain)
	for _, n := range dsNames {
		if ln, ds, ok := strings.Cut(n, "$"); ok {
			d.datasetRef = model.ObjectReference(d.domain + "/" + ln + "." + ds)
			break
		}
	}
	return d
}

// mmsToRef converts ["LN","FC","DO",...,"DA"] to "LD/LN.DO....DA" (dropping
// the FC element).
func mmsToRef(domain string, parts []string) model.ObjectReference {
	path := append([]string{parts[0]}, parts[2:]...)
	return model.ObjectReference(domain + "/" + strings.Join(path, "."))
}

// coRef converts ["LN","CO","DO",...,"Oper"] to the controllable object ref.
func coRef(domain string, parts []string) model.ObjectReference {
	do := parts[2 : len(parts)-1] // drop LN, CO and trailing Oper
	path := append([]string{parts[0]}, do...)
	return model.ObjectReference(domain + "/" + strings.Join(path, "."))
}

// errSkip lets a step downgrade itself to SKIP (e.g. optional service off).
type errSkip struct{ reason string }

func (e errSkip) Error() string { return e.reason }

func isUnsupported(err error) bool {
	var se *mms.ServiceError
	if errors.As(err, &se) {
		return se.Rejected || se.Class == 1
	}
	return false
}

func (t *tester) step(name string, fn func(context.Context) (string, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	defer cancel()
	detail, err := fn(ctx)
	if err != nil {
		if es, ok := err.(errSkip); ok {
			t.skipped++
			fmt.Printf("  %s SKIP  %-34s %s\n", "○", name, es.reason)
			return
		}
		t.fail++
		fmt.Printf("  %s FAIL  %-34s %v\n", "✗", name, err)
		return
	}
	t.pass++
	fmt.Printf("  %s PASS  %-34s %s\n", "✓", name, detail)
}

func (t *tester) skip(name, reason string) {
	t.skipped++
	fmt.Printf("  %s SKIP  %-34s %s\n", "○", name, reason)
}
