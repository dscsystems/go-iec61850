package main

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// The reports, datasets, settings and logs panels enumerate their objects
// with the client's ACSI-class browse instead of filtering MMS item IDs
// themselves. They must still find what the demo IED holds.
func TestPanelsPopulateFromClassBrowse(t *testing.T) {
	addr := startServer(t)
	a := newApp(addr, "", false)
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	drain(t, a, a.connect())
	if !a.connected {
		t.Fatalf("not connected: status=%q", a.status)
	}

	load := func(i int) {
		t.Helper()
		a.active = i
		drain(t, a, a.panels[i].load(a))
	}

	// Reports: both flavours of control block, each tagged correctly.
	load(1)
	rp := a.panels[1].(*reportsPanel)
	var buffered, unbuffered int
	for _, r := range rp.rcbs {
		switch {
		case r.buffered:
			buffered++
			if !strings.Contains(string(r.ref), ".BR.") {
				t.Errorf("buffered RCB %s is not a BR reference", r.ref)
			}
		default:
			unbuffered++
			if !strings.Contains(string(r.ref), ".RP.") {
				t.Errorf("unbuffered RCB %s is not an RP reference", r.ref)
			}
		}
	}
	if buffered == 0 || unbuffered == 0 {
		t.Fatalf("found %d buffered and %d unbuffered RCBs, want both", buffered, unbuffered)
	}

	// Data sets.
	load(2)
	ds := a.panels[2].(*datasetsPanel)
	var names []string
	for _, r := range ds.refs {
		names = append(names, string(r))
	}
	if !contains(names, "simpleIOGenericIO/LLN0.Events") {
		t.Errorf("datasets = %v, want the Events set", names)
	}

	// Controllable objects still come from the Oper scan, which no ACSI
	// class covers.
	load(3)
	cp := a.panels[3].(*controlsPanel)
	var ctrls []string
	for _, r := range cp.refs {
		ctrls = append(ctrls, string(r))
	}
	if !contains(ctrls, "simpleIOGenericIO/GGIO1.SPCSO1") {
		t.Errorf("controls = %v, want SPCSO1", ctrls)
	}

	// The demo IED has no setting groups and no logs: an empty panel, not
	// a failed load.
	load(4)
	if sp := a.panels[4].(*settingsPanel); len(sp.refs) != 0 {
		t.Errorf("setting groups = %v, want none", sp.refs)
	}
	load(6)
	if lp := a.panels[6].(*logsPanel); len(lp.refs) != 0 {
		t.Errorf("logs = %v, want none", lp.refs)
	}
	if a.status != "" && strings.Contains(a.status, "error") {
		t.Errorf("status after loading every panel: %q", a.status)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
