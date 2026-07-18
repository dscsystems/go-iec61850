package main

import (
	"net"
	"testing"

	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
	tea "github.com/charmbracelet/bubbletea"
)

// drain runs a command and feeds any resulting messages back into the app,
// following batches, so async work completes synchronously in the test.
func drain(t *testing.T, a *app, cmd tea.Cmd) {
	t.Helper()
	for i := 0; cmd != nil && i < 100; i++ {
		msg := cmd()
		switch m := msg.(type) {
		case nil:
			return
		case tea.BatchMsg:
			for _, c := range m {
				drain(t, a, c)
			}
			return
		default:
			_, cmd = a.Update(m)
		}
	}
}

func startServer(t *testing.T) string {
	t.Helper()
	m, err := scl.LoadModel("../../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New(m, server.WithIdentity(server.Identity{Vendor: "ACME", Model: "test", Revision: "1"}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestAppConnectAndBrowse(t *testing.T) {
	addr := startServer(t)
	a := newApp(addr, "", false)
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})

	// Connect (synchronously in the test).
	drain(t, a, a.connect())
	if !a.connected {
		t.Fatalf("not connected: status=%q", a.status)
	}
	if a.ident == "" {
		t.Fatalf("identity not read")
	}

	// The Browse panel loads the model on activation.
	drain(t, a, a.loadActive())
	bp := a.panels[0].(*browsePanel)
	if len(bp.roots) == 0 {
		t.Fatal("browse tree empty")
	}

	// Expand into a readable leaf and read it.
	bp.rebuild()
	var leaf *node
	var find func(ns []*node)
	find = func(ns []*node) {
		for _, n := range ns {
			if n.readable && leaf == nil {
				leaf = n
			}
			find(n.children)
		}
	}
	find(bp.roots)
	if leaf == nil {
		t.Fatal("no readable leaf")
	}
	drain(t, a, bp.read(a, leaf))
	if leaf.value == "" || leaf.valErr {
		t.Fatalf("leaf not read: %q err=%v", leaf.value, leaf.valErr)
	}
	t.Logf("read %s = %s", leaf.ref, leaf.value)

	// View must render at several sizes without panicking.
	for _, sz := range [][2]int{{120, 40}, {80, 24}, {40, 20}} {
		a.Update(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		if a.View() == "" {
			t.Fatalf("empty view at %v", sz)
		}
	}
}

func TestAppTabsAndMouse(t *testing.T) {
	addr := startServer(t)
	a := newApp(addr, "", false)
	a.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	drain(t, a, a.connect())

	// Keyboard tab switch.
	a.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	if a.active != 2 {
		t.Fatalf("expected tab 3 (index 2), got %d", a.active)
	}

	// Mouse click on the first tab switches back to Browse.
	rng := a.tabRanges()[0]
	a.handleMouse(tea.MouseMsg{X: rng[0], Y: 1, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
	if a.active != 0 {
		t.Fatalf("mouse tab click failed, active=%d", a.active)
	}

	// Wheel scrolls the browse tree.
	drain(t, a, a.loadActive())
	bp := a.panels[0].(*browsePanel)
	before := bp.cursor
	a.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown})
	if bp.cursor == before && len(bp.visible) > 1 {
		t.Fatal("wheel did not move cursor")
	}

	// Each panel loads and renders against the live server.
	for i := range a.panels {
		a.active = i
		drain(t, a, a.panels[i].load(a))
		if a.panels[i].view(a, rect{w: 120, h: 30}) == "" {
			t.Fatalf("panel %d (%s) rendered empty", i, a.panels[i].title())
		}
	}
}
