package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// panel is one tab of the explorer. Panels mutate themselves via pointer
// receivers and return commands; the app supplies itself for shared access
// to the connection and for opening dialogs.
type panel interface {
	title() string
	load(a *app) tea.Cmd // (re)fetch data, e.g. when the tab opens
	update(a *app, msg tea.Msg) tea.Cmd
	view(a *app, r rect) string // render within r
	click(a *app, x, y int) tea.Cmd
	wheel(a *app, up bool) tea.Cmd
}

// dialog is a modal overlay capturing input until it closes.
type dialog interface {
	update(a *app, msg tea.Msg) (done bool, cmd tea.Cmd)
	view(a *app, w, h int) string
}

type rect struct{ w, h int }

type app struct {
	addr     string
	password string
	tlsOn    bool

	cl        *client.Client
	ident     string
	connected bool
	loaded    map[int]bool // which panels have been loaded

	panels []panel
	active int

	dialog   dialog
	connForm *connectForm

	status     string
	statusKind int // 0 info, 1 ok, 2 err

	w, h       int
	contentTop int
}

// messages
type (
	connResultMsg struct {
		cl    *client.Client
		ident string
		err   error
	}
	statusMsg struct {
		text string
		kind int
	}
)

func newApp(addr, password string, tlsOn bool) *app {
	a := &app{addr: addr, password: password, tlsOn: tlsOn, loaded: map[int]bool{}}
	a.panels = []panel{
		newBrowsePanel(),
		newReportsPanel(),
		newDatasetsPanel(),
		newControlsPanel(),
		newSettingsPanel(),
		newFilesPanel(),
		newLogsPanel(),
	}
	return a
}

func (a *app) Init() tea.Cmd {
	if a.addr != "" {
		return a.connect()
	}
	a.connForm = newConnectForm(a.addr, a.password, a.tlsOn)
	return nil
}

// connect dials the IED asynchronously.
func (a *app) connect() tea.Cmd {
	a.setStatus("connecting to "+a.addr+" ...", 0)
	addr, pw, tlsOn := a.addr, a.password, a.tlsOn
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		opts := []client.Option{client.WithTimeout(6 * time.Second)}
		if pw != "" {
			opts = append(opts, client.WithPassword(pw))
		}
		_ = tlsOn // TLS config wiring omitted from the demo UI
		c, err := client.Dial(ctx, addr, opts...)
		if err != nil {
			return connResultMsg{err: err}
		}
		vendor, model, rev, _ := c.MMS().Identify(ctx)
		ident := strings.TrimSpace(vendor + " " + model + " " + rev)
		return connResultMsg{cl: c, ident: ident}
	}
}

func (a *app) setStatus(text string, kind int) { a.status, a.statusKind = text, kind }

func (a *app) openDialog(d dialog) { a.dialog = d }

func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.w, a.h = msg.Width, msg.Height
		a.contentTop = 2
		return a, nil

	case connResultMsg:
		if msg.err != nil {
			a.setStatus("connect failed: "+msg.err.Error(), 2)
			if a.connForm == nil {
				a.connForm = newConnectForm(a.addr, a.password, a.tlsOn)
			}
			return a, nil
		}
		a.cl = msg.cl
		a.ident = msg.ident
		a.connected = true
		a.connForm = nil
		a.setStatus("connected to "+a.addr, 1)
		return a, a.loadActive()

	case statusMsg:
		a.setStatus(msg.text, msg.kind)
		return a, nil

	case tea.KeyMsg:
		if k := msg.String(); k == "ctrl+c" {
			return a, tea.Quit
		}
	}

	// Modal dialog captures everything while open.
	if a.dialog != nil {
		done, cmd := a.dialog.update(a, msg)
		if done {
			a.dialog = nil
		}
		return a, cmd
	}

	// Connection form when not connected.
	if !a.connected {
		if a.connForm == nil {
			return a, nil
		}
		cmd := a.connForm.update(a, msg)
		return a, cmd
	}

	// Connected: tabbed UI.
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return a, a.handleKey(msg)
	case tea.MouseMsg:
		return a, a.handleMouse(msg)
	default:
		// Forward other messages (async results) to the active panel.
		return a, a.panels[a.active].update(a, msg)
	}
}

func (a *app) handleKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "q":
		return tea.Quit
	case "tab", "]":
		a.active = (a.active + 1) % len(a.panels)
		return a.loadActive()
	case "shift+tab", "[":
		a.active = (a.active - 1 + len(a.panels)) % len(a.panels)
		return a.loadActive()
	case "1", "2", "3", "4", "5", "6", "7":
		i := int(msg.String()[0] - '1')
		if i < len(a.panels) {
			a.active = i
			return a.loadActive()
		}
	case "R":
		return a.panels[a.active].load(a)
	case "?":
		a.openDialog(newHelpDialog())
		return nil
	}
	return a.panels[a.active].update(a, msg)
}

func (a *app) loadActive() tea.Cmd {
	if a.loaded[a.active] {
		return nil
	}
	a.loaded[a.active] = true
	return a.panels[a.active].load(a)
}

func (a *app) handleMouse(m tea.MouseMsg) tea.Cmd {
	if tea.MouseEvent(m).IsWheel() {
		return a.panels[a.active].wheel(a, m.Button == tea.MouseButtonWheelUp)
	}
	if m.Action != tea.MouseActionPress || m.Button != tea.MouseButtonLeft {
		return nil
	}
	// Tab bar is row 1.
	if m.Y == 1 {
		for i, rng := range a.tabRanges() {
			if m.X >= rng[0] && m.X < rng[1] {
				a.active = i
				return a.loadActive()
			}
		}
		return nil
	}
	// Content area.
	if m.Y >= a.contentTop && m.Y < a.h-2 {
		return a.panels[a.active].click(a, m.X, m.Y-a.contentTop)
	}
	return nil
}

// tabRanges returns the [start,end) column of each tab label in the bar.
func (a *app) tabRanges() [][2]int {
	var out [][2]int
	x := 0
	for i, p := range a.panels {
		label := fmt.Sprintf(" %d %s ", i+1, p.title())
		out = append(out, [2]int{x, x + lipgloss.Width(label)})
		x += lipgloss.Width(label)
	}
	return out
}

func (a *app) View() string {
	if a.w == 0 {
		return "iedx: starting..."
	}
	if !a.connected {
		body := "iedx: not connected"
		if a.connForm != nil {
			body = a.connForm.view(a, a.w, a.h)
		}
		return a.overlay(body)
	}

	// Header.
	title := "iedx"
	if a.ident != "" {
		title = "iedx  ·  " + a.ident
	}
	header := styleHeader.Width(a.w).Render(title + "  ·  " + a.addr)

	// Tab bar.
	var tabs strings.Builder
	for i, p := range a.panels {
		label := fmt.Sprintf(" %d %s ", i+1, p.title())
		if i == a.active {
			tabs.WriteString(styleTabActive.Render(label))
		} else {
			tabs.WriteString(styleTab.Render(label))
		}
	}

	contentH := a.h - 4 // header, tabs, status, help
	if contentH < 1 {
		contentH = 1
	}
	content := a.panels[a.active].view(a, rect{w: a.w, h: contentH})
	content = lipgloss.NewStyle().Width(a.w).Height(contentH).MaxHeight(contentH).Render(content)

	// Status + help.
	statusStyle := styleStatus
	switch a.statusKind {
	case 1:
		statusStyle = styleStatusOK
	case 2:
		statusStyle = styleStatusErr
	}
	status := statusStyle.Width(a.w).Render(truncate(a.status, a.w))
	help := styleHelp.Width(a.w).Render(
		"tab/1-7 switch  R refresh  ? help  q quit  ·  mouse: click tabs & rows, wheel scrolls")

	screen := lipgloss.JoinVertical(lipgloss.Left, header, tabs.String(), content, status, help)
	return a.overlay(screen)
}

// overlay renders any active dialog centred over the screen.
func (a *app) overlay(base string) string {
	if a.dialog == nil {
		return base
	}
	dw, dh := a.w*2/3, a.h*2/3
	if dw < 40 {
		dw = min(a.w-4, 60)
	}
	box := a.dialog.view(a, dw, dh)
	return lipgloss.Place(a.w, a.h, lipgloss.Center, lipgloss.Center, box,
		lipgloss.WithWhitespaceChars(" "))
}

func truncate(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	if w <= 1 {
		return ""
	}
	return s[:w-1] + "…"
}
