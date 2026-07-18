package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type node struct {
	label        string
	depth        int
	ref          model.ObjectReference
	fc           model.FC
	kind         mms.Type
	readable     bool
	writable     bool
	controllable bool
	expanded     bool
	children     []*node
	value        string
	valErr       bool
}

type browsePanel struct {
	roots   []*node
	visible []*node
	cursor  int
	top     int

	filtering bool
	filter    string

	auto    bool
	autoGen int
}

type (
	modelLoadedMsg struct {
		roots []*node
		err   error
	}
	valueMsg struct {
		target *node
		text   string
		err    error
	}
	autoTickMsg struct{ gen int }
)

func newBrowsePanel() *browsePanel { return &browsePanel{} }

func (p *browsePanel) title() string { return "Browse" }

func (p *browsePanel) load(a *app) tea.Cmd {
	a.setStatus("retrieving model...", 0)
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		m, err := c.RetrieveModel(ctx)
		if err != nil {
			return modelLoadedMsg{err: err}
		}
		return modelLoadedMsg{roots: buildTree(m)}
	}
}

func buildTree(m *model.Model) []*node {
	var roots []*node
	for _, ld := range m.Devices {
		ldn := &node{label: "LD " + ld.Name, depth: 0, expanded: true}
		for _, ln := range ld.Nodes {
			lnn := &node{label: "LN " + ln.Name, depth: 1}
			base := model.ObjectReference(ld.Name + "/" + ln.Name)
			for _, do := range ln.Objects {
				lnn.children = append(lnn.children, buildDO(base.Child(do.Name), do, do.Name, 2))
			}
			ldn.children = append(ldn.children, lnn)
		}
		roots = append(roots, ldn)
	}
	return roots
}

func buildDO(ref model.ObjectReference, do *model.DataObject, name string, depth int) *node {
	label := "DO " + name
	if do.CDC != "" {
		label += " " + styleMuted.Render("("+do.CDC+")")
	}
	n := &node{label: label, depth: depth, ref: ref}
	for _, fc := range do.FCs() {
		if fc == model.CO {
			n.controllable = true
		}
	}
	if n.controllable {
		n.label += " " + styleAccent.Render("⚡")
	}
	for _, a := range do.Attributes {
		n.children = append(n.children, buildDA(ref.Child(a.Name), a, depth+1))
	}
	for _, sub := range do.Objects {
		n.children = append(n.children, buildDO(ref.Child(sub.Name), sub, sub.Name, depth+1))
	}
	return n
}

func buildDA(ref model.ObjectReference, da *model.DataAttribute, depth int) *node {
	n := &node{
		label: da.Name + " " + fcBadge(da.FC.String()) + " " + styleMuted.Render(da.Kind.String()),
		depth: depth, ref: ref, fc: da.FC, kind: da.Kind,
	}
	if len(da.Children) == 0 {
		n.readable = true
		n.writable = da.FC == model.CF || da.FC == model.SP || da.FC == model.SE || da.FC == model.SV || da.FC == model.DC
	}
	for _, c := range da.Children {
		n.children = append(n.children, buildDA(ref.Child(c.Name), c, depth+1))
	}
	return n
}

func (p *browsePanel) rebuild() {
	p.visible = p.visible[:0]
	var walk func(ns []*node)
	walk = func(ns []*node) {
		for _, n := range ns {
			if p.filter == "" || nodeMatches(n, p.filter) {
				p.visible = append(p.visible, n)
			}
			if n.expanded || (p.filter != "" && len(n.children) > 0) {
				walk(n.children)
			}
		}
	}
	walk(p.roots)
	if p.cursor >= len(p.visible) {
		p.cursor = len(p.visible) - 1
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
}

func nodeMatches(n *node, filter string) bool {
	f := strings.ToLower(filter)
	if strings.Contains(strings.ToLower(string(n.ref)), f) || strings.Contains(strings.ToLower(n.label), f) {
		return true
	}
	for _, c := range n.children {
		if nodeMatches(c, filter) {
			return true
		}
	}
	return false
}

func (p *browsePanel) cur() *node {
	if p.cursor >= 0 && p.cursor < len(p.visible) {
		return p.visible[p.cursor]
	}
	return nil
}

func (p *browsePanel) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case modelLoadedMsg:
		if msg.err != nil {
			a.setStatus("model load failed: "+msg.err.Error(), 2)
			return nil
		}
		p.roots = msg.roots
		p.rebuild()
		a.setStatus(fmt.Sprintf("model loaded: %d logical devices", len(p.roots)), 1)
		return nil
	case valueMsg:
		if msg.err != nil {
			msg.target.value, msg.target.valErr = msg.err.Error(), true
		} else {
			msg.target.value, msg.target.valErr = msg.text, false
		}
		return nil
	case autoTickMsg:
		if !p.auto || msg.gen != p.autoGen {
			return nil
		}
		var cmds []tea.Cmd
		if n := p.cur(); n != nil && n.readable {
			cmds = append(cmds, p.read(a, n))
		}
		cmds = append(cmds, p.tick())
		return tea.Batch(cmds...)
	case tea.KeyMsg:
		return p.key(a, msg)
	}
	return nil
}

func (p *browsePanel) key(a *app, msg tea.KeyMsg) tea.Cmd {
	if p.filtering {
		switch msg.String() {
		case "enter", "esc":
			p.filtering = false
		case "backspace":
			if p.filter != "" {
				p.filter = p.filter[:len(p.filter)-1]
			}
			p.rebuild()
		default:
			if len(msg.String()) == 1 {
				p.filter += msg.String()
				p.rebuild()
			}
		}
		return nil
	}
	switch msg.String() {
	case "up", "k":
		if p.cursor > 0 {
			p.cursor--
		}
	case "down", "j":
		if p.cursor < len(p.visible)-1 {
			p.cursor++
		}
	case "home", "g":
		p.cursor = 0
	case "end", "G":
		p.cursor = len(p.visible) - 1
	case "enter", " ", "right", "l":
		if n := p.cur(); n != nil {
			if len(n.children) > 0 {
				n.expanded = !n.expanded
				p.rebuild()
			} else if n.readable {
				return p.read(a, n)
			}
		}
	case "left", "h":
		if n := p.cur(); n != nil && n.expanded {
			n.expanded = false
			p.rebuild()
		}
	case "r":
		if n := p.cur(); n != nil && n.readable {
			return p.read(a, n)
		}
	case "w":
		if n := p.cur(); n != nil && n.writable {
			a.openDialog(newWriteDialog(n))
		} else {
			a.setStatus("not a writable attribute", 2)
		}
	case "o":
		if n := p.cur(); n != nil && n.controllable {
			a.openDialog(newControlDialog(n.ref))
		} else {
			a.setStatus("not a controllable object", 2)
		}
	case "a":
		p.auto = !p.auto
		p.autoGen++
		if p.auto {
			a.setStatus("auto-refresh on", 1)
			return p.tick()
		}
		a.setStatus("auto-refresh off", 0)
	case "/":
		p.filtering = true
	}
	return nil
}

func (p *browsePanel) tick() tea.Cmd {
	gen := p.autoGen
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return autoTickMsg{gen: gen} })
}

func (p *browsePanel) read(a *app, n *node) tea.Cmd {
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		v, err := c.Read(ctx, n.ref, n.fc)
		if err != nil {
			return valueMsg{target: n, err: err}
		}
		return valueMsg{target: n, text: v.String()}
	}
}

func (p *browsePanel) click(a *app, x, y int) tea.Cmd {
	leftW := p.leftWidth(a.w)
	if x >= leftW {
		return nil // detail pane: no hit targets yet
	}
	row := y - 1 // account for top border
	idx := p.top + row
	if idx < 0 || idx >= len(p.visible) {
		return nil
	}
	p.cursor = idx
	n := p.cur()
	if n != nil && len(n.children) > 0 {
		n.expanded = !n.expanded
		p.rebuild()
	} else if n != nil && n.readable {
		return p.read(a, n)
	}
	return nil
}

func (p *browsePanel) wheel(a *app, up bool) tea.Cmd {
	if up {
		if p.cursor > 0 {
			p.cursor--
		}
	} else if p.cursor < len(p.visible)-1 {
		p.cursor++
	}
	return nil
}

func (p *browsePanel) leftWidth(w int) int {
	lw := w * 2 / 5
	if lw < 28 {
		lw = 28
	}
	if lw > w-20 {
		lw = w - 20
	}
	return lw
}

func (p *browsePanel) view(a *app, r rect) string {
	leftW := p.leftWidth(r.w)
	rightW := r.w - leftW - 1
	innerH := r.h - 2 // borders

	// Keep the cursor within the viewport.
	if p.cursor < p.top {
		p.top = p.cursor
	}
	if p.cursor >= p.top+innerH {
		p.top = p.cursor - innerH + 1
	}
	if p.top < 0 {
		p.top = 0
	}

	var tree strings.Builder
	end := p.top + innerH
	if end > len(p.visible) {
		end = len(p.visible)
	}
	for i := p.top; i < end; i++ {
		n := p.visible[i]
		marker := "  "
		if len(n.children) > 0 {
			if n.expanded {
				marker = "▾ "
			} else {
				marker = "▸ "
			}
		}
		line := strings.Repeat("  ", n.depth) + marker + n.label
		if n.value != "" {
			vs := styleValue
			if n.valErr {
				vs = styleErr
			}
			line += "  = " + vs.Render(clip(n.value, 16))
		}
		line = clipANSI(line, leftW-2)
		if i == p.cursor {
			line = styleCursor.Width(leftW - 2).Render(clipANSI(line, leftW-2))
		}
		tree.WriteString(line + "\n")
	}

	treeBox := stylePane.Width(leftW - 2).Height(innerH).Render(tree.String())
	detailBox := stylePane.Width(rightW - 2).Height(innerH).Render(p.detail(a, rightW-4))
	body := lipgloss.JoinHorizontal(lipgloss.Top, treeBox, " ", detailBox)

	hint := styleHelp.Render("↑↓ move · enter expand/read · r read · w write · o operate · a auto · / filter")
	if p.filtering {
		hint = styleAccent.Render("filter: " + p.filter + "▏  (enter/esc to finish)")
	} else if p.filter != "" {
		hint = styleMuted.Render("filter: " + p.filter + "  (/ to edit)")
	}
	return lipgloss.JoinVertical(lipgloss.Left, body, hint)
}

func (p *browsePanel) detail(a *app, w int) string {
	n := p.cur()
	if n == nil {
		return styleMuted.Render("no selection")
	}
	var b strings.Builder
	b.WriteString(styleSel.Render("Reference") + "\n")
	b.WriteString("  " + wrap(string(n.ref), w) + "\n\n")
	if n.fc != model.FCNone {
		b.WriteString(styleSel.Render("FC") + "  " + n.fc.String() + "    ")
		b.WriteString(styleSel.Render("Type") + "  " + n.kind.String() + "\n\n")
	}
	if n.readable {
		b.WriteString(styleSel.Render("Value") + "\n")
		if n.value == "" {
			b.WriteString("  " + styleMuted.Render("(press r to read)") + "\n")
		} else {
			vs := styleValue
			if n.valErr {
				vs = styleErr
			}
			b.WriteString("  " + vs.Render(wrap(n.value, w)) + "\n")
		}
		b.WriteString("\n")
	}
	var actions []string
	if n.readable {
		actions = append(actions, "r read")
	}
	if n.writable {
		actions = append(actions, "w write")
	}
	if n.controllable {
		actions = append(actions, "o operate")
	}
	if len(n.children) > 0 {
		actions = append(actions, "enter expand")
	}
	if len(actions) > 0 {
		b.WriteString(styleMuted.Render("actions: "+strings.Join(actions, " · ")) + "\n")
	}
	if p.auto {
		b.WriteString("\n" + styleOK().Render("● auto-refresh"))
	}
	return b.String()
}

func styleOK() lipgloss.Style { return lipgloss.NewStyle().Foreground(colOK) }

// helpers

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func clipANSI(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(s)
}

func wrap(s string, w int) string {
	if w < 8 {
		w = 8
	}
	return lipgloss.NewStyle().Width(w).Render(s)
}
