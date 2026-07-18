package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/model"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type controlsPanel struct {
	list listbox
	refs []model.ObjectReference
}

type controlsLoadedMsg struct{ refs []model.ObjectReference }

func newControlsPanel() *controlsPanel { return &controlsPanel{} }

func (p *controlsPanel) title() string { return "Controls" }

func (p *controlsPanel) load(a *app) tea.Cmd {
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		lds, err := c.LogicalDevices(ctx)
		if err != nil {
			return statusMsg{"controls: " + err.Error(), 2}
		}
		seen := map[string]bool{}
		var refs []model.ObjectReference
		for _, ld := range lds {
			names, _ := c.MMS().GetNameList(ctx, 0, ld)
			for _, n := range names {
				parts := strings.Split(n, "$")
				// LN$CO$DO$Oper marks a controllable object.
				if len(parts) >= 4 && parts[1] == "CO" && parts[len(parts)-1] == "Oper" {
					do := strings.Join(parts[2:len(parts)-1], ".")
					ref := ld + "/" + parts[0] + "." + do
					if !seen[ref] {
						seen[ref] = true
						refs = append(refs, model.ObjectReference(ref))
					}
				}
			}
		}
		return controlsLoadedMsg{refs}
	}
}

func (p *controlsPanel) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case controlsLoadedMsg:
		p.refs = msg.refs
		a.setStatus(fmt.Sprintf("%d controllable objects", len(p.refs)), 1)
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			p.list.move(-1, len(p.refs))
		case "down", "j":
			p.list.move(1, len(p.refs))
		case "enter", "o":
			if r, ok := p.selected(); ok {
				a.openDialog(newControlDialog(r))
			}
		}
	}
	return nil
}

func (p *controlsPanel) selected() (model.ObjectReference, bool) {
	if p.list.cursor >= 0 && p.list.cursor < len(p.refs) {
		return p.refs[p.list.cursor], true
	}
	return "", false
}

func (p *controlsPanel) click(a *app, x, y int) tea.Cmd {
	if p.list.clickRow(y-1, len(p.refs)) {
		if r, ok := p.selected(); ok {
			a.openDialog(newControlDialog(r))
		}
	}
	return nil
}

func (p *controlsPanel) wheel(a *app, up bool) tea.Cmd {
	if up {
		p.list.move(-1, len(p.refs))
	} else {
		p.list.move(1, len(p.refs))
	}
	return nil
}

func (p *controlsPanel) view(a *app, r rect) string {
	innerH := r.h - 2
	list := p.list.render(len(p.refs), r.w-2, innerH, func(i int) string {
		return styleAccent.Render("⚡ ") + string(p.refs[i])
	})
	box := stylePane.Width(r.w - 2).Height(innerH).Render(list)
	hint := styleHelp.Render("↑↓ select · enter/o operate (opens the operate dialog)")
	return lipgloss.JoinVertical(lipgloss.Left, box, hint)
}
