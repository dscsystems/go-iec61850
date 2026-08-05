package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type settingsPanel struct {
	list listbox
	refs []model.ObjectReference
	sg   *client.SettingGroup
}

type (
	sgcbsLoadedMsg struct{ refs []model.ObjectReference }
	sgLoadedMsg    struct {
		sg  *client.SettingGroup
		err error
	}
)

func newSettingsPanel() *settingsPanel { return &settingsPanel{} }

func (p *settingsPanel) title() string { return "SetGroups" }

func (p *settingsPanel) load(a *app) tea.Cmd {
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		lds, err := c.LogicalDevices(ctx)
		if err != nil {
			return statusMsg{"setting groups: " + err.Error(), 2}
		}
		var refs []model.ObjectReference
		for _, ld := range lds {
			found, _ := c.Browse(ctx, ld, client.ACSISGCB)
			for _, e := range found {
				refs = append(refs, e.Ref)
			}
		}
		return sgcbsLoadedMsg{refs}
	}
}

func (p *settingsPanel) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case sgcbsLoadedMsg:
		p.refs = msg.refs
		if len(p.refs) == 0 {
			a.setStatus("no setting group control blocks", 0)
		} else {
			a.setStatus(fmt.Sprintf("%d setting group control blocks", len(p.refs)), 1)
			return p.readSG(a)
		}
	case sgLoadedMsg:
		if msg.err != nil {
			a.setStatus("read SGCB: "+msg.err.Error(), 2)
			return nil
		}
		p.sg = msg.sg
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			p.list.move(-1, len(p.refs))
			return p.readSG(a)
		case "down", "j":
			p.list.move(1, len(p.refs))
			return p.readSG(a)
		default:
			// Number keys 1-9 select the active setting group.
			if len(msg.String()) == 1 && msg.String()[0] >= '1' && msg.String()[0] <= '9' && p.sg != nil {
				return p.selectActive(a, uint8(msg.String()[0]-'0'))
			}
		}
	}
	return nil
}

func (p *settingsPanel) readSG(a *app) tea.Cmd {
	if p.list.cursor < 0 || p.list.cursor >= len(p.refs) {
		return nil
	}
	ref := p.refs[p.list.cursor]
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		sg, err := c.SettingGroups(ctx, ref)
		return sgLoadedMsg{sg: sg, err: err}
	}
}

func (p *settingsPanel) selectActive(a *app, g uint8) tea.Cmd {
	if g > p.sg.NumOfSG {
		a.setStatus(fmt.Sprintf("only %d setting groups", p.sg.NumOfSG), 2)
		return nil
	}
	sg := p.sg
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sg.SelectActiveSG(ctx, g); err != nil {
			return statusMsg{"select active SG: " + err.Error(), 2}
		}
		return statusMsg{fmt.Sprintf("active setting group = %d", g), 1}
	}
}

func (p *settingsPanel) click(a *app, x, y int) tea.Cmd {
	leftW := a.w * 2 / 5
	if x < leftW && p.list.clickRow(y-1, len(p.refs)) {
		return p.readSG(a)
	}
	return nil
}

func (p *settingsPanel) wheel(a *app, up bool) tea.Cmd {
	if up {
		p.list.move(-1, len(p.refs))
	} else {
		p.list.move(1, len(p.refs))
	}
	return p.readSG(a)
}

func (p *settingsPanel) view(a *app, r rect) string {
	leftW := r.w * 2 / 5
	if leftW < 30 {
		leftW = 30
	}
	rightW := r.w - leftW - 1
	innerH := r.h - 2

	left := p.list.render(len(p.refs), leftW-2, innerH, func(i int) string {
		return string(p.refs[i])
	})

	var right strings.Builder
	if p.sg == nil {
		right.WriteString(styleMuted.Render("select a setting group control block"))
	} else {
		right.WriteString(styleSel.Render(string(p.sg.Ref)) + "\n\n")
		right.WriteString(fmt.Sprintf("Number of groups : %s\n", styleValue.Render(fmt.Sprint(p.sg.NumOfSG))))
		right.WriteString(fmt.Sprintf("Active group     : %s\n", styleValue.Render(fmt.Sprint(p.sg.ActSG))))
		right.WriteString(fmt.Sprintf("Edit group       : %s\n", styleValue.Render(fmt.Sprint(p.sg.EditSG))))
		right.WriteString("\n" + styleMuted.Render("press 1-9 to activate that setting group"))
	}

	body := twoPane(left, right.String(), leftW, rightW, innerH)
	hint := styleHelp.Render("↑↓ select block · 1-9 activate group")
	return lipgloss.JoinVertical(lipgloss.Left, body, hint)
}
