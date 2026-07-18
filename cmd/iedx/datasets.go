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

type datasetsPanel struct {
	list listbox
	refs []model.ObjectReference
	ds   *client.DataSet
}

type (
	datasetsLoadedMsg struct{ refs []model.ObjectReference }
	datasetReadMsg    struct {
		ds  *client.DataSet
		err error
	}
)

func newDatasetsPanel() *datasetsPanel { return &datasetsPanel{} }

func (p *datasetsPanel) title() string { return "Datasets" }

func (p *datasetsPanel) load(a *app) tea.Cmd {
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		lds, err := c.LogicalDevices(ctx)
		if err != nil {
			return statusMsg{"datasets: " + err.Error(), 2}
		}
		var refs []model.ObjectReference
		for _, ld := range lds {
			names, _ := c.MMS().GetNameList(ctx, 2, ld) // named variable lists
			for _, n := range names {
				ln, ds, ok := strings.Cut(n, "$")
				if ok {
					refs = append(refs, model.ObjectReference(ld+"/"+ln+"."+ds))
				}
			}
		}
		return datasetsLoadedMsg{refs}
	}
}

func (p *datasetsPanel) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case datasetsLoadedMsg:
		p.refs = msg.refs
		a.setStatus(fmt.Sprintf("%d datasets", len(p.refs)), 1)
	case datasetReadMsg:
		if msg.err != nil {
			a.setStatus("read dataset: "+msg.err.Error(), 2)
			return nil
		}
		p.ds = msg.ds
		a.setStatus(fmt.Sprintf("%s: %d members", msg.ds.Ref, len(msg.ds.Members)), 1)
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			p.list.move(-1, len(p.refs))
		case "down", "j":
			p.list.move(1, len(p.refs))
		case "enter", "r":
			return p.read(a)
		}
	}
	return nil
}

func (p *datasetsPanel) read(a *app) tea.Cmd {
	if p.list.cursor < 0 || p.list.cursor >= len(p.refs) {
		return nil
	}
	ref := p.refs[p.list.cursor]
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ds, err := c.ReadDataSet(ctx, ref)
		return datasetReadMsg{ds: ds, err: err}
	}
}

func (p *datasetsPanel) click(a *app, x, y int) tea.Cmd {
	leftW := a.w * 2 / 5
	if x < leftW && p.list.clickRow(y-1, len(p.refs)) {
		return p.read(a)
	}
	return nil
}

func (p *datasetsPanel) wheel(a *app, up bool) tea.Cmd {
	if up {
		p.list.move(-1, len(p.refs))
	} else {
		p.list.move(1, len(p.refs))
	}
	return nil
}

func (p *datasetsPanel) view(a *app, r rect) string {
	leftW := r.w * 2 / 5
	if leftW < 32 {
		leftW = 32
	}
	rightW := r.w - leftW - 1
	innerH := r.h - 2

	left := p.list.render(len(p.refs), leftW-2, innerH, func(i int) string {
		return string(p.refs[i])
	})

	var right strings.Builder
	if p.ds == nil {
		right.WriteString(styleMuted.Render("select a dataset and press enter"))
	} else {
		right.WriteString(styleSel.Render(string(p.ds.Ref)) + "\n\n")
		for _, m := range p.ds.Members {
			right.WriteString(fmt.Sprintf("%s %s = %s\n",
				m.Ref, fcBadge(m.FC.String()), styleValue.Render(m.Value.String())))
		}
	}

	body := twoPane(left, right.String(), leftW, rightW, innerH)
	hint := styleHelp.Render("↑↓ select · enter/r read dataset")
	return lipgloss.JoinVertical(lipgloss.Left, body, hint)
}
