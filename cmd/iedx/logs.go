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

type logsPanel struct {
	list    listbox
	refs    []model.ObjectReference
	entries []client.LogEntry
	window  time.Duration
}

type (
	logsLoadedMsg struct{ refs []model.ObjectReference }
	logQueriedMsg struct {
		entries []client.LogEntry
		err     error
	}
)

func newLogsPanel() *logsPanel { return &logsPanel{window: time.Hour} }

func (p *logsPanel) title() string { return "Logs" }

func (p *logsPanel) load(a *app) tea.Cmd {
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		lds, err := c.LogicalDevices(ctx)
		if err != nil {
			return statusMsg{"logs: " + err.Error(), 2}
		}
		var refs []model.ObjectReference
		for _, ld := range lds {
			found, _ := c.Browse(ctx, ld, client.ACSILCB)
			for _, e := range found {
				refs = append(refs, e.Ref)
			}
		}
		return logsLoadedMsg{refs}
	}
}

func (p *logsPanel) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case logsLoadedMsg:
		p.refs = msg.refs
		a.setStatus(fmt.Sprintf("%d logs", len(p.refs)), 1)
	case logQueriedMsg:
		if msg.err != nil {
			a.setStatus("query log: "+msg.err.Error(), 2)
			return nil
		}
		p.entries = msg.entries
		a.setStatus(fmt.Sprintf("%d log entries", len(p.entries)), 1)
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			p.list.move(-1, len(p.refs))
		case "down", "j":
			p.list.move(1, len(p.refs))
		case "enter", "r":
			return p.query(a)
		case "+":
			p.window *= 2
		case "-":
			if p.window > time.Minute {
				p.window /= 2
			}
		}
	}
	return nil
}

func (p *logsPanel) query(a *app) tea.Cmd {
	if p.list.cursor < 0 || p.list.cursor >= len(p.refs) {
		return nil
	}
	ref := p.refs[p.list.cursor]
	c := a.cl
	win := p.window
	a.setStatus("querying "+string(ref)+" ...", 0)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		entries, err := c.QueryLogByTime(ctx, ref, time.Now().Add(-win), time.Now())
		return logQueriedMsg{entries: entries, err: err}
	}
}

func (p *logsPanel) click(a *app, x, y int) tea.Cmd {
	leftW := a.w * 2 / 5
	if x < leftW && p.list.clickRow(y-1, len(p.refs)) {
		return p.query(a)
	}
	return nil
}

func (p *logsPanel) wheel(a *app, up bool) tea.Cmd {
	if up {
		p.list.move(-1, len(p.refs))
	} else {
		p.list.move(1, len(p.refs))
	}
	return nil
}

func (p *logsPanel) view(a *app, r rect) string {
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
	right.WriteString(styleMuted.Render(fmt.Sprintf("window: last %s (+/- to change)", p.window)) + "\n\n")
	if len(p.entries) == 0 {
		right.WriteString(styleMuted.Render("select a log and press enter to query"))
	}
	for _, e := range p.entries {
		right.WriteString(fmt.Sprintf("%s  %s\n",
			styleMuted.Render(e.OccurrenceTime.Format("15:04:05")), styleAccent.Render(fmt.Sprintf("%x", e.EntryID))))
		for _, v := range e.Variables {
			right.WriteString(fmt.Sprintf("    %s = %s\n", v.Tag, styleValue.Render(v.Value.String())))
		}
	}

	body := twoPane(left, right.String(), leftW, rightW, innerH)
	hint := styleHelp.Render("↑↓ select · enter/r query · +/- window")
	return lipgloss.JoinVertical(lipgloss.Left, body, hint)
}
