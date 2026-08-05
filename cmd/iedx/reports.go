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

type rcbItem struct {
	ref      model.ObjectReference
	buffered bool
}

type reportsPanel struct {
	list    listbox
	rcbs    []rcbItem
	feed    []string
	sub     *client.ReportSubscription
	enabled model.ObjectReference
	ch      chan string
}

type (
	rcbsLoadedMsg    struct{ rcbs []rcbItem }
	reportLineMsg    string
	reportEnabledMsg struct {
		ref model.ObjectReference
		sub *client.ReportSubscription
		err error
	}
)

func newReportsPanel() *reportsPanel { return &reportsPanel{ch: make(chan string, 256)} }

func (p *reportsPanel) title() string { return "Reports" }

func (p *reportsPanel) load(a *app) tea.Cmd {
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		lds, err := c.LogicalDevices(ctx)
		if err != nil {
			return statusMsg{"reports: " + err.Error(), 2}
		}
		var rcbs []rcbItem
		for _, ld := range lds {
			found, _ := c.Browse(ctx, ld, client.ACSIURCB, client.ACSIBRCB)
			for _, e := range found {
				rcbs = append(rcbs, rcbItem{ref: e.Ref, buffered: e.Class == client.ACSIBRCB})
			}
		}
		return rcbsLoadedMsg{rcbs}
	}
}

func (p *reportsPanel) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case rcbsLoadedMsg:
		p.rcbs = msg.rcbs
		a.setStatus(fmt.Sprintf("%d report control blocks", len(p.rcbs)), 1)
		return nil
	case reportEnabledMsg:
		if msg.err != nil {
			a.setStatus("enable failed: "+msg.err.Error(), 2)
			return nil
		}
		p.sub = msg.sub
		p.enabled = msg.ref
		p.feed = append(p.feed, styleOK().Render("● enabled "+string(msg.ref)))
		a.setStatus("reporting enabled on "+string(msg.ref), 1)
		return p.listen()
	case reportLineMsg:
		p.feed = append(p.feed, string(msg))
		if len(p.feed) > 500 {
			p.feed = p.feed[len(p.feed)-500:]
		}
		return p.listen()
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			p.list.move(-1, len(p.rcbs))
		case "down", "j":
			p.list.move(1, len(p.rcbs))
		case "e", "enter":
			return p.enable(a)
		case "g":
			return p.gi(a)
		case "x":
			return p.disable(a)
		case "c":
			p.feed = nil
		}
	}
	return nil
}

func (p *reportsPanel) selected() (rcbItem, bool) {
	if p.list.cursor >= 0 && p.list.cursor < len(p.rcbs) {
		return p.rcbs[p.list.cursor], true
	}
	return rcbItem{}, false
}

func (p *reportsPanel) enable(a *app) tea.Cmd {
	rcb, ok := p.selected()
	if !ok {
		return nil
	}
	c := a.cl
	ch := p.ch
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		r, err := c.GetRCB(ctx, rcb.ref)
		if err != nil {
			return reportEnabledMsg{err: err}
		}
		r.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptDataSetName | model.OptConfRev
		r.TrgOps = model.TrgDataChange | model.TrgQualityChange | model.TrgGI
		sub, err := c.EnableReporting(ctx, r, func(rep *client.Report) {
			line := fmt.Sprintf("%s  %s seq=%d", time.Now().Format("15:04:05"), rep.RptID, rep.SeqNum)
			select {
			case ch <- line:
			default:
			}
			for _, e := range rep.Entries {
				select {
				case ch <- fmt.Sprintf("    %s = %s (%s)", e.Ref, e.Value, e.Reason):
				default:
				}
			}
		})
		if err != nil {
			return reportEnabledMsg{err: err}
		}
		_ = c.TriggerGI(ctx, r)
		return reportEnabledMsg{ref: rcb.ref, sub: sub}
	}
}

func (p *reportsPanel) gi(a *app) tea.Cmd {
	if p.enabled == "" {
		a.setStatus("enable a report first", 2)
		return nil
	}
	c := a.cl
	ref := p.enabled
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r, err := c.GetRCB(ctx, ref)
		if err == nil {
			err = c.TriggerGI(ctx, r)
		}
		if err != nil {
			return statusMsg{"GI failed: " + err.Error(), 2}
		}
		return statusMsg{"general interrogation sent", 1}
	}
}

func (p *reportsPanel) disable(a *app) tea.Cmd {
	if p.sub == nil {
		return nil
	}
	sub := p.sub
	p.sub, p.enabled = nil, ""
	return func() tea.Msg {
		sub.Disable(context.Background())
		return statusMsg{"reporting disabled", 0}
	}
}

func (p *reportsPanel) listen() tea.Cmd {
	ch := p.ch
	return func() tea.Msg { return reportLineMsg(<-ch) }
}

func (p *reportsPanel) click(a *app, x, y int) tea.Cmd {
	leftW := a.w * 2 / 5
	if x < leftW && p.list.clickRow(y-1, len(p.rcbs)) {
		return p.enable(a)
	}
	return nil
}

func (p *reportsPanel) wheel(a *app, up bool) tea.Cmd {
	if up {
		p.list.move(-1, len(p.rcbs))
	} else {
		p.list.move(1, len(p.rcbs))
	}
	return nil
}

func (p *reportsPanel) view(a *app, r rect) string {
	leftW := r.w * 2 / 5
	if leftW < 30 {
		leftW = 30
	}
	rightW := r.w - leftW - 1
	innerH := r.h - 2

	left := p.list.render(len(p.rcbs), leftW-2, innerH, func(i int) string {
		it := p.rcbs[i]
		tag := "URCB"
		if it.buffered {
			tag = "BRCB"
		}
		mark := "  "
		if it.ref == p.enabled {
			mark = styleOK().Render("● ")
		}
		return mark + string(it.ref) + " " + styleMuted.Render(tag)
	})

	// Feed pane shows the tail.
	feedStart := 0
	if len(p.feed) > innerH {
		feedStart = len(p.feed) - innerH
	}
	feed := strings.Join(p.feed[feedStart:], "\n")
	if feed == "" {
		feed = styleMuted.Render("select an RCB and press e to enable reporting")
	}

	body := twoPane(left, feed, leftW, rightW, innerH)
	hint := styleHelp.Render("↑↓ select · e enable+GI · g GI · x disable · c clear feed")
	return lipgloss.JoinVertical(lipgloss.Left, body, hint)
}
