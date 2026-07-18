package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type filesPanel struct {
	list    listbox
	entries []client.FileEntry
}

type filesLoadedMsg struct {
	entries []client.FileEntry
	err     error
}

func newFilesPanel() *filesPanel { return &filesPanel{} }

func (p *filesPanel) title() string { return "Files" }

func (p *filesPanel) load(a *app) tea.Cmd {
	c := a.cl
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		entries, err := c.FileDirectory(ctx, "")
		return filesLoadedMsg{entries: entries, err: err}
	}
}

func (p *filesPanel) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case filesLoadedMsg:
		if msg.err != nil {
			a.setStatus("file directory: "+msg.err.Error(), 2)
			return nil
		}
		p.entries = msg.entries
		a.setStatus(fmt.Sprintf("%d files", len(p.entries)), 1)
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			p.list.move(-1, len(p.entries))
		case "down", "j":
			p.list.move(1, len(p.entries))
		case "d", "enter":
			return p.download(a)
		}
	}
	return nil
}

func (p *filesPanel) download(a *app) tea.Cmd {
	if p.list.cursor < 0 || p.list.cursor >= len(p.entries) {
		return nil
	}
	name := p.entries[p.list.cursor].Name
	c := a.cl
	a.setStatus("downloading "+name+" ...", 0)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		data, err := c.ReadFile(ctx, name)
		if err != nil {
			return statusMsg{"download failed: " + err.Error(), 2}
		}
		out := filepath.Base(name)
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return statusMsg{"save failed: " + err.Error(), 2}
		}
		return statusMsg{fmt.Sprintf("saved %s (%d bytes) to ./%s", name, len(data), out), 1}
	}
}

func (p *filesPanel) click(a *app, x, y int) tea.Cmd {
	if p.list.clickRow(y-1, len(p.entries)) {
		return nil
	}
	return nil
}

func (p *filesPanel) wheel(a *app, up bool) tea.Cmd {
	if up {
		p.list.move(-1, len(p.entries))
	} else {
		p.list.move(1, len(p.entries))
	}
	return nil
}

func (p *filesPanel) view(a *app, r rect) string {
	innerH := r.h - 2
	list := p.list.render(len(p.entries), r.w-2, innerH, func(i int) string {
		e := p.entries[i]
		return fmt.Sprintf("%10d  %s  %s", e.Size,
			styleMuted.Render(e.LastModified.Format("2006-01-02 15:04")), e.Name)
	})
	box := stylePane.Width(r.w - 2).Height(innerH).Render(list)
	hint := styleHelp.Render("↑↓ select · d/enter download to the current directory")
	return lipgloss.JoinVertical(lipgloss.Left, box, hint)
}
