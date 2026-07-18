package main

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// connectForm is the initial connection screen: address, password and a
// TLS toggle, navigable by keyboard or mouse.
type connectForm struct {
	addr  textinput.Model
	pass  textinput.Model
	tlsOn bool
	focus int // 0 addr, 1 pass, 2 tls, 3 connect button
}

func newConnectForm(addr, pass string, tlsOn bool) *connectForm {
	a := textinput.New()
	a.Placeholder = "host:port"
	a.SetValue(addr)
	a.Focus()
	a.Width = 30
	p := textinput.New()
	p.Placeholder = "(optional)"
	p.SetValue(pass)
	p.EchoMode = textinput.EchoPassword
	p.Width = 30
	return &connectForm{addr: a, pass: p, tlsOn: tlsOn}
}

func (f *connectForm) setFocus(i int) {
	f.focus = (i + 4) % 4
	f.addr.Blur()
	f.pass.Blur()
	switch f.focus {
	case 0:
		f.addr.Focus()
	case 1:
		f.pass.Focus()
	}
}

func (f *connectForm) submit(a *app) tea.Cmd {
	a.addr = f.addr.Value()
	a.password = f.pass.Value()
	a.tlsOn = f.tlsOn
	if a.addr == "" {
		a.setStatus("enter an address", 2)
		return nil
	}
	return a.connect()
}

func (f *connectForm) update(a *app, msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return tea.Quit
		case "tab", "down":
			f.setFocus(f.focus + 1)
			return nil
		case "shift+tab", "up":
			f.setFocus(f.focus - 1)
			return nil
		case "enter":
			if f.focus == 2 {
				f.tlsOn = !f.tlsOn
				return nil
			}
			return f.submit(a)
		case " ":
			if f.focus == 2 {
				f.tlsOn = !f.tlsOn
				return nil
			}
		}
	case tea.MouseMsg:
		if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
			// Rough vertical hit testing against the form layout.
			switch {
			case msg.Y >= 5 && msg.Y <= 6:
				f.setFocus(0)
			case msg.Y >= 7 && msg.Y <= 8:
				f.setFocus(1)
			case msg.Y == 9 || msg.Y == 10:
				f.setFocus(2)
				f.tlsOn = !f.tlsOn
			case msg.Y >= 11:
				return f.submit(a)
			}
			return nil
		}
	}
	var cmd tea.Cmd
	switch f.focus {
	case 0:
		f.addr, cmd = f.addr.Update(msg)
	case 1:
		f.pass, cmd = f.pass.Update(msg)
	}
	return cmd
}

func (f *connectForm) view(a *app, w, h int) string {
	label := func(i int, s string) string {
		if f.focus == i {
			return styleFieldActive.Render("▸ " + s)
		}
		return styleField.Render("  " + s)
	}
	tls := "[ ] off"
	if f.tlsOn {
		tls = "[x] on"
	}
	btn := styleBtn.Render("Connect")
	if f.focus == 3 {
		btn = styleBtnActive.Render("Connect")
	}

	body := lipgloss.JoinVertical(lipgloss.Left,
		styleDialogTitle.Render("Connect to an IED"),
		"",
		label(0, "Address"),
		"  "+f.addr.View(),
		label(1, "Password"),
		"  "+f.pass.View(),
		label(2, "TLS (62351-3)")+"  "+styleValue.Render(tls),
		"",
		btn,
		"",
		styleHelp.Render("tab/↑↓ move · enter connect · space toggle TLS · esc quit"),
	)
	box := styleDialog.Render(body)
	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, box)
}
