package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---- write dialog ----

type writeDialog struct {
	n     *node
	input textinput.Model
}

func newWriteDialog(n *node) *writeDialog {
	in := textinput.New()
	in.Focus()
	in.Width = 30
	switch n.kind {
	case mms.TypeBoolean:
		in.Placeholder = "true / false"
	case mms.TypeFloat32, mms.TypeFloat64:
		in.Placeholder = "number"
	default:
		in.Placeholder = "value"
	}
	return &writeDialog{n: n, input: in}
}

func (d *writeDialog) update(a *app, msg tea.Msg) (bool, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			return true, nil
		case "enter":
			v, err := parseValueForKind(d.n.kind, d.input.Value())
			if err != nil {
				a.setStatus("bad value: "+err.Error(), 2)
				return false, nil
			}
			return true, writeCmd(a.cl, d.n.ref, d.n.fc, v)
		}
	}
	var cmd tea.Cmd
	d.input, cmd = d.input.Update(msg)
	return false, cmd
}

func (d *writeDialog) view(a *app, w, h int) string {
	body := lipgloss.JoinVertical(lipgloss.Left,
		styleDialogTitle.Render("Write value"),
		"",
		styleMuted.Render(string(d.n.ref)+"  "+fcBadge(d.n.fc.String())+"  "+d.n.kind.String()),
		"",
		d.input.View(),
		"",
		styleHelp.Render("enter write · esc cancel"),
	)
	return styleDialog.Width(w).Render(body)
}

func writeCmd(c *client.Client, ref model.ObjectReference, fc model.FC, v *mms.Value) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Write(ctx, ref, fc, v); err != nil {
			return statusMsg{"write failed: " + err.Error(), 2}
		}
		return statusMsg{"wrote " + string(ref) + " = " + v.String(), 1}
	}
}

func parseValueForKind(kind mms.Type, s string) (*mms.Value, error) {
	switch kind {
	case mms.TypeBoolean:
		b, err := strconv.ParseBool(s)
		return mms.NewBool(b), err
	case mms.TypeInteger:
		n, err := strconv.ParseInt(s, 10, 64)
		return mms.NewInt64(n), err
	case mms.TypeUnsigned:
		n, err := strconv.ParseUint(s, 10, 32)
		return mms.NewUint32(uint32(n)), err
	case mms.TypeFloat32:
		f, err := strconv.ParseFloat(s, 32)
		return mms.NewFloat32(float32(f)), err
	case mms.TypeFloat64:
		f, err := strconv.ParseFloat(s, 64)
		return mms.NewFloat64(f), err
	case mms.TypeVisibleString, mms.TypeMMSString:
		return mms.NewVisibleString(s), nil
	default:
		return nil, fmt.Errorf("unsupported type %s", kind)
	}
}

// ---- control (operate) dialog ----

type controlDialog struct {
	ref       model.ObjectReference
	on        bool
	test      bool
	interlock bool
	synchro   bool
	ident     textinput.Model
	focus     int // 0 value 1 test 2 interlock 3 synchro 4 ident 5 operate
	confirm   bool
}

func newControlDialog(ref model.ObjectReference) *controlDialog {
	in := textinput.New()
	in.SetValue("iedx")
	in.Width = 20
	return &controlDialog{ref: ref, on: true, ident: in}
}

func (d *controlDialog) update(a *app, msg tea.Msg) (bool, tea.Cmd) {
	k, ok := msg.(tea.KeyMsg)
	if !ok {
		return false, nil
	}
	if d.confirm {
		switch k.String() {
		case "y", "enter":
			return true, operateCmd(a.cl, d.ref, d.on, d.test, d.interlock, d.synchro, d.ident.Value())
		default:
			d.confirm = false
		}
		return false, nil
	}
	switch k.String() {
	case "esc":
		return true, nil
	case "tab", "down":
		d.focus = (d.focus + 1) % 6
	case "shift+tab", "up":
		d.focus = (d.focus + 5) % 6
	case " ":
		switch d.focus {
		case 0:
			d.on = !d.on
		case 1:
			d.test = !d.test
		case 2:
			d.interlock = !d.interlock
		case 3:
			d.synchro = !d.synchro
		}
	case "enter":
		if d.focus == 5 {
			d.confirm = true
			return false, nil
		}
	}
	if d.focus == 4 {
		var cmd tea.Cmd
		d.ident.Focus()
		d.ident, cmd = d.ident.Update(msg)
		return false, cmd
	}
	d.ident.Blur()
	return false, nil
}

func (d *controlDialog) view(a *app, w, h int) string {
	check := func(b bool) string {
		if b {
			return styleValue.Render("[x]")
		}
		return "[ ]"
	}
	onOff := "OFF"
	if d.on {
		onOff = "ON"
	}
	row := func(i int, s string) string {
		if d.focus == i {
			return styleFieldActive.Render("▸ " + s)
		}
		return "  " + s
	}
	btn := styleBtn.Render("Operate")
	if d.focus == 5 {
		btn = styleBtnActive.Render("Operate")
	}
	if d.confirm {
		body := lipgloss.JoinVertical(lipgloss.Left,
			styleWarn.Render("⚠ Confirm operate"),
			"",
			"Operate "+styleAccent.Render(string(d.ref))+" = "+styleAccent.Render(onOff)+"?",
			styleMuted.Render("Real switchgear may be attached."),
			"",
			styleHelp.Render("y/enter confirm · any other key cancel"),
		)
		return styleDialog.Width(w).BorderForeground(colWarn).Render(body)
	}
	body := lipgloss.JoinVertical(lipgloss.Left,
		styleDialogTitle.Render("Operate control"),
		styleMuted.Render(string(d.ref)),
		"",
		row(0, "Value       "+styleValue.Render(onOff)+"  (space toggles)"),
		row(1, "Test        "+check(d.test)),
		row(2, "Interlock   "+check(d.interlock)),
		row(3, "Synchro     "+check(d.synchro)),
		row(4, "Originator  "+d.ident.View()),
		"",
		btn,
		"",
		styleHelp.Render("tab move · space toggle · enter operate · esc cancel"),
	)
	return styleDialog.Width(w).Render(body)
}

func operateCmd(c *client.Client, ref model.ObjectReference, on, test, interlock, synchro bool, ident string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		co, err := c.ControlFor(ctx, ref)
		if err != nil {
			return statusMsg{"control setup failed: " + err.Error(), 2}
		}
		opts := []client.ControlOption{
			client.WithOriginator(model.OrCatStationControl, ident),
			client.WithTest(test),
			client.WithInterlockCheck(interlock),
			client.WithSynchroCheck(synchro),
		}
		if err := co.Operate(ctx, mms.NewBool(on), opts...); err != nil {
			var ce *client.ControlError
			if errors.As(err, &ce) {
				return statusMsg{fmt.Sprintf("operate rejected (%s): %s", ce.Stage, ce.AddCause), 2}
			}
			return statusMsg{"operate failed: " + err.Error(), 2}
		}
		return statusMsg{fmt.Sprintf("operated %s = %v (%s)", ref, on, co.Model()), 1}
	}
}

// ---- help dialog ----

type helpDialog struct{}

func newHelpDialog() *helpDialog { return &helpDialog{} }

func (d *helpDialog) update(a *app, msg tea.Msg) (bool, tea.Cmd) {
	if _, ok := msg.(tea.KeyMsg); ok {
		return true, nil
	}
	if _, ok := msg.(tea.MouseMsg); ok {
		return true, nil
	}
	return false, nil
}

func (d *helpDialog) view(a *app, w, h int) string {
	body := lipgloss.JoinVertical(lipgloss.Left,
		styleDialogTitle.Render("iedx — keys"),
		"",
		"tab / shift+tab / 1-7   switch tab",
		"R                       refresh current tab",
		"↑ ↓ j k / wheel         move / scroll",
		"enter / space / click   expand or read",
		"r  read      w  write      o  operate",
		"a  auto-refresh          /  filter (Browse)",
		"e  enable report / GI    d  download (Files)",
		"?  this help             q  quit",
		"",
		styleHelp.Render("mouse: click tabs and rows, wheel to scroll"),
		styleHelp.Render("press any key to close"),
	)
	return styleDialog.Width(w).Render(body)
}
