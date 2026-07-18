package main

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// listbox is a reusable vertical selection list with scrolling, used by
// several panels.
type listbox struct {
	cursor int
	top    int
	count  int
}

func (l *listbox) clamp() {
	if l.cursor >= l.count {
		l.cursor = l.count - 1
	}
	if l.cursor < 0 {
		l.cursor = 0
	}
}

func (l *listbox) move(delta, count int) {
	l.count = count
	l.cursor += delta
	l.clamp()
}

// clickRow maps a panel-relative y (0-based, first row is the list's first
// item) to an index, selecting it. Returns true if a row was hit.
func (l *listbox) clickRow(y, count int) bool {
	l.count = count
	idx := l.top + y
	if idx < 0 || idx >= count {
		return false
	}
	l.cursor = idx
	return true
}

// render draws count rows using row(i) -> string, highlighting the cursor,
// within width w and height h.
func (l *listbox) render(count, w, h int, row func(i int) string) string {
	l.count = count
	l.clamp()
	if l.cursor < l.top {
		l.top = l.cursor
	}
	if l.cursor >= l.top+h {
		l.top = l.cursor - h + 1
	}
	if l.top < 0 {
		l.top = 0
	}
	var b strings.Builder
	end := l.top + h
	if end > count {
		end = count
	}
	for i := l.top; i < end; i++ {
		line := clipANSI(row(i), w)
		if i == l.cursor {
			line = styleCursor.Width(w).Render(clipANSI(row(i), w))
		}
		b.WriteString(line + "\n")
	}
	if count == 0 {
		b.WriteString(styleMuted.Render("(nothing here)"))
	}
	return b.String()
}

// twoPane lays out a left list and a right detail box with borders.
func twoPane(left, right string, leftW, rightW, h int) string {
	lb := stylePane.Width(leftW - 2).Height(h).Render(left)
	rb := stylePane.Width(rightW - 2).Height(h).Render(right)
	return lipgloss.JoinHorizontal(lipgloss.Top, lb, " ", rb)
}
