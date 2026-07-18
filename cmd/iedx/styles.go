package main

import "github.com/charmbracelet/lipgloss"

// Adaptive colours so the UI is legible on light and dark terminals.
var (
	colAccent   = lipgloss.AdaptiveColor{Light: "#0550ae", Dark: "#58a6ff"}
	colOK       = lipgloss.AdaptiveColor{Light: "#116329", Dark: "#3fb950"}
	colWarn     = lipgloss.AdaptiveColor{Light: "#9a6700", Dark: "#d29922"}
	colErr      = lipgloss.AdaptiveColor{Light: "#cf222e", Dark: "#f85149"}
	colMuted    = lipgloss.AdaptiveColor{Light: "#57606a", Dark: "#8b949e"}
	colBorder   = lipgloss.AdaptiveColor{Light: "#d0d7de", Dark: "#30363d"}
	colSelBg    = lipgloss.AdaptiveColor{Light: "#0969da", Dark: "#1f6feb"}
	colSelFg    = lipgloss.AdaptiveColor{Light: "#ffffff", Dark: "#ffffff"}
	colHeaderBg = lipgloss.AdaptiveColor{Light: "#0969da", Dark: "#1f6feb"}
)

var (
	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(colSelFg).Background(colHeaderBg).Padding(0, 1)

	styleTab       = lipgloss.NewStyle().Padding(0, 2).Foreground(colMuted)
	styleTabActive = lipgloss.NewStyle().Padding(0, 2).Bold(true).Foreground(colSelFg).Background(colSelBg)

	styleStatus    = lipgloss.NewStyle().Foreground(colMuted)
	styleStatusOK  = lipgloss.NewStyle().Foreground(colOK)
	styleStatusErr = lipgloss.NewStyle().Foreground(colErr)

	styleHelp = lipgloss.NewStyle().Faint(true)

	styleCursor = lipgloss.NewStyle().Foreground(colSelFg).Background(colSelBg)
	styleSel    = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleValue  = lipgloss.NewStyle().Foreground(colOK)
	styleMuted  = lipgloss.NewStyle().Foreground(colMuted)
	styleAccent = lipgloss.NewStyle().Foreground(colAccent)
	styleErr    = lipgloss.NewStyle().Foreground(colErr)
	styleWarn   = lipgloss.NewStyle().Foreground(colWarn)

	stylePane = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colBorder)

	styleDialog = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colAccent).
			Padding(1, 2)

	styleDialogTitle = lipgloss.NewStyle().Bold(true).Foreground(colAccent)

	styleBtn       = lipgloss.NewStyle().Padding(0, 2).Foreground(colMuted).Border(lipgloss.RoundedBorder()).BorderForeground(colBorder)
	styleBtnActive = lipgloss.NewStyle().Padding(0, 2).Bold(true).Foreground(colSelFg).Background(colSelBg).Border(lipgloss.RoundedBorder()).BorderForeground(colSelBg)

	styleField       = lipgloss.NewStyle().Foreground(colMuted)
	styleFieldActive = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
)

// fcBadge colours a functional-constraint badge.
func fcBadge(fc string) string {
	return styleMuted.Render("[" + fc + "]")
}
