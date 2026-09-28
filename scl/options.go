package scl

import (
	"fmt"
	"strings"
)

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

func joinLines(lines []string) string { return strings.Join(lines, "\n") }

// Error reports a failure that terminated a parse or a build, carrying the
// diagnostics collected up to that point. A permissive load that succeeds
// never produces one; a Strict load produces one listing every diagnostic.
type Error struct {
	Diagnostics []Diagnostic
	msg         string
}

func (e *Error) Error() string { return "scl: " + e.msg }

// Option adjusts model instantiation.
type Option func(*buildOptions)

type buildOptions struct {
	ied  string
	ap   string
	opts Options
}

// ForIED selects the IED to instantiate; the default is the first IED in
// the document.
func ForIED(name string) Option { return func(o *buildOptions) { o.ied = name } }

// WithAccessPoint selects the access point of the chosen IED; the default
// is the first access point that contains a Server.
func WithAccessPoint(name string) Option { return func(o *buildOptions) { o.ap = name } }

// Strict makes a build fail when it raised any diagnostic, instead of
// returning a usable model. See Options.
func Strict(b bool) Option { return func(o *buildOptions) { o.opts.Strict = b } }

// OnWarn installs a callback invoked for each diagnostic as it is raised.
// See Options.
func OnWarn(fn func(Diagnostic)) Option {
	return func(o *buildOptions) { o.opts.OnWarn = fn }
}
