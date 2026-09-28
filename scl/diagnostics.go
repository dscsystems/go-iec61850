package scl

import "github.com/dscsystems/go-iec61850/model"

// Diagnostic is a non-fatal problem found while parsing or building a
// model. It is the same type the model carries, so a diagnostic raised
// while loading an SCL file can be inspected on the resulting model.
type Diagnostic = model.Diagnostic

// Options control how strictly a document is interpreted. The zero value
// is permissive: unrecognised constructs are recorded as diagnostics and
// the model is still built.
type Options struct {
	// Strict turns diagnostics into a load error. Use it to fail a
	// configuration check on a document that is not fully understood,
	// for instance in a conformance test harness.
	Strict bool
	// OnWarn is called for each diagnostic as it is raised, for streaming
	// progress on a large document. It must not be nil-checked by the
	// caller: the loader never calls it when it is nil.
	OnWarn func(Diagnostic)
}

// diag collects diagnostics for one parse or build.
type diag struct {
	opts Options
	all  []Diagnostic
}

func (d *diag) add(path, message string) {
	if d == nil {
		return
	}
	dn := Diagnostic{Path: path, Message: message}
	d.all = append(d.all, dn)
	if d.opts.OnWarn != nil {
		d.opts.OnWarn(dn)
	}
}

func (d *diag) addf(path, format string, args ...any) {
	if d == nil {
		return
	}
	d.add(path, sprintf(format, args...))
}

// addAll appends bare messages reported against the document root.
func (d *diag) addAll(msgs []string) {
	for _, m := range msgs {
		d.add("SCL", m)
	}
}

// err returns the diagnostics as an error when strict, else nil.
func (d *diag) err() error {
	if d == nil || !d.opts.Strict || len(d.all) == 0 {
		return nil
	}
	lines := make([]string, 0, len(d.all))
	for _, dn := range d.all {
		lines = append(lines, dn.String())
	}
	return &Error{Diagnostics: d.all, msg: joinLines(lines)}
}
