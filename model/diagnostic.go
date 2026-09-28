package model

import "fmt"

// Diagnostic is a non-fatal problem found while interpreting a data model.
//
// Interpretation is deliberately permissive: an unknown basic type, an
// unknown functional constraint or an unresolvable dataset member is
// recorded as a diagnostic and the model is still usable. One unrecognised
// construct must not make a whole IED unreadable — a vendor file or a newer
// SCL release is far more common than a schema change that actually
// matters, and a hard failure gives the operator nothing to work with.
type Diagnostic struct {
	// Path locates the construct, e.g. "IED1LD0/MMXU1.TotW.mag" or, while
	// parsing SCL, "SCL/IED[name=SIMPLE]/DataTypeTemplates".
	Path string
	// Message describes the problem in one line.
	Message string
}

func (d Diagnostic) String() string {
	if d.Path == "" {
		return d.Message
	}
	return d.Path + ": " + d.Message
}

// Addf returns a diagnostic with a formatted message.
func Addf(path, format string, args ...any) Diagnostic {
	return Diagnostic{Path: path, Message: fmt.Sprintf(format, args...)}
}
