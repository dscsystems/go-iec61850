package model

import (
	"fmt"
	"strings"
)

// ObjectReference is an IEC 61850 object reference of the form
// "LD/LN.DO[.DA...]" (e.g. "ied1LD0/GGIO1.AnIn1.mag.f"). The logical
// device part is the full MMS domain name (IED name + LD instance).
type ObjectReference string

// ParseRef validates s and returns it as an ObjectReference.
func ParseRef(s string) (ObjectReference, error) {
	r := ObjectReference(s)
	if err := r.Valid(); err != nil {
		return "", err
	}
	return r, nil
}

// Valid checks structural validity (one '/', non-empty components).
func (r ObjectReference) Valid() error {
	ld, rest, ok := strings.Cut(string(r), "/")
	if !ok || ld == "" || rest == "" {
		return fmt.Errorf("model: reference %q must be LD/LN.DO...", string(r))
	}
	for _, part := range strings.Split(rest, ".") {
		if part == "" {
			return fmt.Errorf("model: reference %q has empty component", string(r))
		}
	}
	return nil
}

// LD returns the logical device (MMS domain) part.
func (r ObjectReference) LD() string {
	ld, _, _ := strings.Cut(string(r), "/")
	return ld
}

// LN returns the logical node name.
func (r ObjectReference) LN() string {
	_, rest, ok := strings.Cut(string(r), "/")
	if !ok {
		return ""
	}
	ln, _, _ := strings.Cut(rest, ".")
	return ln
}

// Path returns the components after the LD: LN, DO, DA...
func (r ObjectReference) Path() []string {
	_, rest, ok := strings.Cut(string(r), "/")
	if !ok {
		return nil
	}
	return strings.Split(rest, ".")
}

// Parent returns the reference with the last component removed, or ""
// at the LN level.
func (r ObjectReference) Parent() ObjectReference {
	i := strings.LastIndexByte(string(r), '.')
	if i < 0 {
		return ""
	}
	return r[:i]
}

// Child returns the reference extended by one component.
func (r ObjectReference) Child(name string) ObjectReference {
	return r + ObjectReference("."+name)
}

func (r ObjectReference) String() string { return string(r) }

// ToMMS converts the reference plus FC to an MMS (domain, itemID) pair:
// "LD/LN.DO.DA" + MX becomes ("LD", "LN$MX$DO$DA").
func (r ObjectReference) ToMMS(fc FC) (domain, item string) {
	domain = r.LD()
	parts := r.Path()
	if len(parts) == 0 {
		return domain, ""
	}
	var sb strings.Builder
	sb.WriteString(parts[0])
	if fc != FCNone && fc != ALL {
		sb.WriteByte('$')
		sb.WriteString(fc.String())
	}
	for _, p := range parts[1:] {
		sb.WriteByte('$')
		sb.WriteString(p)
	}
	return domain, sb.String()
}

// FromMMS converts an MMS (domain, itemID) pair back to a reference and
// functional constraint. ItemIDs without an FC component (e.g. dataset
// entries in some servers) yield FCNone.
func FromMMS(domain, item string) (ObjectReference, FC) {
	parts := strings.Split(item, "$")
	fc := FCNone
	var path []string
	for i, p := range parts {
		if i == 1 {
			if f, err := ParseFC(p); err == nil {
				fc = f
				continue
			}
		}
		path = append(path, p)
	}
	return ObjectReference(domain + "/" + strings.Join(path, ".")), fc
}
