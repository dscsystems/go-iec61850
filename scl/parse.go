// Package scl parses IEC 61850-6 SCL files (ICD, CID, SCD, IID) with the
// standard library XML decoder and instantiates the runtime object model
// of the model package.
//
// The parser covers the common subset needed to configure a server or a
// GOOSE subscriber: IEDs with access points, servers, logical devices and
// nodes, data type templates, datasets, report/GOOSE/SV/log/setting-group
// control blocks, initial values (DOI/SDI/DAI) and the Communication
// section. Substation topology is decoded but not instantiated, and
// Services capabilities, KDC/certificate elements and private extensions
// are decoded loosely or ignored.
//
// Parsing is permissive by design. Element names are matched by local name,
// so any SCL namespace revision is accepted, and an unrecognised element,
// basic type or functional constraint is recorded as a Diagnostic rather
// than failing the load: one construct from a newer schema or a vendor
// extension must not make a whole IED unreadable. Use Strict to turn
// diagnostics into an error, and read the resulting model.Diagnostics to
// see what was not understood. See Edition for the version a document
// declares.
package scl

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Parse decodes an SCL document from r. It checks that the root element is
// SCL but does not validate against the XML schema. The edition the
// document declares is available from SCL.Edition, and the elements this
// package does not decode from SCL.Dropped.
func Parse(r io.Reader) (*SCL, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("scl: read: %w", err)
	}
	return ParseBytes(data)
}

// ParseFile decodes the SCL document at path.
func ParseFile(path string) (*SCL, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scl: %w", err)
	}
	s, err := ParseBytes(data)
	if err != nil {
		return nil, fmt.Errorf("scl: parse %s: %w", path, err)
	}
	return s, nil
}

// ParseBytes decodes an SCL document held in memory.
func ParseBytes(data []byte) (*SCL, error) {
	var s SCL
	if err := xml.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	s.drops = audit(data)
	return &s, nil
}

// SCL is the document root. Element matching is by local name, so any SCL
// namespace revision is accepted. See Edition.
type SCL struct {
	XMLName           xml.Name           `xml:"SCL"`
	Xmlns             string             `xml:"xmlns,attr"`
	Version           string             `xml:"version,attr"`
	Revision          string             `xml:"revision,attr"`
	Release           string             `xml:"release,attr"`
	Header            Header             `xml:"Header"`
	Communication     *Communication     `xml:"Communication"`
	Substations       []Substation       `xml:"Substation"`
	Lines             []Line             `xml:"Line"`
	Processes         []Process          `xml:"Process"`
	IEDs              []IED              `xml:"IED"`
	DataTypeTemplates *DataTypeTemplates `xml:"DataTypeTemplates"`

	// drops maps each element name present in the document that this
	// package does not decode to the paths it occurs at, filled in by
	// ParseBytes.
	drops map[string][]string
}

// Edition returns the SCL edition the document declares. Fields are empty
// for a document that states no version.
func (s *SCL) Edition() Edition {
	return Edition{
		Namespace: s.Xmlns,
		Version:   s.Version,
		Revision:  s.Revision,
		Release:   s.Release,
	}
}

// Dropped returns the elements present in the document that this package
// does not decode, as a mapping from element name to the paths it occurs
// at, sorted by name. A non-empty result is normal and not an error: a
// Substation section, a vendor private block and the Ed 2.1 elements the
// model does not need are all decoded-and-ignored on purpose. It is
// reported so a caller that cares about coverage can tell an intentional
// omission from an unrecognised construct, and — because dropping an
// element drops its subtree — can see what was lost with it.
func (s *SCL) Dropped() map[string][]string {
	out := make(map[string][]string, len(s.drops))
	for name, paths := range s.drops {
		p := append([]string(nil), paths...)
		sort.Strings(p)
		out[name] = p
	}
	return out
}

// DroppedNames returns the names of the elements this package does not
// decode, sorted. It is the convenient form when only the names matter.
func (s *SCL) DroppedNames() []string {
	out := make([]string, 0, len(s.drops))
	for n := range s.drops {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// declaredElements is the set of SCL child element names this package
// decodes, derived from the struct tags so the audit cannot drift from the
// decoder.
var declaredElements = deriveElementNames()

// deriveElementNames walks the SCL type graph and collects every element
// name bound by an xml struct tag.
func deriveElementNames() map[string]bool {
	out := map[string]bool{"SCL": true}
	seen := map[reflect.Type]bool{}

	var walk func(t reflect.Type, depth int)
	walk = func(t reflect.Type, depth int) {
		if t == nil || depth > 24 || seen[t] {
			return
		}
		seen[t] = true
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag, _, _ := strings.Cut(f.Tag.Get("xml"), ",")
			switch tag {
			case "", "-", "any", "chardata":
				// Not an element binding: a chardata or attribute
				// holder, or the XMLName of a nested type.
			default:
				out[tag] = true
			}
			ft := f.Type
			for ft.Kind() == reflect.Ptr || ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				walk(ft, depth+1)
			}
		}
	}
	walk(reflect.TypeOf(SCL{}), 0)
	return out
}

// audit walks the document and records the elements this package does not
// decode, with the path they sit at. Dropping an element drops its whole
// subtree, so the path is what makes a report actionable: "SubNetwork" is
// noise, "/SCL/Communication/SubNetwork" says the GOOSE addressing of every
// IED on the network is missing.
func audit(data []byte) map[string][]string {
	drops := map[string][]string{}
	dec := xml.NewDecoder(bytes.NewReader(data))
	var path []string
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			// Malformed input is reported by the real decode.
			return drops
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if !declaredElements[t.Name.Local] {
				p := "/" + strings.Join(append(path, t.Name.Local), "/")
				if len(path) >= maxAuditDepth {
					p += "..."
				}
				drops[t.Name.Local] = append(drops[t.Name.Local], p)
			}
			if depth < maxAuditDepth {
				path = append(path, t.Name.Local)
			}
			depth++
		case xml.EndElement:
			depth--
			if depth < len(path) {
				path = path[:len(path)-1]
			}
		}
	}
}

// maxAuditDepth bounds the recorded path, so a deeply nested or hostile
// document cannot make the audit allocate without limit.
const maxAuditDepth = 32
