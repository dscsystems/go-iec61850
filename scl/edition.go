package scl

import (
	"fmt"
	"strings"
)

// Edition identifies which release of IEC 61850-6 a document was written
// against, from its SCL namespace version, revision and release
// attributes (IEC 61850-6 clause 1.2).
//
// The element names of a document are matched by local name, so every
// edition parses; the edition matters for interpreting the attributes whose
// meaning or presence changed, and for reporting a file this library
// cannot fully understand.
type Edition struct {
	// Namespace is the SCL namespace URI. All published editions share
	// "http://www.iec.ch/61850/2003/SCL"; a different URI is a vendor
	// schema.
	Namespace string
	Version   string // "2003" (Ed 1) or "2007" (Ed 2 and later)
	Revision  string // "A" (Ed 1), "B" (Ed 2.0), "C" (Ed 2.2)
	Release   string // SCL schema release, e.g. "4" for 2007B4
}

// known lists the published SCL namespaces and their version attributes.
var knownEditions = []struct {
	ns                         string
	version, revision, release string
}{
	{"http://www.iec.ch/61850/2003/SCL", "2003", "A", ""},
	{"http://www.iec.ch/61850/2003/SCL", "2007", "B", ""},
	{"http://www.iec.ch/61850/2003/SCL", "2007", "B", "1"},
	{"http://www.iec.ch/61850/2003/SCL", "2007", "B", "2"},
	{"http://www.iec.ch/61850/2003/SCL", "2007", "B", "3"},
	{"http://www.iec.ch/61850/2003/SCL", "2007", "B", "4"},
	{"http://www.iec.ch/61850/2003/SCL", "2007", "C", "5"},
}

// String renders the edition as "2007B4", the identifier used in the SCL
// conformance literature, or the raw version when it matches no known one.
func (e Edition) String() string {
	v := e.Version
	if v == "" {
		return "unknown"
	}
	return v + strings.ToUpper(e.Revision) + e.Release
}

// Known reports whether the edition is one this library has seen. A
// document that declares no version at all — which some tools emit, and
// which the Ed 1 fixture in testdata does — reports Known, because absent
// attributes are legal and the parser is permissive.
func (e Edition) Known() bool {
	if e.Version == "" {
		return true
	}
	for _, k := range knownEditions {
		if e.Version == k.version && strings.EqualFold(e.Revision, k.revision) &&
			e.Release == k.release {
			return true
		}
	}
	return false
}

// IsEd1 reports whether the document declares the Edition 1 SCL (2003),
// whose data model and control blocks differ from Edition 2's.
func (e Edition) IsEd1() bool { return e.Version == "2003" }

// AtLeastEd2 reports whether the document is Edition 2 or later, the
// editions this library implements. Edition 1 files load, but with
// differences recorded as diagnostics.
func (e Edition) AtLeastEd2() bool { return e.Version == "2007" }

// validate checks the edition and returns the diagnostics worth reporting
// for it: a vendor namespace, or a version this library does not know.
func (e Edition) validate(path string) []string {
	if e.Namespace == "" {
		return nil
	}
	if e.Namespace != "http://www.iec.ch/61850/2003/SCL" {
		return []string{fmt.Sprintf("%s: SCL namespace %q is not the IEC 61850 one; "+
			"parsing by local element name", path, e.Namespace)}
	}
	if e.Known() {
		return nil
	}
	return []string{fmt.Sprintf("%s: SCL version %s revision %s release %s is not a "+
		"published IEC 61850-6 code component; parsing by local element name",
		path, e.Version, e.Revision, e.Release)}
}
