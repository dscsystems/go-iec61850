package model

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
)

// The attribute tables are checked against the machine-readable form of
// IEC 61850-7-3, its NSD file (IEC_61850-7-3_2007B5.nsd for Edition 2.1).
// The file is an IEC code component under its own licence and is not part
// of this repository; point IEC61850_NSD_DIR at a directory holding it to
// run the check. OpenSCD publishes it with its editor.
//
// For every class in cdcTable the check requires:
//
//   - every attribute and sub-object of the template to exist in the NSD
//     class, under the same functional constraint (the SP variant, for a
//     setting class), of a compatible type, and an array exactly when the
//     NSD says so;
//   - every mandatory NSD attribute and sub-object to be in the template,
//     and not optional;
//   - no template attribute to be mandatory where the NSD makes it optional;
//   - the trigger options of every attribute to be the NSD's.

type nsdDoc struct {
	CDCs       []nsdCDC       `xml:"CDCs>CDC"`
	Constructs []nsdConstruct `xml:"ConstructedAttributes>ConstructedAttribute"`
}

type nsdCDC struct {
	Name    string       `xml:"name,attr"`
	Variant string       `xml:"variant,attr"`
	Items   []nsdElement `xml:",any"`
}

type nsdConstruct struct {
	Name    string       `xml:"name,attr"`
	Members []nsdElement `xml:"SubDataAttribute"`
}

type nsdElement struct {
	XMLName  xml.Name
	Name     string `xml:"name,attr"`
	FC       string `xml:"fc,attr"`
	Type     string `xml:"type,attr"`
	TypeKind string `xml:"typeKind,attr"`
	PresCond string `xml:"presCond,attr"`
	IsArray  bool   `xml:"isArray,attr"`
	Dchg     bool   `xml:"dchg,attr"`
	Qchg     bool   `xml:"qchg,attr"`
	Dupd     bool   `xml:"dupd,attr"`
}

func (e nsdElement) mandatory() bool {
	return e.PresCond == "M" || e.PresCond == "MAllOrNonePerGroup"
}

// mayBeMandatory reports whether a template may build the element by
// default: it is mandatory, or a member of a group of which at least one
// is present.
func (e nsdElement) mayBeMandatory() bool {
	return e.mandatory() || e.PresCond == "AtLeastOne" || e.PresCond == "AllAtLeastOneGroup"
}

func (e nsdElement) trgOps() TrgOps {
	var t TrgOps
	if e.Dchg {
		t |= TrgDataChange
	}
	if e.Qchg {
		t |= TrgQualityChange
	}
	if e.Dupd {
		t |= TrgDataUpdate
	}
	return t
}

// nsdKind is the MMS type IEC 61850-8-1 maps an NSD type to, and false for
// a type whose mapping the SCSM chooses (the "*" of GTS.dstAddress).
func nsdKind(e nsdElement) (mms.Type, bool) {
	switch e.TypeKind {
	case "CONSTRUCTED":
		return mms.TypeStructure, true
	case "ENUMERATED":
		switch e.Type {
		case "DpStatusKind", "StepControlKind":
			return mms.TypeBitString, true // coded enums in 8-1
		}
		return mms.TypeInteger, true
	case "undefined", "":
		if e.Type == "" || e.Type == "*" {
			return mms.TypeNone, false
		}
	}
	switch e.Type {
	case "BOOLEAN":
		return mms.TypeBoolean, true
	case "INT8", "INT16", "INT32", "INT64":
		return mms.TypeInteger, true
	case "INT8U", "INT16U", "INT32U":
		return mms.TypeUnsigned, true
	case "FLOAT32":
		return mms.TypeFloat32, true
	case "Timestamp":
		return mms.TypeUTCTime, true
	case "EntryTime":
		return mms.TypeBinaryTime, true
	case "Quality", "Check", "OptFlds", "SvOptFlds", "TrgOps":
		return mms.TypeBitString, true
	case "Octet64", "EntryID":
		return mms.TypeOctetString, true
	case "Unicode255":
		return mms.TypeMMSString, true
	case "PhyComAddr":
		return mms.TypeStructure, true
	}
	if strings.HasPrefix(e.Type, "VisString") || e.Type == "ObjRef" || e.Type == "Currency" {
		return mms.TypeVisibleString, true
	}
	return mms.TypeNone, false
}

// loadNSD reads the newest 7-3 NSD in IEC61850_NSD_DIR, and the
// constructed types of the 7-2 one (Originator is defined there).
func loadNSD(t *testing.T) *nsdDoc {
	dir := os.Getenv("IEC61850_NSD_DIR")
	if dir == "" {
		t.Skip("set IEC61850_NSD_DIR to a directory holding IEC_61850-7-3_2007B5.nsd " +
			"and IEC_61850-7-2_2007B5.nsd")
	}
	read := func(part string) *nsdDoc {
		matches, _ := filepath.Glob(filepath.Join(dir, "IEC_61850-"+part+"_*.nsd"))
		if len(matches) == 0 {
			t.Fatalf("no IEC_61850-%s_*.nsd in %s", part, dir)
		}
		sort.Strings(matches)
		raw, err := os.ReadFile(matches[len(matches)-1])
		if err != nil {
			t.Fatal(err)
		}
		var doc nsdDoc
		if err := xml.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		return &doc
	}
	doc := read("7-3")
	doc.Constructs = append(doc.Constructs, read("7-2").Constructs...)
	return doc
}

func TestCDCTablesMatchNSD(t *testing.T) {
	doc := loadNSD(t)
	classes := map[string]nsdCDC{}
	for _, c := range doc.CDCs {
		if c.Variant == "" || c.Variant == "SP" {
			classes[c.Name] = c
		}
	}
	constructs := map[string]nsdConstruct{}
	for _, c := range doc.Constructs {
		constructs[c.Name] = c
	}

	for cdc, sp := range cdcTable {
		nc, ok := classes[string(cdc)]
		if !ok {
			t.Errorf("%s: not a class of the NSD", cdc)
			continue
		}
		das := map[string]nsdElement{}
		sdos := map[string]nsdElement{}
		for _, it := range nc.Items {
			switch it.XMLName.Local {
			case "DataAttribute":
				das[it.Name] = it
			case "SubDataObject":
				sdos[it.Name] = it
			}
		}

		inTemplate := map[string]CDCAttribute{}
		for _, a := range sp.attrs {
			inTemplate[a.Name] = a
			e, ok := das[a.Name]
			if !ok {
				t.Errorf("%s.%s: not an attribute of the class", cdc, a.Name)
				continue
			}
			if e.FC != a.FC.String() {
				t.Errorf("%s.%s: FC %s, the NSD has %s", cdc, a.Name, a.FC, e.FC)
			}
			if e.IsArray != a.Array {
				t.Errorf("%s.%s: array %v, the NSD has %v", cdc, a.Name, a.Array, e.IsArray)
			}
			if a.ctlValSlot {
				continue // the type is the tracked control's
			}
			checkNSDType(t, string(cdc)+"."+a.Name, a, e, constructs)
			if !a.Optional && !e.mayBeMandatory() {
				t.Errorf("%s.%s: mandatory here, %s in the NSD", cdc, a.Name, e.PresCond)
			}
			var trg TrgOps
			if a.trgSet {
				trg = a.trg
			} else {
				trg = cdcTrgOps(a.Name, a.FC)
			}
			if trg != e.trgOps() {
				t.Errorf("%s.%s: trigger options %v, the NSD has %v", cdc, a.Name, trg, e.trgOps())
			}
		}
		for name, e := range das {
			if !e.mandatory() {
				continue
			}
			if name == "ctlModel" && sp.ctlVal != nil {
				continue // built with the control attributes
			}
			if a, ok := inTemplate[name]; !ok {
				t.Errorf("%s.%s: mandatory in the NSD, missing here", cdc, name)
			} else if a.Optional && a.allOrNone == "" {
				t.Errorf("%s.%s: mandatory in the NSD, optional here", cdc, name)
			}
		}

		subs := map[string]CDCSubObject{}
		for _, s := range sp.subObjects {
			subs[s.Name] = s
			e, ok := sdos[s.Name]
			if !ok {
				t.Errorf("%s.%s: not a sub-object of the class", cdc, s.Name)
				continue
			}
			if e.Type != string(s.CDC) {
				t.Errorf("%s.%s: class %s, the NSD has %s", cdc, s.Name, s.CDC, e.Type)
			}
			if e.IsArray != s.Array {
				t.Errorf("%s.%s: array %v, the NSD has %v", cdc, s.Name, s.Array, e.IsArray)
			}
			if !s.Optional && !e.mayBeMandatory() {
				t.Errorf("%s.%s: mandatory here, %s in the NSD", cdc, s.Name, e.PresCond)
			}
		}
		for name, e := range sdos {
			if s, ok := subs[name]; e.mandatory() && (!ok || s.Optional) {
				t.Errorf("%s.%s: mandatory sub-object in the NSD, missing or optional here", cdc, name)
			}
		}
	}
}

// checkNSDType compares the type of a template attribute with the NSD's,
// descending into constructed types.
func checkNSDType(t *testing.T, path string, a CDCAttribute, e nsdElement, constructs map[string]nsdConstruct) {
	t.Helper()
	want, known := nsdKind(e)
	if !known {
		return
	}
	got := a.Kind
	if got != want {
		t.Errorf("%s: type %v, the NSD has %s (%v)", path, got, e.Type, want)
		return
	}
	if want != mms.TypeStructure {
		return
	}
	if e.Type == "PhyComAddr" {
		return // the 8-1 structure; checked by the model tests
	}
	c, ok := constructs[e.Type]
	if !ok {
		t.Errorf("%s: constructed type %s not in the NSD", path, e.Type)
		return
	}
	members := map[string]nsdElement{}
	for _, m := range c.Members {
		members[m.Name] = m
	}
	have := map[string]bool{}
	for _, ch := range a.Children {
		have[ch.Name] = true
		m, ok := members[ch.Name]
		if !ok {
			t.Errorf("%s.%s: not a member of %s", path, ch.Name, e.Type)
			continue
		}
		checkNSDType(t, path+"."+ch.Name, ch, m, constructs)
	}
	for name, m := range members {
		if m.mandatory() && !have[name] {
			t.Errorf("%s.%s: mandatory member of %s, missing here", path, name, e.Type)
		}
	}
}

// The logical node classes are checked against the 7-4 NSD
// (IEC_61850-7-4_2007B5.nsd) in the same directory. A class there lists its
// own data objects and names the abstract class it extends (base); the
// data objects of a class are the union along that chain. For every class
// in lnClassTable the check requires:
//
//   - every data object of the template to exist in the NSD class, of the
//     same common data class, multi-instance exactly when the NSD says so,
//     and mandatory only where the NSD makes it mandatory;
//   - every data object the NSD makes unconditionally mandatory (M,
//     Mmulti) to be in the template and mandatory.

type nsd74Doc struct {
	Abstract []nsdLNClass `xml:"AbstractLNClasses>AbstractLNClass"`
	Classes  []nsdLNClass `xml:"LNClasses>LNClass"`
}

type nsdLNClass struct {
	Name    string          `xml:"name,attr"`
	Base    string          `xml:"base,attr"`
	Objects []nsdDataObject `xml:"DataObject"`
}

type nsdDataObject struct {
	Name     string `xml:"name,attr"`
	Type     string `xml:"type,attr"`
	PresCond string `xml:"presCond,attr"`
}

func TestLNClassTablesMatchNSD(t *testing.T) {
	dir := os.Getenv("IEC61850_NSD_DIR")
	if dir == "" {
		t.Skip("set IEC61850_NSD_DIR to a directory holding IEC_61850-7-4_2007B5.nsd")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "IEC_61850-7-4_*.nsd"))
	if len(matches) == 0 {
		t.Fatalf("no IEC_61850-7-4_*.nsd in %s", dir)
	}
	sort.Strings(matches)
	raw, err := os.ReadFile(matches[len(matches)-1])
	if err != nil {
		t.Fatal(err)
	}
	var doc nsd74Doc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	byName := map[string]nsdLNClass{}
	for _, c := range append(doc.Abstract, doc.Classes...) {
		byName[c.Name] = c
	}
	// objectsOf resolves the base chain; a class's own entry wins over an
	// inherited one of the same name.
	var objectsOf func(name string, depth int) map[string]nsdDataObject
	objectsOf = func(name string, depth int) map[string]nsdDataObject {
		c, ok := byName[name]
		if !ok || depth > 16 {
			return map[string]nsdDataObject{}
		}
		out := objectsOf(c.Base, depth+1)
		for _, o := range c.Objects {
			out[o.Name] = o
		}
		return out
	}

	for class, objs := range lnClassTable {
		if _, ok := byName[class]; !ok {
			t.Errorf("%s: not a class of the NSD", class)
			continue
		}
		nsdObjs := objectsOf(class, 0)
		inTemplate := map[string]LNObject{}
		for _, o := range objs {
			inTemplate[o.Name] = o
			n, ok := nsdObjs[o.Name]
			if !ok {
				t.Errorf("%s.%s: not a data object of the class", class, o.Name)
				continue
			}
			if n.Type != string(o.CDC) {
				t.Errorf("%s.%s: class %s, the NSD has %s", class, o.Name, o.CDC, n.Type)
			}
			if multi := strings.HasSuffix(n.PresCond, "multi"); multi != o.Multi {
				t.Errorf("%s.%s: multi %v, the NSD has %s", class, o.Name, o.Multi, n.PresCond)
			}
			if !o.Optional && n.PresCond != "M" && n.PresCond != "Mmulti" {
				t.Errorf("%s.%s: mandatory here, %s in the NSD", class, o.Name, n.PresCond)
			}
		}
		for name, n := range nsdObjs {
			if n.PresCond != "M" && n.PresCond != "Mmulti" {
				continue
			}
			if o, ok := inTemplate[name]; !ok || o.Optional {
				t.Errorf("%s.%s: mandatory in the NSD, missing or optional here", class, name)
			}
		}
	}
}
