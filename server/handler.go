package server

import (
	"errors"
	"strings"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Sentinel errors returned by write and control handlers, mapped to MMS
// DataAccessError codes.
var (
	ErrAccessDenied       = mms.AccessObjectAccessDenied
	ErrObjectValueInvalid = mms.AccessObjectValueInvalid
	ErrObjectNonExistent  = mms.AccessObjectNonExistent
)

// MMS confirmed service CHOICE tag numbers (mirrors the mms package).
const (
	svcStatus              = 0
	svcGetNameList         = 1
	svcIdentify            = 2
	svcRead                = 4
	svcWrite               = 5
	svcGetVariableAccess   = 6
	svcDefineNamedVarList  = 11
	svcGetNamedVarListAttr = 12
	svcDeleteNamedVarList  = 13
	svcFileOpen            = 72
	svcFileRead            = 73
	svcFileClose           = 74
	svcFileDirectory       = 77
)

type handler struct {
	s        *Server
	readConn *mms.ServerConn // set for the duration of a read request
}

func (h *handler) Handle(req *mms.Request) (*asn1.Element, error) {
	h.s.log.Debug("server: request", "service", req.Service, "bytes", len(req.Content))
	switch req.Service {
	case svcIdentify:
		return h.identity(), nil
	case svcGetNameList:
		return h.getNameList(req.Content)
	case svcRead:
		return h.read(req.Content, req.Conn)
	case svcWrite:
		return h.write(req.Content, req.Conn)
	case svcGetVariableAccess:
		return h.getVariableAccess(req.Content)
	case svcGetNamedVarListAttr:
		return h.getNVLAttrs(req.Content)
	case svcDefineNamedVarList:
		return h.defineNVL(req.Content)
	case svcDeleteNamedVarList:
		return h.deleteNVL(req.Content)
	default:
		if resp, err, handled := h.fileService(req); handled {
			return resp, err
		}
		return nil, &mms.ServiceError{Rejected: true, Class: 1, Code: 1} // unrecognized-service
	}
}

func (h *handler) identity() *asn1.Element {
	id := h.s.identity
	return asn1.Cons(asn1.ContextConstructed(svcIdentify),
		asn1.Prim(asn1.ContextPrimitive(0), []byte(id.Vendor)),
		asn1.Prim(asn1.ContextPrimitive(1), []byte(id.Model)),
		asn1.Prim(asn1.ContextPrimitive(2), []byte(id.Revision)),
	)
}

func (h *handler) getNameList(content []byte) (*asn1.Element, error) {
	dec := asn1.NewDecoder(content)
	// objectClass [0] { basicObjectClass [0] INTEGER }
	classContent, err := dec.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return nil, err
	}
	classBytes, err := asn1.NewDecoder(classContent).Expect(asn1.ContextPrimitive(0))
	if err != nil {
		return nil, err
	}
	class, _ := asn1.DecodeInt(classBytes)

	// objectScope [1] CHOICE { vmdSpecific [0] NULL, domainSpecific [1] Identifier }
	var domain string
	if scope, ok, _ := dec.Optional(asn1.ContextConstructed(1)); ok {
		sd := asn1.NewDecoder(scope)
		if d, ok, _ := sd.Optional(asn1.ContextPrimitive(1)); ok {
			domain = string(d)
		}
	}
	var after string
	if a, ok, _ := dec.Optional(asn1.ContextPrimitive(2)); ok {
		after = string(a)
	}

	h.s.mu.RLock()
	names := h.enumerate(int(class), domain)
	h.s.mu.RUnlock()

	// Apply continuation.
	if after != "" {
		for i, n := range names {
			if n == after {
				names = names[i+1:]
				break
			}
		}
	}
	// Cap the page; signal moreFollows if truncated.
	const pageMax = 100
	more := false
	if len(names) > pageMax {
		names = names[:pageMax]
		more = true
	}

	list := asn1.Cons(asn1.ContextConstructed(0))
	for _, n := range names {
		list.Add(asn1.Prim(asn1.TagVisibleString, []byte(n)))
	}
	resp := asn1.Cons(asn1.ContextConstructed(svcGetNameList), list)
	if more {
		resp.Add(asn1.BoolElem(asn1.ContextPrimitive(1), true))
	} else {
		resp.Add(asn1.BoolElem(asn1.ContextPrimitive(1), false))
	}
	return resp, nil
}

func (h *handler) enumerate(class int, domain string) []string {
	switch class {
	case 9: // domain
		var out []string
		for _, ld := range h.s.model.Devices {
			out = append(out, ld.Name)
		}
		return out
	case 0: // named variable
		ld := h.s.model.Device(domain)
		if ld == nil {
			return nil
		}
		return namesForDomain(ld)
	case 2: // named variable list (dataset)
		ld := h.s.model.Device(domain)
		if ld == nil {
			return nil
		}
		var out []string
		for _, ln := range ld.Nodes {
			for _, ds := range ln.DataSets {
				out = append(out, ln.Name+"$"+ds.Name)
			}
		}
		return out
	}
	return nil
}

func (h *handler) read(content []byte, conn *mms.ServerConn) (*asn1.Element, error) {
	h.readConn = conn
	dec := asn1.NewDecoder(content)
	// Optional specificationWithResult [0] BOOLEAN precedes the access
	// specification; libiec61850 sets it when reading datasets.
	if _, _, err := dec.Optional(asn1.ContextPrimitive(0)); err != nil {
		return nil, err
	}
	// variableAccessSpecification [1] EXPLICIT.
	vasContent, err := dec.Expect(asn1.ContextConstructed(1))
	if err != nil {
		return nil, err
	}
	vd := asn1.NewDecoder(vasContent)
	results := asn1.Cons(asn1.ContextConstructed(1)) // listOfAccessResult [1]

	if listContent, ok, _ := vd.Optional(asn1.ContextConstructed(0)); ok {
		// listOfVariable.
		ld := asn1.NewDecoder(listContent)
		h.s.mu.RLock()
		defer h.s.mu.RUnlock()
		for ld.More() {
			entry, err := ld.Expect(asn1.TagSequence)
			if err != nil {
				return nil, err
			}
			domain, item, err := h.parseVarSpec(entry)
			if err != nil {
				results.Add(accessFailure(mms.AccessObjectNonExistent))
				continue
			}
			results.Add(h.readOne(domain, item))
		}
	} else if nameContent, ok, _ := vd.Optional(asn1.ContextConstructed(1)); ok {
		// variableListName (dataset).
		domain, list, err := parseObjectName(nameContent)
		if err != nil {
			return nil, err
		}
		h.s.mu.RLock()
		defer h.s.mu.RUnlock()
		for _, entry := range h.datasetMembers(domain, list) {
			results.Add(h.readOne(entry.domain, entry.item))
		}
	} else {
		return nil, errors.New("server: unsupported read access specification")
	}
	return asn1.Cons(asn1.ContextConstructed(svcRead), results), nil
}

func (h *handler) readOne(domain, item string) *asn1.Element {
	ld := h.s.model.Device(domain)
	if ld == nil {
		return accessFailure(mms.AccessObjectNonExistent)
	}
	// Reading an "$SBO" attribute selects the control (SBO with normal
	// security): return the object reference on success, empty otherwise.
	if base, phase, ok := splitControl(item); ok && phase == "SBO" {
		ref := controlRef(domain, base)
		name := h.s.selectSBO(ref, h.readConn)
		return mms.DataElement(mms.NewVisibleString(name))
	}
	ln, itemRest := splitLN(ld, item)
	if ln == nil {
		return accessFailure(mms.AccessObjectNonExistent)
	}
	v, ok := resolveRead(ln, itemRest)
	if !ok {
		return accessFailure(mms.AccessObjectNonExistent)
	}
	return mms.DataElement(v)
}

func (h *handler) write(content []byte, conn *mms.ServerConn) (*asn1.Element, error) {
	dec := asn1.NewDecoder(content)
	// WriteRequest: variableAccessSpecification (untagged CHOICE), listOfData [0].
	listContent, err := dec.Expect(asn1.ContextConstructed(0)) // listOfVariable [0]
	if err != nil {
		return nil, err
	}
	dataContent, err := dec.Expect(asn1.ContextConstructed(0)) // listOfData [0]
	if err != nil {
		return nil, err
	}
	type target struct{ domain, item string }
	var targets []target
	ld := asn1.NewDecoder(listContent)
	for ld.More() {
		entry, err := ld.Expect(asn1.TagSequence)
		if err != nil {
			return nil, err
		}
		domain, item, err := h.parseVarSpec(entry)
		if err != nil {
			targets = append(targets, target{})
			continue
		}
		targets = append(targets, target{domain, item})
	}

	resp := asn1.Cons(asn1.ContextConstructed(svcWrite))
	dd := asn1.NewDecoder(dataContent)
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	for i := 0; dd.More(); i++ {
		v, err := mms.DecodeData(dd)
		if err != nil {
			return nil, err
		}
		if i >= len(targets) || targets[i].domain == "" {
			resp.Add(accessFailureWrite(mms.AccessObjectNonExistent))
			continue
		}
		// Control attribute writes (Oper/SBOw/Cancel) are handled specially.
		if handled, code := h.controlWrite(targets[i].domain, targets[i].item, v, conn); handled {
			if code != 0xff {
				resp.Add(accessFailureWrite(mms.DataAccessError(code)))
			} else {
				resp.Add(asn1.Prim(asn1.ContextPrimitive(1), nil))
			}
			continue
		}
		if code := h.writeOne(targets[i].domain, targets[i].item, v); code != 0xff {
			resp.Add(accessFailureWrite(mms.DataAccessError(code)))
			continue
		}
		resp.Add(asn1.Prim(asn1.ContextPrimitive(1), nil)) // success [1] NULL
		// Report control block side effects (RptEna, GI).
		if _, attr, ok := rcbKey(targets[i].domain, targets[i].item); ok {
			h.s.reports.onRCBWrite(targets[i].domain, targets[i].item, attr, v, conn)
		}
		// Setting group control block side effects (ActSG, EditSG, CnfEdit).
		if mgr := h.s.sgs[targets[i].domain]; mgr != nil {
			if attr, ok := isSGCBWrite(targets[i].item); ok {
				mgr.onSGCBWrite(attr, v)
			}
		}
	}
	return resp, nil
}

// writeOne applies a write and returns 0xff on success or a
// DataAccessError code on failure.
func (h *handler) writeOne(domain, item string, v *mms.Value) byte {
	ld := h.s.model.Device(domain)
	if ld == nil {
		return byte(mms.AccessObjectNonExistent)
	}
	ln, itemRest := splitLN(ld, item)
	if ln == nil {
		return byte(mms.AccessObjectNonExistent)
	}
	da, ok := resolveWrite(ln, itemRest, v)
	if !ok {
		return byte(mms.AccessObjectAccessUnsupported)
	}
	if h.s.writeH != nil {
		if err := h.s.writeH(da, v); err != nil {
			var dae mms.DataAccessError
			if errors.As(err, &dae) {
				return byte(dae)
			}
			return byte(mms.AccessObjectAccessDenied)
		}
	}
	da.Value = v
	return 0xff
}

func (h *handler) getVariableAccess(content []byte) (*asn1.Element, error) {
	dec := asn1.NewDecoder(content)
	nameContent, err := dec.Expect(asn1.ContextConstructed(0)) // name [0]
	if err != nil {
		return nil, err
	}
	domain, item, err := parseObjectName(nameContent)
	if err != nil {
		return nil, err
	}
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	ld := h.s.model.Device(domain)
	if ld == nil {
		return nil, mms.AccessObjectNonExistent
	}
	ln, itemRest := splitLN(ld, item)
	if ln == nil {
		return nil, mms.AccessObjectNonExistent
	}
	ts, ok := typeSpecFor(ln, itemRest)
	if !ok {
		return nil, mms.AccessObjectNonExistent
	}
	// Response: mmsDeletable [0] BOOLEAN, typeSpecification [2] EXPLICIT.
	return asn1.Cons(asn1.ContextConstructed(svcGetVariableAccess),
		asn1.BoolElem(asn1.ContextPrimitive(0), false),
		asn1.Cons(asn1.ContextConstructed(2), ts.BER()),
	), nil
}

func (h *handler) getNVLAttrs(content []byte) (*asn1.Element, error) {
	domain, list, err := parseObjectName(content)
	if err != nil {
		return nil, err
	}
	h.s.mu.RLock()
	defer h.s.mu.RUnlock()
	members := h.datasetMembers(domain, list)
	if members == nil {
		return nil, mms.AccessObjectNonExistent
	}
	varList := asn1.Cons(asn1.ContextConstructed(1)) // listOfVariable [1]
	for _, m := range members {
		varList.Add(asn1.Cons(asn1.TagSequence,
			asn1.Cons(asn1.ContextConstructed(0), // variableSpecification name [0]
				domainSpecificName(m.domain, m.item)),
		))
	}
	return asn1.Cons(asn1.ContextConstructed(svcGetNamedVarListAttr),
		asn1.BoolElem(asn1.ContextPrimitive(0), false), // mmsDeletable
		varList,
	), nil
}

// defineNVL creates a dynamic named variable list (dataset) from the
// request's member specifications.
func (h *handler) defineNVL(content []byte) (*asn1.Element, error) {
	dec := asn1.NewDecoder(content)
	domain, list, err := parseObjectNameElem(dec)
	if err != nil {
		return nil, err
	}
	lnName, dsName, ok := strings.Cut(list, "$")
	if !ok {
		return nil, mms.AccessObjectValueInvalid
	}
	listContent, err := dec.Expect(asn1.ContextConstructed(1)) // listOfVariable [1]
	if err != nil {
		return nil, err
	}
	var entries []model.FCDA
	ld := asn1.NewDecoder(listContent)
	for ld.More() {
		entry, err := ld.Expect(asn1.TagSequence)
		if err != nil {
			return nil, err
		}
		spec, err := asn1.NewDecoder(entry).Expect(asn1.ContextConstructed(0)) // variableSpecification name [0]
		if err != nil {
			return nil, err
		}
		md, mi, err := parseObjectName(spec)
		if err != nil {
			return nil, err
		}
		ref, fc := model.FromMMS(md, mi)
		entries = append(entries, model.FCDA{Ref: ref, FC: fc})
	}

	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	dev := h.s.model.Device(domain)
	if dev == nil {
		return nil, mms.AccessObjectNonExistent
	}
	ln := dev.Node(lnName)
	if ln == nil {
		return nil, mms.AccessObjectNonExistent
	}
	if ln.DataSet(dsName) != nil {
		return nil, mms.AccessObjectValueInvalid // already exists
	}
	ln.DataSets = append(ln.DataSets, &model.DataSet{Name: dsName, Entries: entries})
	// DefineNamedVariableList-Response ::= NULL.
	return asn1.Prim(asn1.ContextPrimitive(svcDefineNamedVarList), nil), nil
}

// deleteNVL removes a dynamic named variable list.
func (h *handler) deleteNVL(content []byte) (*asn1.Element, error) {
	dec := asn1.NewDecoder(content)
	// DeleteNamedVariableList-Request ::= SEQUENCE {
	//   scopeOfDelete [0] INTEGER DEFAULT specific,
	//   listOfVariableListName [1] SEQUENCE OF ObjectName OPTIONAL, ... }
	if _, _, err := dec.Optional(asn1.ContextPrimitive(0)); err != nil {
		return nil, err
	}
	matched, deleted := 0, 0
	if listContent, ok, _ := dec.Optional(asn1.ContextConstructed(1)); ok {
		h.s.mu.Lock()
		nd := asn1.NewDecoder(listContent)
		for nd.More() {
			domain, list, err := parseObjectNameElem(nd)
			if err != nil {
				break
			}
			matched++
			if h.deleteDataset(domain, list) {
				deleted++
			}
		}
		h.s.mu.Unlock()
	}
	// DeleteNamedVariableList-Response ::= SEQUENCE {
	//   numberMatched [0] Unsigned32, numberDeleted [1] Unsigned32 }
	return asn1.Cons(asn1.ContextConstructed(svcDeleteNamedVarList),
		asn1.UintElem(asn1.ContextPrimitive(0), uint64(matched)),
		asn1.UintElem(asn1.ContextPrimitive(1), uint64(deleted)),
	), nil
}

func (h *handler) deleteDataset(domain, list string) bool {
	dev := h.s.model.Device(domain)
	if dev == nil {
		return false
	}
	lnName, dsName, ok := strings.Cut(list, "$")
	if !ok {
		return false
	}
	ln := dev.Node(lnName)
	if ln == nil {
		return false
	}
	for i, ds := range ln.DataSets {
		if ds.Name == dsName {
			ln.DataSets = append(ln.DataSets[:i], ln.DataSets[i+1:]...)
			return true
		}
	}
	return false
}

type dsMember struct{ domain, item string }

func (h *handler) datasetMembers(domain, list string) []dsMember {
	ld := h.s.model.Device(domain)
	if ld == nil {
		return nil
	}
	lnName, dsName, ok := strings.Cut(list, "$")
	if !ok {
		return nil
	}
	ln := ld.Node(lnName)
	if ln == nil {
		return nil
	}
	ds := ln.DataSet(dsName)
	if ds == nil {
		return nil
	}
	var members []dsMember
	for _, e := range ds.Entries {
		d, item := e.Ref.ToMMS(e.FC)
		members = append(members, dsMember{d, item})
	}
	return members
}

// parseVarSpec extracts (domain, item) from a ListOfVariable entry.
func (h *handler) parseVarSpec(entry []byte) (string, string, error) {
	dec := asn1.NewDecoder(entry)
	specContent, err := dec.Expect(asn1.ContextConstructed(0)) // variableSpecification name [0]
	if err != nil {
		return "", "", err
	}
	return parseObjectName(specContent)
}

// parseObjectName decodes an ObjectName element (given its bytes) into
// (domain, item).
func parseObjectName(content []byte) (string, string, error) {
	return parseObjectNameElem(asn1.NewDecoder(content))
}

// parseObjectNameElem reads one ObjectName from dec (a CHOICE, so it
// appears directly as its alternative: domain-specific [1] or
// vmd-specific [0]).
func parseObjectNameElem(dec *asn1.Decoder) (string, string, error) {
	tag, c, err := dec.ReadTLV()
	if err != nil {
		return "", "", err
	}
	switch tag {
	case asn1.ContextConstructed(1): // domain-specific
		dd := asn1.NewDecoder(c)
		domain, err := dd.Expect(asn1.TagVisibleString)
		if err != nil {
			return "", "", err
		}
		item, err := dd.Expect(asn1.TagVisibleString)
		if err != nil {
			return "", "", err
		}
		return string(domain), string(item), nil
	case asn1.ContextPrimitive(0): // vmd-specific
		return "", string(c), nil
	default:
		return "", "", errors.New("server: unsupported ObjectName")
	}
}

func domainSpecificName(domain, item string) *asn1.Element {
	return asn1.Cons(asn1.ContextConstructed(1),
		asn1.Prim(asn1.TagVisibleString, []byte(domain)),
		asn1.Prim(asn1.TagVisibleString, []byte(item)),
	)
}

// splitLN finds the logical node named by the first "$"-separated segment
// of item and returns it with the full item ID (the resolver re-parses).
func splitLN(ld *model.LogicalDevice, item string) (*model.LogicalNode, string) {
	lnName, _, _ := strings.Cut(item, "$")
	if lnName == "" {
		lnName = item
	}
	return ld.Node(lnName), item
}

func accessFailure(code mms.DataAccessError) *asn1.Element {
	return asn1.UintElem(asn1.ContextPrimitive(0), uint64(code)) // AccessResult failure [0]
}

func accessFailureWrite(code mms.DataAccessError) *asn1.Element {
	return asn1.UintElem(asn1.ContextPrimitive(0), uint64(code)) // failure [0]
}
