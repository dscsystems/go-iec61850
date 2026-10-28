package mmsinterop_test

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// The fixture's logical device. Third-party servers name it after the IED
// (InteropIEDInteropLD); the peer controller and reporter address the bare
// instance name, which is what the mms-interop contract expects a Go
// server to serve.
const (
	ldInst  = "InteropLD"
	iedName = "InteropIED"
)

// values is testdata/values.json: initial values by reference without the
// IED name ("InteropLD/GGIO1.SPS1.stVal"), and the writable attributes.
type values struct {
	Values   map[string]any `json:"values"`
	Writable []string       `json:"writable"`
}

func loadValues(t *testing.T) values {
	t.Helper()
	b, err := os.ReadFile("testdata/values.json")
	if err != nil {
		t.Fatal(err)
	}
	var v values
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("values.json: %v", err)
	}
	return v
}

// sortedKeys returns the references of values.json in order, so subtests
// and messages come out the same on every run.
func (v values) sortedKeys() []string {
	keys := make([]string, 0, len(v.Values))
	for k := range v.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// loadModel builds the fixture model. Third-party servers name the logical
// device after the IED (InteropIEDInteropLD) and index the report
// instances (urcb0101), so their clients' tests resolve both. The client
// adapters address InteropLD/LLN0.RP.urcb01 as they are, which is what
// the mms-interop contract expects a Go server to serve; with contract the
// model is built that way, through the SCL attributes that say so
// (LDevice@ldName and ReportControl@indexed).
func loadModel(t *testing.T, contract bool) *model.Model {
	t.Helper()
	s, err := scl.ParseFile("testdata/interop.icd")
	if err != nil {
		t.Fatal(err)
	}
	var opts []scl.Option
	if contract {
		for i := range s.IEDs {
			for j := range s.IEDs[i].AccessPoints {
				srv := s.IEDs[i].AccessPoints[j].Server
				if srv == nil {
					continue
				}
				for k := range srv.LDevices {
					ld := &srv.LDevices[k]
					if ld.Inst != ldInst {
						continue
					}
					ld.LdName = ldInst
					if ld.LN0 != nil {
						for r := range ld.LN0.ReportControls {
							ld.LN0.ReportControls[r].Indexed = "false"
						}
					}
				}
			}
		}
		opts = append(opts, scl.UseLDName(true))
	}
	m, err := scl.BuildModel(s, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// typedValue converts a values.json scalar to the type of the attribute.
func typedValue(da *model.DataAttribute, raw any) (*mms.Value, error) {
	n, isNum := raw.(float64)
	switch da.Kind {
	case mms.TypeBoolean:
		if b, ok := raw.(bool); ok {
			return mms.NewBool(b), nil
		}
	case mms.TypeInteger:
		if isNum {
			return mms.NewInt64(int64(n)), nil
		}
	case mms.TypeUnsigned:
		if isNum && n >= 0 {
			return mms.NewUint32(uint32(n)), nil
		}
	case mms.TypeFloat32:
		if isNum {
			return mms.NewFloat32(float32(n)), nil
		}
	case mms.TypeFloat64:
		if isNum {
			return mms.NewFloat64(n), nil
		}
	case mms.TypeVisibleString:
		if s, ok := raw.(string); ok {
			return mms.NewVisibleString(s), nil
		}
	case mms.TypeMMSString:
		if s, ok := raw.(string); ok {
			return mms.NewMMSString(s), nil
		}
	case mms.TypeBitString:
		// Dbpos: values.json carries the enumeration (2 = on).
		if isNum && da.BType == "Dbpos" {
			return model.Dbpos(int(n)).Value(), nil
		}
	}
	return nil, fmt.Errorf("value %v does not fit %s (%s)", raw, da.Kind, da.BType)
}

// goServer is this library's IED server loaded with the fixture.
type goServer struct {
	srv  *server.Server
	addr string // host:port on the loopback

	mu       sync.Mutex
	controls []server.ControlCtx // every accepted select and operate
}

// controlled are the SPC objects of the fixture: SPCSO1 direct, SPCSO2
// SBO normal, SPCSO3 SBO enhanced.
var controlled = []string{"SPCSO1", "SPCSO2", "SPCSO3"}

// startGoServer serves the fixture on a free loopback port until the test
// ends. Every control on the SPC objects is accepted; the server enforces
// the control model and reflects ctlVal into stVal itself.
func startGoServer(t *testing.T, opts ...server.Option) *goServer {
	t.Helper()
	m := loadModel(t, true)
	v := loadValues(t)
	srv := server.New(m, opts...)
	var bad []string
	srv.Update(func(tx *server.Tx) {
		for _, k := range v.sortedKeys() {
			ref := model.ObjectReference(k)
			da := m.Attribute(ref, model.ALL)
			if da == nil {
				bad = append(bad, k+": not in the model")
				continue
			}
			val, err := typedValue(da, v.Values[k])
			if err != nil {
				bad = append(bad, k+": "+err.Error())
				continue
			}
			tx.Set(ref, da.FC, val)
		}
	})
	if len(bad) > 0 {
		t.Fatalf("values.json:\n%s", strings.Join(bad, "\n"))
	}
	g := &goServer{srv: srv}
	for _, do := range controlled {
		srv.OnControl(model.ObjectReference(ldInst+"/GGIO1."+do), func(cc *server.ControlCtx) model.AddCause {
			g.mu.Lock()
			g.controls = append(g.controls, *cc)
			g.mu.Unlock()
			return model.AddCauseNone
		})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Close()
		<-served
	})
	g.addr = ln.Addr().String()
	return g
}

// controlsOn returns the accepted selects and operates of one object.
func (g *goServer) controlsOn(do string) []server.ControlCtx {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []server.ControlCtx
	for _, cc := range g.controls {
		if strings.HasSuffix(string(cc.Ref), "."+do) {
			out = append(out, cc)
		}
	}
	return out
}
