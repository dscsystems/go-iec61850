// Command ied-server is an example IEC 61850 server. It loads a model
// from an SCL file and serves it over MMS, simulating measurement drift
// and a toggling status point so clients have live data to observe.
//
// Usage:
//
//	ied-server -scl model.cid -addr :102
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

func main() {
	sclPath := flag.String("scl", "testdata/simpleIO_direct_control.cid", "SCL file (ICD/CID/SCD)")
	ied := flag.String("ied", "", "IED name to serve (default: first in the file)")
	addr := flag.String("addr", ":102", "listen address")
	filesDir := flag.String("files", "", "directory to serve via MMS file services")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	var opts []scl.Option
	if *ied != "" {
		opts = append(opts, scl.ForIED(*ied))
	}
	m, err := scl.LoadModel(*sclPath, opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ied-server: load model: %v\n", err)
		os.Exit(1)
	}

	sopts := []server.Option{
		server.WithLogger(log),
		server.WithIdentity(server.Identity{Vendor: "ACME", Model: m.Name, Revision: "0.1"}),
	}
	if *filesDir != "" {
		sopts = append(sopts, server.WithFileStore(os.DirFS(*filesDir)))
	}
	srv := server.New(m, sopts...)
	srv.OnWrite(func(da *model.DataAttribute, v *mms.Value) error {
		log.Info("client write", "attr", da.Name, "value", v.String())
		return nil
	})

	// Log and accept every control operation.
	for _, ref := range controllables(m) {
		r := ref
		srv.OnControl(r, func(cc *server.ControlCtx) model.AddCause {
			phase := "operate"
			if cc.Select {
				phase = "select"
			}
			log.Info("control "+phase, "ref", cc.Ref, "value", cc.Value.String(),
				"by", cc.OrIdent, "test", cc.Test)
			return model.AddCauseNone // accept; stVal is updated automatically
		})
	}

	// Simulate live process data.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go simulate(ctx, srv, m, log)

	log.Info("serving", "addr", *addr, "ied", m.Name, "devices", len(m.Devices))
	go func() {
		if err := srv.ListenAndServe(*addr); err != nil {
			log.Error("serve", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	srv.Close()
}

// simPoint is one simulated process point and the quality/timestamp
// attributes to stamp alongside it.
type simPoint struct {
	value      model.ObjectReference
	fc         model.FC
	isFloat    bool
	qRef, tRef model.ObjectReference // "" when absent from the model
}

func simulate(ctx context.Context, srv *server.Server, m *model.Model, log *slog.Logger) {
	sigs := collectSignals(m)
	nFloat, nBool := 0, 0
	for _, s := range sigs {
		if s.isFloat {
			nFloat++
		} else {
			nBool++
		}
	}
	log.Info("simulating", "measurands", nFloat, "status-points", nBool)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var phase float64
	tick := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			phase += 0.1
			tick++
			toggle := tick%6 == 0 // flip status points every ~3s
			srv.Update(func(tx *server.Tx) {
				for i, s := range sigs {
					if s.isFloat {
						tx.SetFloat32(s.value, float32(math.Sin(phase+float64(i))))
					} else if toggle {
						// Read the current value via the transaction, never
						// via srv.Read (which would re-lock and deadlock).
						tx.Toggle(s.value, s.fc)
					} else {
						continue
					}
					if s.qRef != "" {
						tx.SetQuality(s.qRef, s.fc, model.QualityGood)
					}
					if s.tRef != "" {
						tx.SetTimestampNow(s.tRef, s.fc)
					}
				}
			})
		}
	}
}

// collectSignals walks the model for measurand floats (mag.f under MX) and
// single-point status booleans (stVal under ST), pairing each with its
// sibling quality (q) and timestamp (t) attributes when present.
func collectSignals(m *model.Model) []simPoint {
	var sigs []simPoint
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, do := range ln.Objects {
				walkDO(&sigs, m, model.ObjectReference(ld.Name+"/"+ln.Name+"."+do.Name), do)
			}
		}
	}
	return sigs
}

func walkDO(sigs *[]simPoint, m *model.Model, ref model.ObjectReference, do *model.DataObject) {
	if f := m.Attribute(ref.Child("mag").Child("f"), model.MX); f != nil {
		*sigs = append(*sigs, simPoint{
			value: ref.Child("mag").Child("f"), fc: model.MX, isFloat: true,
			qRef: existRef(m, ref.Child("q"), model.MX),
			tRef: existRef(m, ref.Child("t"), model.MX),
		})
	}
	if s := m.Attribute(ref.Child("stVal"), model.ST); s != nil && s.Kind == mms.TypeBoolean {
		*sigs = append(*sigs, simPoint{
			value: ref.Child("stVal"), fc: model.ST, isFloat: false,
			qRef: existRef(m, ref.Child("q"), model.ST),
			tRef: existRef(m, ref.Child("t"), model.ST),
		})
	}
	for _, sub := range do.Objects {
		walkDO(sigs, m, ref.Child(sub.Name), sub)
	}
}

func existRef(m *model.Model, ref model.ObjectReference, fc model.FC) model.ObjectReference {
	if m.Attribute(ref, fc) != nil {
		return ref
	}
	return ""
}

// controllables returns the references of all controllable data objects
// (those exposing a CO functional constraint).
func controllables(m *model.Model) []model.ObjectReference {
	var out []model.ObjectReference
	var walk func(base model.ObjectReference, do *model.DataObject)
	walk = func(base model.ObjectReference, do *model.DataObject) {
		ref := base.Child(do.Name)
		for _, fc := range do.FCs() {
			if fc == model.CO {
				out = append(out, ref)
				break
			}
		}
		for _, sub := range do.Objects {
			walk(ref, sub)
		}
	}
	for _, ld := range m.Devices {
		for _, ln := range ld.Nodes {
			for _, do := range ln.Objects {
				walk(model.ObjectReference(ld.Name+"/"+ln.Name), do)
			}
		}
	}
	return out
}
