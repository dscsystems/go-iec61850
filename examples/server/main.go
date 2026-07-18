// Example: serve a model from an SCL file and push live values.
//
//	go run ./examples/server testdata/simpleIO_direct_control.cid :10102
package main

import (
	"context"
	"log"
	"math"
	"os"
	"os/signal"
	"time"

	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

func main() {
	sclPath, addr := "testdata/simpleIO_direct_control.cid", ":102"
	if len(os.Args) > 1 {
		sclPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		addr = os.Args[2]
	}

	m, err := scl.LoadModel(sclPath)
	if err != nil {
		log.Fatalf("load model: %v", err)
	}
	srv := server.New(m, server.WithIdentity(server.Identity{
		Vendor: "ACME", Model: m.Name, Revision: "0.1",
	}))

	// Accept controls on SPCSO1 and reflect them into stVal automatically
	// (the default), but log each operation.
	srv.OnControl(model.ObjectReference(m.Devices[0].Name+"/GGIO1.SPCSO1"),
		func(cc *server.ControlCtx) model.AddCause {
			log.Printf("operate %s = %s by %s", cc.Ref, cc.Value, cc.OrIdent)
			return model.AddCauseNone // accept
		})

	// Drive a measurand from the process side.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		ref := model.ObjectReference(m.Devices[0].Name + "/GGIO1.AnIn1.mag.f")
		var phase float64
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				phase += 0.2
				srv.Update(func(tx *server.Tx) {
					tx.SetFloat32(ref, float32(math.Sin(phase)))
				})
			}
		}
	}()

	log.Printf("serving %s on %s", m.Name, addr)
	go func() { log.Fatal(srv.ListenAndServe(addr)) }()
	<-ctx.Done()
	srv.Close()
}
