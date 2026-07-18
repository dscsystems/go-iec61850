// Example: operate a controllable point. The control model is read from
// the server and the correct select/operate sequence is used automatically.
//
//	go run ./examples/control 127.0.0.1:10102 simpleIOGenericIO/GGIO1.SPCSO1 on
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

func main() {
	if len(os.Args) < 4 {
		log.Fatal("usage: control host:port LD/LN.DO on|off")
	}
	addr := os.Args[1]
	ref := model.ObjectReference(os.Args[2])
	on := os.Args[3] == "on"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()

	co, err := c.ControlFor(ctx, ref)
	if err != nil {
		log.Fatalf("control for %s: %v", ref, err)
	}
	fmt.Printf("control model: %s\n", co.Model())

	err = co.Operate(ctx, mms.NewBool(on),
		client.WithOriginator(model.OrCatStationControl, "example"),
		client.WithInterlockCheck(true))
	if err != nil {
		var ce *client.ControlError
		if errors.As(err, &ce) {
			log.Fatalf("operate rejected at %s stage: %s", ce.Stage, ce.AddCause)
		}
		log.Fatalf("operate: %v", err)
	}
	fmt.Printf("operated %s = %v\n", ref, on)
}
