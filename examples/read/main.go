// Example: connect to an IED, browse it and read a value.
//
//	go run ./examples/read 127.0.0.1:10102
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
)

func main() {
	addr := "127.0.0.1:102"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()

	// Enumerate logical devices and their logical nodes.
	lds, err := c.LogicalDevices(ctx)
	if err != nil {
		log.Fatalf("logical devices: %v", err)
	}
	for _, ld := range lds {
		lns, _ := c.LogicalNodes(ctx, ld)
		fmt.Printf("%s: %v\n", ld, lns)
	}

	// Read a measurand by object reference and functional constraint.
	if len(lds) > 0 {
		ref := model.ObjectReference(lds[0] + "/GGIO1.AnIn1.mag.f")
		v, err := c.Read(ctx, ref, model.MX)
		if err != nil {
			log.Printf("read %s: %v", ref, err)
			return
		}
		fmt.Printf("%s = %s (%s)\n", ref, v, v.Type())
	}
}
