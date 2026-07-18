// Example: enable a report control block and print incoming reports.
//
//	go run ./examples/report-monitor 127.0.0.1:10102 simpleIOGenericIO/LLN0.RP.EventsRCB01
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: report-monitor host:port LD/LN.RP.rcbName")
	}
	addr, rcbRef := os.Args[1], model.ObjectReference(os.Args[2])

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	c, err := client.Dial(ctx, addr, client.WithTimeout(5*time.Second))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer c.Close()

	rcb, err := c.GetRCB(ctx, rcbRef)
	if err != nil {
		log.Fatalf("get RCB: %v", err)
	}
	// Ask for sequence numbers, reason codes and the dataset name.
	rcb.OptFlds = model.OptSeqNum | model.OptReasonCode | model.OptDataSetName | model.OptConfRev
	rcb.TrgOps = model.TrgDataChange | model.TrgQualityChange | model.TrgGI

	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) {
		fmt.Printf("report %q seq=%d entries=%d\n", r.RptID, r.SeqNum, len(r.Entries))
		for _, e := range r.Entries {
			fmt.Printf("  %s [%s] = %s  (%s)\n", e.Ref, e.FC, e.Value, e.Reason)
		}
	})
	if err != nil {
		log.Fatalf("enable reporting: %v", err)
	}
	defer sub.Disable(context.Background())

	// General interrogation gives an immediate full snapshot.
	if err := c.TriggerGI(ctx, rcb); err != nil {
		log.Printf("GI: %v", err)
	}

	<-ctx.Done()
}
