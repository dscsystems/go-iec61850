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
	"sync/atomic"
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

	// The callback runs on the connection's reader goroutine and must not
	// block, so it only hands each report over; printing happens below.
	// A report that finds the channel full is dropped rather than stall
	// the connection, and counted; the count is printed below.
	reports := make(chan *client.Report, 64)
	var dropped atomic.Uint64
	sub, err := c.EnableReporting(ctx, rcb, func(r *client.Report) {
		select {
		case reports <- r:
		default:
			dropped.Add(1)
		}
	})
	if err != nil {
		log.Fatalf("enable reporting: %v", err)
	}
	defer func() {
		// ctx is cancelled by now: disable under a fresh, bounded one so an
		// unresponsive server cannot hang the exit.
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := sub.Disable(dctx); err != nil {
			log.Printf("disable reporting: %v", err)
		}
	}()

	// General interrogation gives an immediate full snapshot.
	if err := c.TriggerGI(ctx, rcb); err != nil {
		log.Printf("GI: %v", err)
	}

	var reported uint64
	for {
		select {
		case r := <-reports:
			if n := dropped.Load(); n != reported {
				fmt.Printf("(%d reports dropped: printing is behind)\n", n-reported)
				reported = n
			}
			fmt.Printf("report %q seq=%d entries=%d\n", r.RptID, r.SeqNum, len(r.Entries))
			for _, e := range r.Entries {
				fmt.Printf("  %s [%s] = %s  (%s)\n", e.Ref, e.FC, e.Value, e.Reason)
			}
		case <-ctx.Done():
			return
		}
	}
}
