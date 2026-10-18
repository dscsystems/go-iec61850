// Example: subscribe to GOOSE on a network interface (Linux, needs
// CAP_NET_RAW).
//
//	sudo go run ./examples/goose-subscribe eth0
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/goose"
)

func main() {
	iface := "eth0"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	eth, err := ethernet.Open(iface, ethernet.EtherTypeGOOSE)
	if err != nil {
		log.Fatalf("open %s: %v", iface, err)
	}
	defer eth.Close()

	// The callback runs on the subscriber's reader goroutine and must not
	// block, so it only hands each message over; printing happens below.
	// A message that finds the channel full is dropped rather than stall
	// the reader.
	msgs := make(chan *goose.Message, 256)
	sub := goose.NewSubscriber(eth)
	stop, err := sub.Subscribe(goose.Filter{}, func(m *goose.Message) {
		select {
		case msgs <- m:
		default:
		}
	})
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	defer stop()

	fmt.Printf("listening for GOOSE on %s (Ctrl-C to stop)\n", iface)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	for {
		select {
		case m := <-msgs:
			flag := ""
			if m.Anomalies.StNumRegressed || m.Anomalies.SqNumGap || m.Anomalies.Stale {
				flag = " [ANOMALY]"
			}
			fmt.Printf("%-30s st=%d sq=%d confRev=%d test=%v vals=%d%s\n",
				m.GoCbRef, m.StNum, m.SqNum, m.ConfRev, m.Test, len(m.Values), flag)
		case <-sig:
			return
		}
	}
}
