// Command goose-sniff is a passive GOOSE and Sampled Values monitor. It
// subscribes on a network interface and prints a live view of the streams
// it observes, highlighting sequence anomalies. It doubles as the smoke
// test for the ethernet, goose and sv packages.
//
// Requires CAP_NET_RAW (or root) and a Linux host:
//
//	sudo goose-sniff -i eth0
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/goose"
	"github.com/dscsystems/go-iec61850/sv"
)

func main() {
	iface := flag.String("i", "eth0", "network interface to listen on")
	flag.Parse()

	eth, err := ethernet.Open(*iface, ethernet.EtherTypeGOOSE, ethernet.EtherTypeSV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "goose-sniff: %v\n", err)
		os.Exit(1)
	}
	defer eth.Close()
	fmt.Printf("Listening on %s for GOOSE (0x88b8) and SV (0x88ba). Ctrl-C to stop.\n\n", *iface)

	// One interface cannot be shared by two Subscribers (they would race
	// for frames), so demultiplex here and dispatch to per-protocol logic.
	var mu sync.Mutex
	gseen := map[string]uint32{} // goCbRef -> last stNum
	sseen := map[string]uint16{} // svID -> last smpCnt

	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			fr, err := eth.ReadFrame()
			if err != nil {
				return
			}
			switch fr.EtherType {
			case ethernet.EtherTypeGOOSE:
				m, err := goose.Parse(fr.Payload)
				if err != nil {
					continue
				}
				mu.Lock()
				last, ok := gseen[m.GoCbRef]
				gseen[m.GoCbRef] = m.StNum
				mu.Unlock()
				flag := ""
				if ok && m.StNum > last {
					flag = "  <-- state change"
				}
				fmt.Printf("[%s] GOOSE %-28s st=%-4d sq=%-4d conf=%d ttl=%dms vals=%d%s\n",
					time.Now().Format("15:04:05.000"), m.GoCbRef, m.StNum, m.SqNum,
					m.ConfRev, m.TimeAllowedToLive, len(m.Values), flag)
			case ethernet.EtherTypeSV:
				pdu, err := sv.Parse(fr.Payload)
				if err != nil {
					continue
				}
				for _, a := range pdu.ASDUs {
					mu.Lock()
					last, ok := sseen[a.SvID]
					sseen[a.SvID] = a.SmpCnt
					mu.Unlock()
					flag := ""
					if ok && a.SmpCnt != last+1 && a.SmpCnt != 0 {
						flag = "  <-- smpCnt gap"
					}
					fmt.Printf("[%s] SV    %-28s smp=%-5d conf=%d sync=%d bytes=%d%s\n",
						time.Now().Format("15:04:05.000"), a.SvID, a.SmpCnt,
						a.ConfRev, a.SmpSynch, len(a.Sample), flag)
				}
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	close(stop)
	fmt.Println("\nstopping")
}
