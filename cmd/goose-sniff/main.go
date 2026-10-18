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
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
	"github.com/dscsystems/go-iec61850/goose"
	"github.com/dscsystems/go-iec61850/sv"
)

// gooseState is the last message seen of one GOOSE control block.
type gooseState struct {
	stNum, sqNum uint32
	arrival      time.Time
	tatl         time.Duration
}

// check flags m against the previous message of its control block, as
// goose.Subscriber does: stNum regression, sqNum gap, stale arrival.
func (st *gooseState) check(m *goose.Message, now time.Time) []string {
	var out []string
	// Both counters roll over to 1, not 0.
	if m.StNum < st.stNum && !(st.stNum == math.MaxUint32 && m.StNum == 1) {
		out = append(out, "stNum regressed")
	}
	if m.StNum == st.stNum {
		next := st.sqNum + 1
		if next == 0 {
			next = 1
		}
		if m.SqNum != next {
			out = append(out, "sqNum gap")
		}
	} else {
		if m.SqNum != 0 {
			out = append(out, "sqNum not reset")
		}
		if m.StNum > st.stNum {
			out = append(out, "state change")
		}
	}
	if st.tatl > 0 && now.Sub(st.arrival) > st.tatl {
		out = append(out, "stale")
	}
	return out
}

func main() {
	iface := flag.String("i", "eth0", "network interface to listen on")
	flag.Parse()

	eth, err := ethernet.Open(*iface, ethernet.EtherTypeGOOSE, ethernet.EtherTypeSV)
	if err != nil {
		fmt.Fprintf(os.Stderr, "goose-sniff: %v\n", err)
		os.Exit(1)
	}
	defer eth.Close()

	// Output is buffered, so printing keeps up with SV rates, and flushed
	// a few times a second.
	var mu sync.Mutex
	out := bufio.NewWriterSize(os.Stdout, 64<<10)
	fmt.Fprintf(out, "Listening on %s for GOOSE (0x88b8) and SV (0x88ba). Ctrl-C to stop.\n\n", *iface)
	go func() {
		for range time.Tick(200 * time.Millisecond) {
			mu.Lock()
			out.Flush()
			mu.Unlock()
		}
	}()

	// One interface cannot be shared by two Subscribers (they would race
	// for frames), so demultiplex here and dispatch to per-protocol logic.
	gseen := map[string]*gooseState{} // goCbRef -> last message
	sseen := map[string]uint16{}      // svID -> last smpCnt

	go func() {
		for {
			fr, err := eth.ReadFrame()
			if err != nil {
				return
			}
			now := time.Now()
			mu.Lock()
			switch fr.EtherType {
			case ethernet.EtherTypeGOOSE:
				m, err := goose.Parse(fr.Payload)
				if err != nil {
					break
				}
				var flags []string
				if int(m.NumDatSetEntries) != len(m.Values) {
					flags = append(flags, "entries mismatch")
				}
				st, ok := gseen[m.GoCbRef]
				if ok {
					flags = append(flags, st.check(m, now)...)
				} else {
					st = &gooseState{}
					gseen[m.GoCbRef] = st
				}
				*st = gooseState{stNum: m.StNum, sqNum: m.SqNum, arrival: now,
					tatl: time.Duration(m.TimeAllowedToLive) * time.Millisecond}
				flag := ""
				if len(flags) > 0 {
					flag = "  <-- " + strings.Join(flags, ", ")
				}
				fmt.Fprintf(out, "[%s] GOOSE %-28s st=%-4d sq=%-4d conf=%d ttl=%dms vals=%d%s\n",
					now.Format("15:04:05.000"), m.GoCbRef, m.StNum, m.SqNum,
					m.ConfRev, m.TimeAllowedToLive, len(m.Values), flag)
			case ethernet.EtherTypeSV:
				pdu, err := sv.Parse(fr.Payload)
				if err != nil {
					break
				}
				for _, a := range pdu.ASDUs {
					last, ok := sseen[a.SvID]
					sseen[a.SvID] = a.SmpCnt
					flag := ""
					if ok && a.SmpCnt != last+1 && a.SmpCnt != 0 {
						flag = "  <-- smpCnt gap"
					}
					fmt.Fprintf(out, "[%s] SV    %-28s smp=%-5d conf=%d sync=%d bytes=%d%s\n",
						now.Format("15:04:05.000"), a.SvID, a.SmpCnt,
						a.ConfRev, a.SmpSynch, len(a.Sample), flag)
				}
			}
			mu.Unlock()
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	mu.Lock()
	fmt.Fprintln(out, "\nstopping")
	out.Flush()
	mu.Unlock()
}
