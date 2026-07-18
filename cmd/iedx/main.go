// Command iedx is a full-featured terminal IEC 61850 client: browse the
// model, read and write data, monitor reports, operate controls, manage
// setting groups, transfer files and query logs — with mouse support.
//
// Usage:
//
//	iedx [host:port]
//
// With no address it opens a connection form. Mouse: click tabs and rows,
// scroll with the wheel.
package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	password := flag.String("password", "", "ACSE authentication password")
	useTLS := flag.Bool("tls", false, "connect with TLS (IEC 62351-3)")
	flag.Parse()

	addr := ""
	if flag.NArg() > 0 {
		addr = flag.Arg(0)
	}

	a := newApp(addr, *password, *useTLS)
	p := tea.NewProgram(a, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "iedx: %v\n", err)
		os.Exit(1)
	}
}
