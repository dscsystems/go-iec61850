// Command iedx is a full-featured terminal IEC 61850 client: browse the
// model, read and write data, monitor reports, operate controls, manage
// setting groups, transfer files and query logs — with mouse support.
//
// Usage:
//
//	iedx [-password pw] [-tls-cert c.pem -tls-key k.pem -tls-ca ca.pem ...] [host:port]
//
// With no address it opens a connection form. Mouse: click tabs and rows,
// scroll with the wheel.
package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/dscsystems/go-iec61850/internal/tlsflags"
)

func main() {
	password := flag.String("password", "", "ACSE authentication password")
	// The TLS credentials come from the -tls-* flags; with them the
	// connection form starts with TLS on. Refusal events are not printed:
	// the terminal belongs to the UI.
	var tlsF tlsflags.Flags
	tlsF.Register(flag.CommandLine)
	flag.Parse()

	addr := ""
	if flag.NArg() > 0 {
		addr = flag.Arg(0)
	}

	a := newApp(addr, *password, &tlsF)
	p := tea.NewProgram(a, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "iedx: %v\n", err)
		os.Exit(1)
	}
}
