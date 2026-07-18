// Package model implements the IEC 61850 object model: functional
// constraints, object references, the LD/LN/DO/DA node tree shared by the
// SCL loader, the server and client-side model retrieval, and the common
// bit-string types from IEC 61850-7-3 (Quality, Dbpos, trigger options).
package model

import (
	"fmt"
	"strings"
)

// FC is a functional constraint (IEC 61850-7-2).
type FC uint8

const (
	FCNone FC = iota
	ST        // status information
	MX        // measurands
	CO        // control
	SP        // set points
	SG        // setting group
	SE        // setting group editable
	SV        // substitution
	CF        // configuration
	DC        // description
	EX        // extended definition
	OR        // operate received
	BL        // blocking
	RP        // unbuffered report control
	BR        // buffered report control
	LG        // log control
	GO        // GOOSE control
	GS        // GSSE control (legacy)
	MS        // multicast sampled values control
	US        // unicast sampled values control
	ALL       // wildcard, client side only
)

var fcNames = [...]string{
	FCNone: "", ST: "ST", MX: "MX", CO: "CO", SP: "SP", SG: "SG", SE: "SE",
	SV: "SV", CF: "CF", DC: "DC", EX: "EX", OR: "OR", BL: "BL", RP: "RP",
	BR: "BR", LG: "LG", GO: "GO", GS: "GS", MS: "MS", US: "US", ALL: "*",
}

func (fc FC) String() string {
	if int(fc) < len(fcNames) {
		return fcNames[fc]
	}
	return fmt.Sprintf("FC(%d)", uint8(fc))
}

// ParseFC parses a functional constraint mnemonic (case-insensitive).
func ParseFC(s string) (FC, error) {
	u := strings.ToUpper(strings.TrimSpace(s))
	for fc, name := range fcNames {
		if name != "" && name == u {
			return FC(fc), nil
		}
	}
	return FCNone, fmt.Errorf("model: unknown functional constraint %q", s)
}
