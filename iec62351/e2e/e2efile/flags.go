package e2efile

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/iec62351/e2e"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
)

// Flags are the command-line options of an E2E-capable tool.
type Flags struct {
	Cert, Key   string
	Path, CA    list
	CRL         list
	AE, PeerAE  string
	ICV         string
	Group       string
	Rekey       time.Duration
	AlarmDiag   string
	T100        bool
	RevocationW string
	Events      string
	Required    bool
	Edition     string
	Corrections string
	AnyAEAttr   bool
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

// Register adds the flags to fs. server selects the server-only options.
func (f *Flags) Register(fs *flag.FlagSet, server bool) {
	fs.StringVar(&f.Cert, "e2e-cert", "", "IEC 62351-4 E2E certificate (enables native mode)")
	fs.StringVar(&f.Key, "e2e-key", "", "E2E private key")
	fs.Var(&f.Path, "e2e-path", "E2E CA certificate sent to the peer (repeatable, top-down)")
	fs.Var(&f.CA, "e2e-ca", "E2E trust anchor (repeatable)")
	fs.Var(&f.CRL, "e2e-crl", "CRL (repeatable)")
	fs.StringVar(&f.AE, "ae", "", "local AE title, <AP-title OID>/<AE-qualifier>")
	if !server {
		fs.StringVar(&f.PeerAE, "peer-ae", "", "called (server) AE title, <AP-title OID>/<AE-qualifier>")
		fs.StringVar(&f.Group, "e2e-group", "23", "Diffie-Hellman group: 23 (secp256r1) or 14 (MODP-2048)")
		fs.DurationVar(&f.Rekey, "rekey", time.Hour, "E2E rekey interval (15m..24h)")
	} else {
		fs.BoolVar(&f.Required, "e2e-required", true, "refuse plain associations when E2E is enabled")
		fs.DurationVar(&f.Rekey, "rekey-request", 0, "request a rekey after this long on one key (0: never)")
	}
	fs.StringVar(&f.ICV, "e2e-icv", "hmac-sha256,aes128-gmac,aes256-gmac", "ICV algorithms in preference order")
	fs.StringVar(&f.AlarmDiag, "alarm-diag", "omit", "diagnostic sent for alarms: omit or no-reason-given")
	fs.BoolVar(&f.T100, "t100-diagnostics", false, "use the IEC TS 62351-100-4 diagnostics where they differ")
	fs.StringVar(&f.RevocationW, "revocation-unavailable", "warn", "warn or fail-closed")
	fs.StringVar(&f.Events, "events", "", "print security events: json")
	fs.StringVar(&f.Edition, "e2e-edition", "2020", "wire format: 2020 (IEC 62351-4+AMD1) or 2018 (first edition)")
	fs.StringVar(&f.Corrections, "e2e-corrections", "tissues", "with edition 2020: tissues (the IEC 62351-4 TISSUEs in force) or none (AMD1 as printed)")
	fs.BoolVar(&f.AnyAEAttr, "e2e-any-ae-attr", false, "accept any OID-valued subject attribute, not only X.520 objectIdentifier (2.5.4.106)")
}

// Enabled reports whether E2E was requested.
func (f *Flags) Enabled() bool { return f.Cert != "" }

func (f *Flags) policy(l *Loaded) (e2e.Policy, error) {
	p := e2e.Policy{Trust: l.Trust, Revocation: l.Revocation, T100Diagnostics: f.T100}
	p.AcceptAnyAEAttributeType = f.AnyAEAttr
	ed, err := e2e.ParseEdition(f.Edition)
	if err != nil {
		return p, err
	}
	p.Edition = ed
	if p.Corrections, err = e2e.ParseCorrections(f.Corrections); err != nil {
		return p, err
	}
	for _, s := range strings.Split(f.ICV, ",") {
		switch strings.TrimSpace(s) {
		case "hmac-sha256":
			p.ICVAlgs = append(p.ICVAlgs, e2e.ICVHMACSHA256)
		case "aes128-gmac":
			p.ICVAlgs = append(p.ICVAlgs, e2e.ICVGMACAES128)
		case "aes256-gmac":
			p.ICVAlgs = append(p.ICVAlgs, e2e.ICVGMACAES256)
		case "":
		default:
			return p, fmt.Errorf("unknown ICV algorithm %q", s)
		}
	}
	switch f.AlarmDiag {
	case "omit", "":
	case "no-reason-given":
		p.AlarmDiagnostic = e2e.AlarmNoReasonGiven
	default:
		return p, fmt.Errorf("alarm-diag %q", f.AlarmDiag)
	}
	return p, nil
}

func (f *Flags) load() (*Loaded, e2e.AETitle, error) {
	ae, err := ParseAETitle(f.AE)
	if err != nil {
		return nil, ae, fmt.Errorf("-ae: %w", err)
	}
	pol := pki.Warn
	if f.RevocationW == "fail-closed" {
		pol = pki.FailClosed
	}
	l, err := Load(Files{Cert: f.Cert, Key: f.Key, Path: f.Path, CA: f.CA, CRL: f.CRL}, ae, pol)
	return l, ae, err
}

// EventPrinter returns an OnEvent function printing JSON lines to w when
// -events json was given, nil otherwise.
func (f *Flags) EventPrinter(w io.Writer) func(e2e.Event) {
	if f.Events != "json" {
		return nil
	}
	var mu sync.Mutex
	enc := json.NewEncoder(w)
	return func(e e2e.Event) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(struct {
			Time    time.Time `json:"time"`
			Code    string    `json:"code"`
			Class   string    `json:"class"`
			Role    string    `json:"role"`
			AssoID  string    `json:"asso_id,omitempty"`
			PeerAE  string    `json:"peer_ae,omitempty"`
			CertSHA string    `json:"cert_sha256,omitempty"`
			Diag    string    `json:"diag,omitempty"`
			Detail  string    `json:"detail,omitempty"`
		}{e.Time, string(e.Code), e.Class.String(), e.Role, e.AssoID, e.PeerAE, shaHex(e.CertSHA), e.Diag, e.Detail})
	}
}

func shaHex(b [32]byte) string {
	if b == [32]byte{} {
		return ""
	}
	return fmt.Sprintf("%x", b[:])
}

// ClientConfig builds the client configuration from the flags.
func (f *Flags) ClientConfig(onEvent func(e2e.Event)) (*e2e.ClientConfig, error) {
	l, _, err := f.load()
	if err != nil {
		return nil, err
	}
	peer, err := ParseAETitle(f.PeerAE)
	if err != nil {
		return nil, fmt.Errorf("-peer-ae: %w", err)
	}
	p, err := f.policy(l)
	if err != nil {
		return nil, err
	}
	switch f.Group {
	case "23", "":
		p.DHGroups = []e2e.Group{e2e.GroupP256}
	case "14":
		p.DHGroups = []e2e.Group{e2e.GroupMODP2048}
	default:
		return nil, fmt.Errorf("-e2e-group %q", f.Group)
	}
	p.RekeyInterval = f.Rekey
	cfg := &e2e.ClientConfig{Local: l.Identity, Policy: p, Peer: peer, OnEvent: onEvent}
	return cfg, cfg.Validate()
}

// ServerConfig builds the server configuration from the flags.
func (f *Flags) ServerConfig(onEvent func(e2e.Event)) (*e2e.ServerConfig, error) {
	l, _, err := f.load()
	if err != nil {
		return nil, err
	}
	p, err := f.policy(l)
	if err != nil {
		return nil, err
	}
	p.RekeyRequest = f.Rekey
	cfg := &e2e.ServerConfig{Local: l.Identity, Policy: p, OnEvent: onEvent}
	return cfg, cfg.Validate()
}
