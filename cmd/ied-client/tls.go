package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/dscsystems/go-iec61850/iec62351"
)

// tlsFlags are the IEC 62351-3 TLS options: this client's certificate,
// the authorities the server's chain must lead to, and their CRLs.
type tlsFlags struct {
	Cert, Key     string
	CA, CRL       fileList
	ServerName    string
	NoServerName  bool
	TLS13Only     bool
	NativeMode    bool
	AllowStaleCRL bool
}

type fileList []string

func (l *fileList) String() string     { return strings.Join(*l, ",") }
func (l *fileList) Set(s string) error { *l = append(*l, s); return nil }

func (f *tlsFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.Cert, "tls-cert", "", "TLS client certificate, PEM (enables TLS, IEC 62351-3)")
	fs.StringVar(&f.Key, "tls-key", "", "TLS client private key, PEM")
	fs.Var(&f.CA, "tls-ca", "TLS trust anchor, PEM or DER (repeatable; required with -tls-cert)")
	fs.Var(&f.CRL, "tls-crl", "CRL, PEM or DER (repeatable)")
	fs.StringVar(&f.ServerName, "tls-server-name", "", "name the server certificate must carry (default: the host of -addr)")
	fs.BoolVar(&f.NoServerName, "tls-no-server-name", false, "check the server's chain only, not its name")
	fs.BoolVar(&f.TLS13Only, "tls13", false, "refuse TLS 1.2")
	fs.BoolVar(&f.NativeMode, "tls-native", false, "IEC 62351-4 native-mode TLS profile instead of IEC 62351-3")
	fs.BoolVar(&f.AllowStaleCRL, "tls-allow-stale-crl", false, "accept a CRL past its next update")
}

func (f *tlsFlags) enabled() bool { return f.Cert != "" }

// config builds the client TLS configuration for a server at addr.
func (f *tlsFlags) config(addr string) (*tls.Config, error) {
	if f.Key == "" {
		return nil, errors.New("-tls-key is required with -tls-cert")
	}
	if len(f.CA) == 0 {
		return nil, errors.New("-tls-ca is required with -tls-cert")
	}
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		return nil, fmt.Errorf("key pair: %w", err)
	}
	roots := x509.NewCertPool()
	for _, p := range f.CA {
		ders, err := readDERs(p, "CERTIFICATE")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, der := range ders {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			roots.AddCert(c)
		}
	}
	var crls []*x509.RevocationList
	for _, p := range f.CRL {
		ders, err := readDERs(p, "X509 CRL")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, der := range ders {
			crl, err := x509.ParseRevocationList(der)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			crls = append(crls, crl)
		}
	}
	name := f.ServerName
	if name == "" && !f.NoServerName {
		if name, _, err = net.SplitHostPort(addr); err != nil {
			name = addr
		}
	}
	return iec62351.ClientConfig(iec62351.Options{
		Certificates:  []tls.Certificate{cert},
		Roots:         roots,
		CRLs:          crls,
		AllowStaleCRL: f.AllowStaleCRL,
		ServerName:    name,
		TLS13Only:     f.TLS13Only,
		NativeMode:    f.NativeMode,
		OnEvent: func(e iec62351.Event) {
			peer := "no certificate"
			if e.Peer != nil {
				peer = e.Peer.Subject.String()
			}
			fmt.Fprintf(os.Stderr, "ied-client: tls: server refused (%s): %v\n", peer, e.Err)
		},
	})
}

// readDERs returns the PEM blocks of type typ in the file at path, or the
// file itself when it is DER.
func readDERs(path, typ string) ([][]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for rest := b; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type == typ {
			out = append(out, blk.Bytes)
		}
	}
	if len(out) == 0 {
		if len(b) > 0 && b[0] == 0x30 {
			return [][]byte{b}, nil
		}
		return nil, fmt.Errorf("no %s found", typ)
	}
	return out, nil
}
