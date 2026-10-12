package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/dscsystems/go-iec61850/iec62351/aprofile"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
)

// apFlags are the IEC 62351-4 A-security profile (compatibility mode)
// options: the certificate and RSA key this client authenticates with in
// the AARQ, and the authorities the server's certificate must lead to.
type apFlags struct {
	Cert, Key       string
	CA, CRL         fileList
	LegacyMechanism bool
	WithoutTLS      bool
}

func (f *apFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.Cert, "mms-cert", "", "IEC 62351-4 A-profile certificate, PEM or DER (enables MMS certificate authentication)")
	fs.StringVar(&f.Key, "mms-key", "", "A-profile RSA private key, PEM or DER")
	fs.Var(&f.CA, "mms-ca", "A-profile trust anchor for the server's certificate (repeatable; required with -mms-cert)")
	fs.Var(&f.CRL, "mms-crl", "A-profile CRL (repeatable)")
	fs.BoolVar(&f.LegacyMechanism, "mms-legacy-mechanism", false,
		"send the mechanism-name 1.0.840.0.1.0.1.1 of some IEC TS 62351-4:2007 implementations")
	fs.BoolVar(&f.WithoutTLS, "mms-without-tls", false,
		"allow the A-profile without TLS (lab only: authenticates the association but protects no data)")
}

func (f *apFlags) enabled() bool { return f.Cert != "" }

func (f *apFlags) config(tlsOn bool) (*aprofile.Config, error) {
	if f.Key == "" || len(f.CA) == 0 {
		return nil, errors.New("-mms-key and -mms-ca are required with -mms-cert")
	}
	if !tlsOn && !f.WithoutTLS {
		return nil, errors.New("the A-profile requires TLS (-tls-cert); -mms-without-tls overrides for lab devices")
	}
	cfg, err := aprofile.Load(aprofile.Files{Cert: f.Cert, Key: f.Key, CA: f.CA, CRL: f.CRL}, pki.Warn)
	if err != nil {
		return nil, err
	}
	if f.LegacyMechanism {
		cfg.Mechanism = aprofile.LegacyMechanism
	}
	cfg.AllowWithoutTLS = f.WithoutTLS
	if !tlsOn {
		fmt.Fprintln(os.Stderr, "ied-client: warning: A-profile without TLS; the association is authenticated, the data is not protected")
	}
	return cfg, nil
}
