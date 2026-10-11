package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/iec62351/e2e"
	"github.com/dscsystems/go-iec61850/iec62351/pki"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/server"
)

// An IEC 61850 client and server under IEC 62351-4 E2E security: browse,
// read and the signed release.
func TestE2EServerClient(t *testing.T) {
	root := pkitest.NewRoot("root", pkitest.ECDSAP256)
	cliAE := e2e.AETitle{APTitle: asn1.OID{1, 3, 9999, 50}, AEQualifier: 1}
	srvAE := e2e.AETitle{APTitle: asn1.OID{1, 3, 9999, 60}, AEQualifier: 1}
	cl := root.NewE2ELeaf(cliAE.APTitle, cliAE.AEQualifier, pkitest.LeafOptions{})
	sl := root.NewE2ELeaf(srvAE.APTitle, srvAE.AEQualifier, pkitest.LeafOptions{})
	trust := pki.NewTrustStore(root.Cert)
	var accepted []e2e.Event
	scfg := &e2e.ServerConfig{Local: e2e.Identity{AE: srvAE, Certificate: sl.DER, Signer: sl.Key},
		Policy: e2e.Policy{Trust: trust}, OnEvent: func(e e2e.Event) {
			if e.Code == e2e.EventHandshakeAccepted {
				accepted = append(accepted, e)
			}
		}}
	addr, _ := startConfigured(t, server.WithE2E(scfg, true))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Plain clients are refused.
	if _, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second)); err == nil {
		t.Fatal("plain client accepted by an E2E-only server")
	}

	ccfg := &e2e.ClientConfig{Local: e2e.Identity{AE: cliAE, Certificate: cl.DER, Signer: cl.Key},
		Policy: e2e.Policy{Trust: trust, ICVAlgs: []e2e.ICVAlg{e2e.ICVGMACAES128}}, Peer: srvAE}
	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second), client.WithE2E(ccfg))
	if err != nil {
		t.Fatalf("E2E dial: %v", err)
	}
	if ps := c.PeerSecurity(); ps.ICV != e2e.ICVGMACAES128 || ps.AE.String() != srvAE.String() {
		t.Fatalf("peer security %+v", ps)
	}
	lds, err := c.LogicalDevices(ctx)
	if err != nil || len(lds) == 0 {
		t.Fatalf("browse: %v %v", lds, err)
	}
	if _, _, _, err := c.MMS().Identify(ctx); err != nil {
		t.Fatalf("identify: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Logf("close: %v", err)
	}
	if len(accepted) != 1 {
		t.Fatalf("handshake events %d", len(accepted))
	}
	_ = mms.E2EKeepAlive
}
