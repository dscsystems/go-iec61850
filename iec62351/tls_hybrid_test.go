package iec62351_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/iec62351"
)

// hybridGroups are the ML-KEM hybrid groups the toolchain supports. The
// NIST-curve hybrids are added by tls_hybrid_go126_test.go.
var hybridGroups = []tls.CurveID{tls.X25519MLKEM768}

// probeTLS runs one handshake between client and server and, if it
// succeeds, echoes application data. It returns the client's state and
// each side's error, so a refusal can be attributed to the side that
// refused and to its reason. A successful client handshake alone does not
// prove that the server accepted.
func probeTLS(client, server *tls.Config) (state tls.ConnectionState, clientErr, serverErr error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return state, err, nil
	}
	defer ln.Close()
	type result struct {
		state tls.ConnectionState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		conn := tls.Server(raw, server)
		if err := conn.Handshake(); err != nil {
			done <- result{err: err}
			return
		}
		var buf [5]byte
		if _, err = io.ReadFull(conn, buf[:]); err == nil {
			_, err = conn.Write(buf[:])
		}
		done <- result{conn.ConnectionState(), err}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return state, err, nil
	}
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	conn := tls.Client(raw, client)
	clientErr = conn.Handshake()
	if clientErr == nil {
		if _, clientErr = conn.Write([]byte("probe")); clientErr == nil {
			var buf [5]byte
			if _, clientErr = io.ReadFull(conn, buf[:]); clientErr == nil && string(buf[:]) != "probe" {
				clientErr = errors.New("incorrect application data")
			}
		}
	}
	state = conn.ConnectionState()
	raw.Close()
	peer := <-done
	if clientErr == nil && peer.err == nil &&
		(state.Version != peer.state.Version || state.CurveID != peer.state.CurveID) {
		clientErr = fmt.Errorf("endpoints disagree: client %s/%s, server %s/%s",
			tls.VersionName(state.Version), state.CurveID,
			tls.VersionName(peer.state.Version), peer.state.CurveID)
	}
	return state, clientErr, peer.err
}

// expectNegotiated requires a completed handshake and data exchange at
// version and group.
func expectNegotiated(t *testing.T, c, s *tls.Config, version uint16, group tls.CurveID) {
	t.Helper()
	state, cerr, serr := probeTLS(c, s)
	if cerr != nil || serr != nil {
		t.Fatalf("handshake failed: client: %v; server: %v", cerr, serr)
	}
	if state.Version != version || state.CurveID != group {
		t.Fatalf("negotiated %s/%s; want %s/%s", tls.VersionName(state.Version), state.CurveID, tls.VersionName(version), group)
	}
}

// expectRefused requires the handshake to fail, and the server to report
// reason: a failure for any other cause (a timeout, a certificate, a
// client that never sent its hello) does not count.
func expectRefused(t *testing.T, c, s *tls.Config, reason string) {
	t.Helper()
	_, cerr, serr := probeTLS(c, s)
	if cerr == nil && serr == nil {
		t.Fatalf("handshake succeeded; want the server to refuse with %q", reason)
	}
	if serr == nil || !strings.Contains(serr.Error(), reason) {
		t.Fatalf("server error %v; want one containing %q (client: %v)", serr, reason, cerr)
	}
}

// skipIfHybridsDisabled skips when GODEBUG removes the hybrid groups from
// crypto/tls, as tlsmlkem=0 and tlssecpmlkem=0 do.
func skipIfHybridsDisabled(t *testing.T, group tls.CurveID) {
	t.Helper()
	godebug := os.Getenv("GODEBUG")
	if strings.Contains(godebug, "tlsmlkem=0") ||
		(group != tls.X25519MLKEM768 && strings.Contains(godebug, "tlssecpmlkem=0")) {
		t.Skipf("GODEBUG=%s disables %s", godebug, group)
	}
}

const (
	noSharedGroup   = "no key exchanges supported by both client and server"
	noSharedSuite   = "no cipher suite supported by both client and server"
	noSharedVersion = "client offered only unsupported versions"
)

func TestTLSHybridCompatibility(t *testing.T) {
	ca := newCA(t, "hybrid-ca")
	srv, _ := ca.issue(t, "ied1", nil, "ied1")
	cli, _ := ca.issue(t, "scada", nil, "scada")
	clientOptions := iec62351.Options{Certificates: []tls.Certificate{cli}, Roots: ca.pool(), ServerName: "ied1"}
	serverOptions := iec62351.Options{Certificates: []tls.Certificate{srv}, Roots: ca.pool()}
	profileClient, err := iec62351.ClientConfig(clientOptions)
	if err != nil {
		t.Fatal(err)
	}
	profileServer, err := iec62351.ServerConfig(serverOptions)
	if err != nil {
		t.Fatal(err)
	}
	// peers are plain crypto/tls endpoints pinned to one version and the
	// given groups.
	peers := func(version uint16, groups ...tls.CurveID) (*tls.Config, *tls.Config) {
		c := &tls.Config{Certificates: []tls.Certificate{cli}, RootCAs: ca.pool(), ServerName: "ied1", MinVersion: version, MaxVersion: version, CurvePreferences: groups}
		s := &tls.Config{Certificates: []tls.Certificate{srv}, ClientCAs: ca.pool(), ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: version, MaxVersion: version, CurvePreferences: groups}
		return c, s
	}
	// optIn applies the documented opt-in to a profile config.
	optIn := func(cfg *tls.Config, group tls.CurveID) *tls.Config {
		cfg = cfg.Clone()
		cfg.MinVersion = tls.VersionTLS13
		cfg.CurvePreferences = []tls.CurveID{group}
		return cfg
	}

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, group := range []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521} {
			t.Run(tls.VersionName(version)+"/"+group.String(), func(t *testing.T) {
				c, s := peers(version, group)
				expectNegotiated(t, c, profileServer, version, group)
				expectNegotiated(t, profileClient, s, version, group)
			})
		}
	}

	for _, group := range hybridGroups {
		t.Run(group.String(), func(t *testing.T) {
			skipIfHybridsDisabled(t, group)
			c, s := peers(tls.VersionTLS13, group)
			expectNegotiated(t, c, s, tls.VersionTLS13, group)

			// The default profile does not offer hybrids, in either role.
			expectRefused(t, c, profileServer, noSharedGroup)
			expectRefused(t, profileClient, s, noSharedGroup)

			// A peer that also offers P-256 falls back to it.
			c, s = peers(tls.VersionTLS13, group, tls.CurveP256)
			expectNegotiated(t, c, profileServer, tls.VersionTLS13, tls.CurveP256)
			expectNegotiated(t, profileClient, s, tls.VersionTLS13, tls.CurveP256)

			// The documented opt-in negotiates the hybrid between two
			// profile endpoints...
			hc, hs := optIn(profileClient, group), optIn(profileServer, group)
			expectNegotiated(t, hc, hs, tls.VersionTLS13, group)
			// ...and keeps the profile's certificate verification: a
			// peer from another CA is refused, whichever side it is.
			other := newCA(t, "other-ca")
			strangerCli, _ := other.issue(t, "scada", nil, "scada")
			strangerSrv, _ := other.issue(t, "ied1", nil, "ied1")
			sc := hc.Clone()
			sc.Certificates = []tls.Certificate{strangerCli}
			expectRefused(t, sc, hs, "certificate signed by unknown authority")
			ss := hs.Clone()
			ss.Certificates = []tls.Certificate{strangerSrv}
			if _, cerr, _ := probeTLS(hc, ss); cerr == nil || !strings.Contains(cerr.Error(), "certificate signed by unknown authority") {
				t.Fatalf("opted-in client accepted a server from another CA: %v", cerr)
			}

			// The hybrids are TLS 1.3 groups: a TLS 1.2 hello offering
			// only a hybrid has no usable ECDHE suite.
			c, s = peers(tls.VersionTLS12, group)
			expectRefused(t, c, s, noSharedSuite)
		})
	}

	t.Run("native-mode-is-TLS12", func(t *testing.T) {
		clientOptions.NativeMode, serverOptions.NativeMode = true, true
		c, err := iec62351.ClientConfig(clientOptions)
		if err != nil {
			t.Fatal(err)
		}
		s, err := iec62351.ServerConfig(serverOptions)
		if err != nil {
			t.Fatal(err)
		}
		expectNegotiated(t, c, s, tls.VersionTLS12, tls.CurveP256)
		// A TLS 1.3-only peer is refused, in either role.
		c13, s13 := peers(tls.VersionTLS13, tls.CurveP256)
		expectRefused(t, c13, s, noSharedVersion)
		expectRefused(t, c, s13, noSharedVersion)
	})
}

// A config does not share Curves' or CipherSuites' backing array, so
// changing the package variables later leaves configs already built alone.
func TestConfigCopiesPackageLists(t *testing.T) {
	ca := newCA(t, "copy-ca")
	cert, _ := ca.issue(t, "ied1", nil, "ied1")
	cfg, err := iec62351.ServerConfig(iec62351.Options{Certificates: []tls.Certificate{cert}, Roots: ca.pool()})
	if err != nil {
		t.Fatal(err)
	}
	curve, suite := iec62351.Curves[0], iec62351.CipherSuites[0]
	iec62351.Curves[0], iec62351.CipherSuites[0] = tls.X25519MLKEM768, 0
	defer func() { iec62351.Curves[0], iec62351.CipherSuites[0] = curve, suite }()
	if cfg.CurvePreferences[0] != curve || cfg.CipherSuites[0] != suite {
		t.Errorf("config changed with the package variables: %v, %v", cfg.CurvePreferences, cfg.CipherSuites)
	}
}
