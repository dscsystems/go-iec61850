package iec62351_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/iec62351"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

// The TLS interop tests run libiec61850's tls_server_example and
// tls_client_example (built against mbedtls 3.6) against the profile.
// IEC61850_C_TLS_SERVER and IEC61850_C_TLS_CLIENT name the binaries; each
// runs in a scratch directory holding the certificates its example
// loads, from the example's source directory, IEC61850_C_TLS_CERTS.
// Both examples use MMS over TLS's port, 3782, which must be free.

func certsDir(t *testing.T) string {
	dir := os.Getenv("IEC61850_C_TLS_CERTS")
	if dir == "" {
		t.Skip("set IEC61850_C_TLS_CERTS to libiec61850's examples directory")
	}
	return dir
}

func loadPEMCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func copyFiles(t *testing.T, dst string, files ...string) {
	t.Helper()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, filepath.Base(f)), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

// Our client, under the profile, against libiec61850's TLS server: the
// server knows the example client certificate, and we verify the
// server's chain to the example root.
func TestInteropClientToLibiecTLSServer(t *testing.T) {
	bin := os.Getenv("IEC61850_C_TLS_SERVER")
	if bin == "" {
		t.Skip("set IEC61850_C_TLS_SERVER to libiec61850's tls_server_example")
	}
	src := filepath.Join(certsDir(t), "tls_server_example")
	cliSrc := filepath.Join(certsDir(t), "tls_client_example")
	work := t.TempDir()
	copyFiles(t, work, filepath.Join(src, "server_CA1_1.key"), filepath.Join(src, "server_CA1_1.pem"),
		filepath.Join(src, "root_CA1.pem"), filepath.Join(src, "client_CA1_1.pem"), filepath.Join(src, "client_CA1_2.pem"))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin)
	cmd.Dir = work
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	addr := "127.0.0.1:3782"
	waitListening(t, addr)

	id, err := tls.LoadX509KeyPair(filepath.Join(cliSrc, "client_CA1_1.pem"), filepath.Join(cliSrc, "client_CA1_1.key"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(loadPEMCert(t, filepath.Join(src, "root_CA1.pem")))
	cfg, err := iec62351.ClientConfig(iec62351.Options{Certificates: []tls.Certificate{id}, Roots: roots, ServerName: "server1"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(ctx, addr, client.WithTLS(cfg), client.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("associate over TLS: %v", err)
	}
	defer c.Close()
	v, err := c.Read(ctx, "simpleIOGenericIO/GGIO1.AnIn1.mag.f", model.MX)
	if err != nil {
		t.Fatalf("read over TLS: %v", err)
	}
	t.Logf("GGIO1.AnIn1.mag.f = %v over %s", v, "TLS")

	// The profile refuses the same server under a name it does not carry.
	bad, _ := iec62351.ClientConfig(iec62351.Options{Certificates: []tls.Certificate{id}, Roots: roots, ServerName: "server2"})
	if c2, err := client.Dial(ctx, addr, client.WithTLS(bad), client.WithTimeout(5*time.Second)); err == nil {
		c2.Close()
		t.Error("a server certificate for server1 was accepted as server2")
	}
}

// libiec61850's TLS client against our server under the profile. The
// server presents the example server certificate, which the C client
// verifies to the example root; the C client presents a certificate our
// test authority issued, which the server verifies to that authority.
func TestInteropLibiecTLSClientToServer(t *testing.T) {
	bin := os.Getenv("IEC61850_C_TLS_CLIENT")
	if bin == "" {
		t.Skip("set IEC61850_C_TLS_CLIENT to libiec61850's tls_client_example")
	}
	src := filepath.Join(certsDir(t), "tls_server_example")
	work := t.TempDir()
	copyFiles(t, work, filepath.Join(src, "root_CA1.pem"))

	// The C client loads client.crt and client.key from its directory.
	auth := newCA(t, "scada-ca")
	cliRSA, err := rsaKey(t)
	if err != nil {
		t.Fatal(err)
	}
	cliCert, _ := auth.issue(t, "c-client", cliRSA)
	writePEM(t, filepath.Join(work, "client.crt"), "CERTIFICATE", cliCert.Certificate[0])
	keyDER, err := x509.MarshalPKCS8PrivateKey(cliRSA)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(work, "client.key"), "PRIVATE KEY", keyDER)

	id, err := tls.LoadX509KeyPair(filepath.Join(src, "server_CA1_1.pem"), filepath.Join(src, "server_CA1_1.key"))
	if err != nil {
		t.Fatal(err)
	}
	var events []iec62351.Event
	cfg, err := iec62351.ServerConfig(iec62351.Options{Certificates: []tls.Certificate{id}, Roots: auth.pool(),
		OnEvent: func(e iec62351.Event) { events = append(events, e) }})
	if err != nil {
		t.Fatal(err)
	}
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:3782")
	if err != nil {
		t.Skipf("port 3782 is not free: %v", err)
	}
	srv := server.New(m, server.WithTLS(cfg))
	go srv.Serve(tls.NewListener(ln, cfg))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "stdbuf", "-oL", bin, "127.0.0.1")
	cmd.Dir = work
	out, _ := cmd.CombinedOutput()
	text := string(out)
	t.Logf("C client:\n%s", text)
	if !strings.Contains(text, "read float value") || strings.Contains(text, "ERROR") ||
		strings.Contains(text, "failed to read server directory") {
		t.Fatalf("the C client did not associate and read over TLS; events %v", events)
	}
}

func rsaKey(t *testing.T) (*rsa.PrivateKey, error) {
	t.Helper()
	return rsa.GenerateKey(rand.Reader, 2048)
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}
