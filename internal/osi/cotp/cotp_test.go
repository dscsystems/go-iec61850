package cotp

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// pipeConn adapts net.Pipe ends to io.ReadWriteCloser (they already are).

func TestConnectAccept(t *testing.T) {
	cli, srv := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)
	var serverConn *Conn
	var serverErr error
	go func() {
		defer wg.Done()
		serverConn, serverErr = Accept(srv)
	}()

	clientConn, err := Connect(cli, Options{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	wg.Wait()
	if serverErr != nil {
		t.Fatalf("Accept: %v", serverErr)
	}
	if serverConn.dstRef != clientConn.srcRef {
		t.Errorf("ref mismatch: server dstRef=%d client srcRef=%d", serverConn.dstRef, clientConn.srcRef)
	}

	// Exchange a TSDU larger than one TPDU to exercise segmentation.
	payload := bytes.Repeat([]byte("ABCDEFGH"), 500) // 4000 bytes > 1024 TPDU
	var rg sync.WaitGroup
	rg.Add(1)
	var got []byte
	var rerr error
	go func() {
		defer rg.Done()
		got, rerr = serverConn.Receive()
	}()
	if err := clientConn.Send(payload); err != nil {
		t.Fatalf("Send: %v", err)
	}
	rg.Wait()
	if rerr != nil {
		t.Fatalf("Receive: %v", rerr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}

	// Reverse direction, small payload.
	rg.Add(1)
	go func() {
		defer rg.Done()
		got, rerr = clientConn.Receive()
	}()
	if err := serverConn.Send([]byte("hello")); err != nil {
		t.Fatalf("server Send: %v", err)
	}
	rg.Wait()
	if rerr != nil || string(got) != "hello" {
		t.Fatalf("reverse: %q %v", got, rerr)
	}
}

func TestReceiveDisconnect(t *testing.T) {
	cli, srv := net.Pipe()
	go func() {
		Connect(cli, Options{})
		cli.Close()
	}()
	_, err := Accept(srv)
	// Accept may succeed then a later Receive sees EOF; either way no panic.
	if err != nil && err != io.EOF {
		return
	}
}
