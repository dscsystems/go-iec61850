package mms

import (
	"errors"
	"net"
	"sync"
	"testing"
)

// A report producer can still be running when the association or server
// closes. Sending to a closed queue must return an error instead of panicking.
func TestServerCloseConcurrentWithReports(t *testing.T) {
	for range 50 {
		raw, peer := net.Pipe()
		sc := &ServerConn{raw: raw, unconf: make(chan []byte, 8)}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for range 100 {
					err := sc.enqueue([]byte{1})
					if err != nil && !errors.Is(err, ErrReportQueueFull) && !errors.Is(err, net.ErrClosed) {
						t.Errorf("enqueue: %v", err)
					}
				}
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); <-start; sc.Close() }()
		close(start)
		wg.Wait()
		if err := sc.enqueue([]byte{1}); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("after Close: %v", err)
		}
		peer.Close()
	}
}
