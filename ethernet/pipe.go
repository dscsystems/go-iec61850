package ethernet

import (
	"net"
	"sync"
)

// Pipe returns two connected in-memory interfaces: a frame written to one
// end is delivered to the other end's ReadFrame. It is the layer-2
// analogue of net.Pipe, used for tests and for simulating a shared
// segment without a real NIC. Frames are copied on write so callers may
// reuse their buffers.
func Pipe() (a, b Interface) {
	ab := make(chan *Frame, 64)
	ba := make(chan *Frame, 64)
	done := make(chan struct{})
	var once sync.Once
	closeFn := func() { once.Do(func() { close(done) }) }
	return &pipeEnd{out: ab, in: ba, done: done, closeFn: closeFn},
		&pipeEnd{out: ba, in: ab, done: done, closeFn: closeFn}
}

type pipeEnd struct {
	out     chan<- *Frame
	in      <-chan *Frame
	done    chan struct{}
	closeFn func()
}

func (p *pipeEnd) WriteFrame(f *Frame) error {
	// Copy so the caller can reuse its Frame and payload.
	cp := *f
	cp.Payload = append([]byte(nil), f.Payload...)
	if f.VLAN != nil {
		v := *f.VLAN
		cp.VLAN = &v
	}
	select {
	case p.out <- &cp:
		return nil
	case <-p.done:
		return net.ErrClosed
	}
}

func (p *pipeEnd) ReadFrame() (*Frame, error) {
	select {
	case f := <-p.in:
		return f, nil
	case <-p.done:
		return nil, net.ErrClosed
	}
}

func (p *pipeEnd) Close() error {
	p.closeFn()
	return nil
}
