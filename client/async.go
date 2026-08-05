package client

import (
	"context"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// ReadRequest is a read that has been issued and not yet collected.
type ReadRequest struct {
	ref    model.ObjectReference
	fc     model.FC
	done   chan struct{}
	cancel context.CancelFunc

	// Written before done is closed, read only after it: the channel
	// close is what publishes them.
	val *mms.Value
	err error
}

// ReadAsync issues a read and returns immediately with a handle to collect
// it. Several reads may be in flight at once — the MMS association matches
// responses to requests by invoke ID — so a client polling many points
// issues them all and then collects, rather than paying a round trip per
// point:
//
//	reqs := make([]*client.ReadRequest, len(refs))
//	for i, ref := range refs {
//		reqs[i] = c.ReadAsync(ctx, ref, model.MX)
//	}
//	for i, r := range reqs {
//		v, err := r.Result()
//		...
//	}
//
// The number of requests actually outstanding is held to the maximum the
// association negotiated (Conn.MaxServOutstanding), which a server enforces
// by rejecting the excess; the rest wait their turn. That accounting covers
// the asynchronous requests only, so a caller mixing in its own concurrent
// synchronous calls has to leave room for them.
//
// ctx bounds the whole request, waiting for a slot included. The handle
// does not have to be collected: an abandoned request completes and
// releases its slot regardless.
func (c *Client) ReadAsync(ctx context.Context, ref model.ObjectReference, fc model.FC) *ReadRequest {
	rctx, cancel := context.WithCancel(ctx)
	r := &ReadRequest{
		ref:    ref,
		fc:     fc,
		done:   make(chan struct{}),
		cancel: cancel,
	}
	go func() {
		defer close(r.done)
		defer cancel()
		if err := c.acquire(rctx); err != nil {
			r.err = err
			return
		}
		defer c.release()
		r.val, r.err = c.Read(rctx, ref, fc)
	}()
	return r
}

// ReadAllAsync issues one read per reference, all under the same
// functional constraint, and returns the handles in the order given. The
// requests run concurrently within the association's outstanding limit, so
// collecting them costs about as long as the slowest one rather than the
// sum:
//
//	for i, r := range c.ReadAllAsync(ctx, model.MX, refs...) {
//		v, err := r.Result()
//		...
//	}
//
// Each reference is read separately, so one failing leaves the others
// unaffected and references may span logical devices. When they share a
// logical device and a single outcome is enough, ReadValues asks for them
// in one MMS request, which is one round trip instead of many.
func (c *Client) ReadAllAsync(ctx context.Context, fc model.FC, refs ...model.ObjectReference) []*ReadRequest {
	reqs := make([]*ReadRequest, len(refs))
	for i, ref := range refs {
		reqs[i] = c.ReadAsync(ctx, ref, fc)
	}
	return reqs
}

// Ref is the reference being read.
func (r *ReadRequest) Ref() model.ObjectReference { return r.ref }

// FC is the functional constraint being read under.
func (r *ReadRequest) FC() model.FC { return r.fc }

// Done returns a channel closed when the read has finished, for a caller
// collecting whichever request completes first.
func (r *ReadRequest) Done() <-chan struct{} { return r.done }

// Result waits for the read to finish and returns its outcome. It may be
// called repeatedly and from several goroutines; the answer does not
// change. A cancelled request reports the context's error.
func (r *ReadRequest) Result() (*mms.Value, error) {
	<-r.done
	return r.val, r.err
}

// Cancel abandons the read. Result then reports context.Canceled, unless
// the read had already finished, in which case Cancel does nothing. The
// request is dropped locally: MMS has no way to withdraw an invoke, so a
// response that arrives later is discarded.
func (r *ReadRequest) Cancel() { r.cancel() }

// acquire takes one of the association's outstanding-request slots, or
// gives up when ctx does.
func (c *Client) acquire(ctx context.Context) error {
	sem := c.outstanding()
	select {
	case sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) release() { <-c.outstanding() }

// outstanding returns the slot channel, sized on first use from the
// negotiated maximum of outstanding services.
func (c *Client) outstanding() chan struct{} {
	c.semOnce.Do(func() {
		n := 1
		if c.mc != nil {
			n = c.mc.MaxServOutstanding()
		}
		if n < 1 {
			n = 1
		}
		c.sem = make(chan struct{}, n)
	})
	return c.sem
}
