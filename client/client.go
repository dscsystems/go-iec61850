// Package client is the high-level IEC 61850 ACSI client. It presents an
// IED as a data model addressed by object reference and functional
// constraint, layered on the MMS services in the mms package.
package client

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Client is a connection to an IEC 61850 server (IED).
type Client struct {
	mc *mms.Conn
}

// closedChan stands in for the connection's Done channel when there is no
// connection to wait on.
var closedChan = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

// Option configures a Client.
type Option func(*mms.Options)

// WithTLS enables TLS per IEC 62351-3.
func WithTLS(cfg *tls.Config) Option { return func(o *mms.Options) { o.TLS = cfg } }

// WithPassword sets an ACSE authentication password.
func WithPassword(pw string) Option { return func(o *mms.Options) { o.Password = pw } }

// WithTimeout bounds the connection handshake.
func WithTimeout(d time.Duration) Option { return func(o *mms.Options) { o.ConnectTimeout = d } }

// WithLogger sets the diagnostic logger.
func WithLogger(l *slog.Logger) Option { return func(o *mms.Options) { o.Logger = l } }

// Dial connects to an IED at "host:port".
func Dial(ctx context.Context, addr string, opts ...Option) (*Client, error) {
	var mo mms.Options
	for _, opt := range opts {
		opt(&mo)
	}
	mc, err := mms.Dial(ctx, addr, mo)
	if err != nil {
		return nil, err
	}
	return &Client{mc: mc}, nil
}

// MMS returns the underlying MMS connection for advanced use.
func (c *Client) MMS() *mms.Conn { return c.mc }

// Close releases the association.
func (c *Client) Close() error { return c.mc.Close() }

// State reports the connection state: the equivalent of libiec61850's
// IedConnection_getState. Dial returns a Client only once the association
// is up, so a fresh Client is StateConnected; it turns StateClosed when
// the peer or the transport drops the association, without a request
// having to fail first, and StateClosing while Close is in progress.
//
// Polling State is a way to observe a connection loss, not to guard a
// request: a request may still fail with the association dropping between
// the check and the call. Handle the request error as well.
func (c *Client) State() mms.State {
	if c == nil || c.mc == nil {
		return mms.StateClosed
	}
	return c.mc.State()
}

// Done returns a channel closed when the connection ends, whether from
// Close, a peer disconnect or a transport error. It replaces polling State
// with a wait, so a supervisor can sit in a select and reconnect the moment
// the IED drops the association:
//
//	select {
//	case <-c.Done():
//		log.Printf("connection lost: %v", c.Err())
//	case <-ctx.Done():
//	}
//
// By the time it fires, State reports mms.StateClosed and Err reports the
// cause. A nil or already-closed Client returns a closed channel.
func (c *Client) Done() <-chan struct{} {
	if c == nil || c.mc == nil {
		return closedChan
	}
	return c.mc.Done()
}

// Err returns the error that ended the association, or nil while it is
// still up. It tells a StateClosed connection that was closed locally
// (net.ErrClosed) apart from one the peer or the network dropped.
func (c *Client) Err() error {
	if c == nil || c.mc == nil {
		return net.ErrClosed
	}
	return c.mc.Err()
}

// LogicalDevices returns the logical device (MMS domain) names.
func (c *Client) LogicalDevices(ctx context.Context) ([]string, error) {
	return c.mc.GetNameList(ctx, mms.ClassDomain, "")
}

// LogicalNodes returns the logical node names within a logical device.
func (c *Client) LogicalNodes(ctx context.Context, ld string) ([]string, error) {
	names, err := c.mc.GetNameList(ctx, mms.ClassNamedVariable, ld)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var lns []string
	for _, n := range names {
		ln, _, found := strings.Cut(n, "$")
		if !found {
			ln = n // bare LN entry
		}
		if ln != "" && !seen[ln] {
			seen[ln] = true
			lns = append(lns, ln)
		}
	}
	return lns, nil
}

// Read reads the data attribute (or object) at ref under functional
// constraint fc and returns its value.
func (c *Client) Read(ctx context.Context, ref model.ObjectReference, fc model.FC) (*mms.Value, error) {
	domain, item := ref.ToMMS(fc)
	vals, err := c.mc.Read(ctx, domain, item)
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		return nil, mms.AccessObjectNonExistent
	}
	if code, isErr := vals[0].AccessError(); isErr {
		return nil, code
	}
	return vals[0], nil
}

// Write writes value to the data attribute at ref under functional
// constraint fc.
func (c *Client) Write(ctx context.Context, ref model.ObjectReference, fc model.FC, value *mms.Value) error {
	domain, item := ref.ToMMS(fc)
	results, err := c.mc.Write(ctx, domain, []string{item}, []*mms.Value{value})
	if err != nil {
		return err
	}
	if len(results) > 0 && results[0] != nil {
		return results[0]
	}
	return nil
}

// ReadValues reads several references (all under the same logical device)
// in one MMS Read request, returning values in order. All references must
// share a logical device; use separate calls for different devices.
func (c *Client) ReadValues(ctx context.Context, fc model.FC, refs ...model.ObjectReference) ([]*mms.Value, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	domain := refs[0].LD()
	items := make([]string, len(refs))
	for i, r := range refs {
		_, items[i] = r.ToMMS(fc)
	}
	return c.mc.Read(ctx, domain, items...)
}
