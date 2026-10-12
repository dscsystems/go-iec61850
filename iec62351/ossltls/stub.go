//go:build !openssl || !cgo

package ossltls

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/dscsystems/go-iec61850/iec62351"
)

// Available reports whether this build includes the OpenSSL engine.
func Available() bool { return false }

// Context is unavailable in this build.
type Context struct{}

// NewContext fails: this build has no OpenSSL.
func NewContext(iec62351.Options, Role) (*Context, error) { return nil, ErrUnavailable }

// Conn is unavailable in this build.
type Conn struct{ net.Conn }

// ConnectionState is empty in this build.
func (*Conn) ConnectionState() tls.ConnectionState { return tls.ConnectionState{} }

// Conn panics: no Context exists in this build. Falling back to the plain
// connection would silently drop the protection the caller asked for.
func (*Context) Conn(net.Conn) *Conn { panic(ErrUnavailable) }

// Handshake fails: this build has no OpenSSL.
func (*Context) Handshake(context.Context, net.Conn) (net.Conn, error) { return nil, ErrUnavailable }

// Listener panics, as Conn does.
func (*Context) Listener(net.Listener) net.Listener { panic(ErrUnavailable) }

// Close does nothing.
func (*Context) Close() {}
