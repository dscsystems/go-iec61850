//go:build openssl && cgo

package ossltls

/*
#cgo pkg-config: libssl libcrypto
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdlib.h>

// Peer certificates are accepted during the handshake and verified in Go
// afterwards (iec62351.Options.VerifyPeer).
static int dd_accept_cb(int ok, X509_STORE_CTX *c) { (void)ok; (void)c; return 1; }

static SSL_CTX *dd_ctx_new(int server, int minv, int maxv, const char *ciphers, const char *suites13,
                           const char *groups, int tickets) {
	SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
	if (!ctx) return NULL;
	if (SSL_CTX_set_min_proto_version(ctx, minv) != 1 || SSL_CTX_set_max_proto_version(ctx, maxv) != 1 ||
	    SSL_CTX_set_cipher_list(ctx, ciphers) != 1 || SSL_CTX_set_ciphersuites(ctx, suites13) != 1 ||
	    SSL_CTX_set1_groups_list(ctx, groups) != 1) {
		SSL_CTX_free(ctx);
		return NULL;
	}
	SSL_CTX_set_dh_auto(ctx, 1);
	SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);
	if (!tickets) SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
	SSL_CTX_set_verify(ctx, server ? (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT) : SSL_VERIFY_PEER,
	                   dd_accept_cb);
	return ctx;
}

static int dd_ctx_cert(SSL_CTX *ctx, const unsigned char *der, long n, int chain) {
	X509 *x = d2i_X509(NULL, &der, n);
	if (!x) return 0;
	int r = chain ? SSL_CTX_add1_chain_cert(ctx, x) : SSL_CTX_use_certificate(ctx, x);
	X509_free(x);
	return r;
}

static int dd_ctx_key(SSL_CTX *ctx, const unsigned char *der, long n) {
	EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &der, n);
	if (!k) return 0;
	int r = SSL_CTX_use_PrivateKey(ctx, k);
	EVP_PKEY_free(k);
	return r == 1 && SSL_CTX_check_private_key(ctx) == 1;
}

static SSL *dd_ssl_new(SSL_CTX *ctx, int server, const char *sni) {
	SSL *s = SSL_new(ctx);
	if (!s) return NULL;
	BIO *r = BIO_new(BIO_s_mem()), *w = BIO_new(BIO_s_mem());
	BIO_set_mem_eof_return(r, -1);
	BIO_set_mem_eof_return(w, -1);
	SSL_set_bio(s, r, w);
	if (server) {
		SSL_set_accept_state(s);
	} else {
		SSL_set_connect_state(s);
		if (sni && sni[0]) SSL_set_tlsext_host_name(s, sni);
	}
	return s;
}

// dd_op runs one operation and collects its error on the same OS thread,
// where OpenSSL keeps its error queue.
enum { OP_HANDSHAKE, OP_READ, OP_WRITE, OP_SHUTDOWN };
static int dd_op(SSL *s, int op, void *buf, int n, int *sslerr, char *ebuf, int elen) {
	ERR_clear_error();
	int r = 0;
	switch (op) {
	case OP_HANDSHAKE: r = SSL_do_handshake(s); break;
	case OP_READ: r = SSL_read(s, buf, n); break;
	case OP_WRITE: r = SSL_write(s, buf, n); break;
	case OP_SHUTDOWN: r = SSL_shutdown(s); break;
	}
	*sslerr = r > 0 ? SSL_ERROR_NONE : SSL_get_error(s, r);
	ebuf[0] = 0;
	unsigned long e = ERR_peek_last_error();
	if (e) ERR_error_string_n(e, ebuf, elen);
	ERR_clear_error();
	return r;
}

static int dd_feed(SSL *s, const void *buf, int n) { return BIO_write(SSL_get_rbio(s), buf, n); }
static int dd_drain(SSL *s, void *buf, int n) { return BIO_read(SSL_get_wbio(s), buf, n); }
static size_t dd_pending(SSL *s) { return BIO_ctrl_pending(SSL_get_wbio(s)); }

static int dd_suite(SSL *s) {
	const SSL_CIPHER *c = SSL_get_current_cipher(s);
	return c ? SSL_CIPHER_get_protocol_id(c) : 0;
}

// dd_peer returns the DER of the peer's certificate i (0 the leaf, then
// the chain it sent), or NULL past the end; free it with dd_free.
static unsigned char *dd_peer(SSL *s, int i, int *n) {
	X509 *x = NULL;
	*n = 0;
	if (i == 0) {
		x = SSL_get1_peer_certificate(s);
	} else {
		STACK_OF(X509) *sk = SSL_get_peer_cert_chain(s);
		if (!sk) return NULL;
		// A client's view of the chain starts with the server's leaf.
		int off = SSL_is_server(s) ? 0 : 1;
		if (i - 1 + off >= sk_X509_num(sk)) return NULL;
		x = X509_dup(sk_X509_value(sk, i - 1 + off));
	}
	if (!x) return NULL;
	unsigned char *der = NULL;
	*n = i2d_X509(x, &der);
	X509_free(x);
	return *n > 0 ? der : NULL;
}

static void dd_free(void *p) { OPENSSL_free(p); }

// dd_last_error describes and clears the thread's OpenSSL error queue.
static void dd_last_error(char *buf, int n) {
	buf[0] = 0;
	unsigned long e = ERR_peek_last_error();
	if (e) ERR_error_string_n(e, buf, n);
	ERR_clear_error();
}
*/
import "C"

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/dscsystems/go-iec61850/iec62351"
)

// Available reports whether this build includes the OpenSSL engine.
func Available() bool { return true }

// Context is an OpenSSL configuration for one role, shared by every
// connection made with it.
type Context struct {
	ctx  *C.SSL_CTX
	role Role
	o    iec62351.Options
	mu   sync.Mutex // guards ctx against Close
}

// NewContext builds the configuration for role from the profile options:
// Certificates[0] is this end's identity, Roots and CRLs check the peer,
// NativeMode selects the IEC 62351-4 Table 10 suites (TLS 1.2), otherwise
// the IEC 62351-3 ones (TLS 1.2 and 1.3, or 1.3 only with TLS13Only).
func NewContext(o iec62351.Options, role Role) (*Context, error) {
	return newContext(o, role, "")
}

// newContext is NewContext with the TLS 1.2 cipher list overridden (tests).
func newContext(o iec62351.Options, role Role, ciphers12 string) (*Context, error) {
	if len(o.Certificates) == 0 || len(o.Certificates[0].Certificate) == 0 {
		return nil, errors.New("ossltls: Options.Certificates is required")
	}
	if o.Roots == nil {
		return nil, errors.New("ossltls: Options.Roots is required")
	}
	minv, maxv := C.int(C.TLS1_2_VERSION), C.int(C.TLS1_3_VERSION)
	ciphers := profileCiphers
	if o.TLS13Only {
		minv = C.TLS1_3_VERSION
	}
	if o.NativeMode {
		if o.TLS13Only {
			return nil, errors.New("ossltls: NativeMode is a TLS 1.2 profile")
		}
		maxv, ciphers = C.TLS1_2_VERSION, nativeCiphers
	}
	if ciphers12 != "" {
		ciphers = ciphers12
	}
	cc, cs, cg := C.CString(ciphers), C.CString(tls13Suites), C.CString(groups)
	defer C.free(unsafe.Pointer(cc))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(cg))
	tickets := C.int(0)
	if o.NativeMode {
		tickets = 1 // resumption, IEC 62351-4 6.2.3
	}
	ctx := C.dd_ctx_new(C.int(role), minv, maxv, cc, cs, cg, tickets)
	if ctx == nil {
		return nil, errors.New("ossltls: cannot create the OpenSSL context (cipher or group list refused)")
	}
	c := &Context{ctx: ctx, role: role, o: o}
	runtime.SetFinalizer(c, (*Context).Close)
	// The setup runs on one OS thread, where OpenSSL keeps its error queue.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	id := o.Certificates[0]
	for i, der := range id.Certificate {
		if C.dd_ctx_cert(ctx, (*C.uchar)(unsafe.Pointer(&der[0])), C.long(len(der)), C.int(min(i, 1))) != 1 {
			c.Close()
			return nil, fmt.Errorf("ossltls: certificate %d refused by OpenSSL: %s", i, lastError())
		}
	}
	key, err := x509.MarshalPKCS8PrivateKey(id.PrivateKey)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("ossltls: private key: %w", err)
	}
	if C.dd_ctx_key(ctx, (*C.uchar)(unsafe.Pointer(&key[0])), C.long(len(key))) != 1 {
		c.Close()
		return nil, fmt.Errorf("ossltls: private key refused by OpenSSL or does not match the certificate: %s", lastError())
	}
	return c, nil
}

func lastError() string {
	var buf [256]C.char
	C.dd_last_error(&buf[0], C.int(len(buf)))
	return C.GoString(&buf[0])
}

// Close frees the OpenSSL context; connections made with it keep their own
// reference.
func (c *Context) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx != nil {
		C.SSL_CTX_free(c.ctx)
		c.ctx = nil
	}
}

// Conn wraps raw in a TLS connection whose handshake runs on first use or
// on HandshakeContext, as tls.Client and tls.Server do.
func (c *Context) Conn(raw net.Conn) *Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	var sni *C.char
	if c.role == Client && c.o.ServerName != "" && net.ParseIP(c.o.ServerName) == nil {
		sni = C.CString(c.o.ServerName)
		defer C.free(unsafe.Pointer(sni))
	}
	cn := &Conn{raw: raw, c: c}
	if c.ctx != nil {
		cn.ssl = C.dd_ssl_new(c.ctx, C.int(c.role), sni)
	}
	runtime.SetFinalizer(cn, (*Conn).free)
	return cn
}

// Handshake wraps raw and completes the handshake under ctx.
func (c *Context) Handshake(ctx context.Context, raw net.Conn) (net.Conn, error) {
	cn := c.Conn(raw)
	if err := cn.HandshakeContext(ctx); err != nil {
		cn.free()
		return nil, err
	}
	return cn, nil
}

// Listener returns a listener whose connections are server-side TLS
// connections of this context, handshaking on first use.
func (c *Context) Listener(ln net.Listener) net.Listener { return &listener{ln, c} }

type listener struct {
	net.Listener
	c *Context
}

func (l *listener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.c.Conn(raw), nil
}

// Conn is a TLS connection run by OpenSSL. It is safe for one reader and
// any number of writers at a time, like crypto/tls.Conn.
type Conn struct {
	raw net.Conn
	c   *Context

	mu     sync.Mutex // guards ssl
	ssl    *C.SSL
	closed bool
	wmu    sync.Mutex // orders writes to raw
	out    sync.Mutex // one Write at a time, so its records stay together
	rmu    sync.Mutex // one reader of raw

	hsMu   sync.Mutex
	hsDone bool
	hsErr  error
	state  tls.ConnectionState
	rbuf   [16 << 10]byte
}

const (
	opHandshake = C.OP_HANDSHAKE
	opRead      = C.OP_READ
	opWrite     = C.OP_WRITE
	opShutdown  = C.OP_SHUTDOWN
)

// op runs an OpenSSL operation; c.mu must be held.
func (c *Conn) op(op C.int, b []byte) (int, C.int, string) {
	if c.ssl == nil {
		return -1, C.SSL_ERROR_SSL, "connection closed"
	}
	var p unsafe.Pointer
	if len(b) > 0 {
		p = unsafe.Pointer(&b[0])
	}
	var se C.int
	var ebuf [256]C.char
	r := C.dd_op(c.ssl, op, p, C.int(len(b)), &se, &ebuf[0], C.int(len(ebuf)))
	return int(r), se, C.GoString(&ebuf[0])
}

// flush sends what OpenSSL produced. It is called with c.mu held and
// releases it, taking wmu first so output leaves in the order produced.
func (c *Conn) flush() error {
	var out []byte
	if c.ssl != nil {
		for C.dd_pending(c.ssl) > 0 {
			var buf [16 << 10]byte
			n := C.dd_drain(c.ssl, unsafe.Pointer(&buf[0]), C.int(len(buf)))
			if n <= 0 {
				break
			}
			out = append(out, buf[:n]...)
		}
	}
	c.wmu.Lock()
	c.mu.Unlock()
	defer c.wmu.Unlock()
	if len(out) == 0 {
		return nil
	}
	_, err := c.raw.Write(out)
	return err
}

// fill reads from raw into OpenSSL; rmu must be held.
func (c *Conn) fill() error {
	n, err := c.raw.Read(c.rbuf[:])
	if n > 0 {
		c.mu.Lock()
		if c.ssl != nil {
			C.dd_feed(c.ssl, unsafe.Pointer(&c.rbuf[0]), C.int(n))
		}
		c.mu.Unlock()
		return nil
	}
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func opError(what string, se C.int, detail string) error {
	if detail == "" {
		detail = fmt.Sprintf("SSL error %d", int(se))
	}
	return fmt.Errorf("ossltls: %s: %s", what, detail)
}

// HandshakeContext runs the handshake if it has not run, then verifies the
// peer with the profile's checks.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	if c.hsDone {
		return c.hsErr
	}
	c.hsDone = true
	if dl, ok := ctx.Deadline(); ok {
		c.raw.SetDeadline(dl)
		defer c.raw.SetDeadline(time.Time{})
	}
	stop := context.AfterFunc(ctx, func() { c.raw.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	c.hsErr = c.handshake()
	if c.hsErr == nil {
		c.hsErr = c.verify()
	}
	if c.hsErr != nil {
		// The context ends the handshake through the transport deadline, so
		// the read fails first; report the context's reason.
		if err := ctx.Err(); err != nil {
			c.hsErr = fmt.Errorf("ossltls: handshake: %w", err)
		} else if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) {
			c.hsErr = fmt.Errorf("ossltls: handshake: %w", context.DeadlineExceeded)
		}
	}
	return c.hsErr
}

func (c *Conn) handshake() error {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		c.mu.Lock()
		r, se, detail := c.op(opHandshake, nil)
		if err := c.flush(); err != nil {
			return fmt.Errorf("ossltls: handshake: %w", err)
		}
		if r == 1 {
			return nil
		}
		if se != C.SSL_ERROR_WANT_READ {
			return opError("handshake", se, detail)
		}
		if err := c.fill(); err != nil {
			return fmt.Errorf("ossltls: handshake: %w", err)
		}
	}
}

// verify collects the negotiated state and applies the profile's checks.
func (c *Conn) verify() error {
	c.mu.Lock()
	st := tls.ConnectionState{HandshakeComplete: true, Version: uint16(C.SSL_version(c.ssl)),
		CipherSuite: uint16(C.dd_suite(c.ssl)), ServerName: c.c.o.ServerName}
	var certs []*x509.Certificate
	for i := 0; ; i++ {
		var n C.int
		der := C.dd_peer(c.ssl, C.int(i), &n)
		if der == nil {
			break
		}
		b := C.GoBytes(unsafe.Pointer(der), n)
		C.dd_free(unsafe.Pointer(der))
		x, err := x509.ParseCertificate(b)
		if err != nil {
			c.mu.Unlock()
			return fmt.Errorf("ossltls: peer certificate %d: %w", i, err)
		}
		certs = append(certs, x)
	}
	st.PeerCertificates = certs
	c.state = st
	c.mu.Unlock()
	o := c.c.o
	if c.c.role == Server {
		o.ServerName = "" // names the server; not checked on clients
	}
	return o.VerifyPeer(certs)
}

// ConnectionState reports the negotiated version, suite (IANA value, see
// SuiteName) and the peer's certificates.
func (c *Conn) ConnectionState() tls.ConnectionState {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	return c.state
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		c.mu.Lock()
		n, se, detail := c.op(opRead, b)
		if err := c.flush(); err != nil && n <= 0 {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
		switch se {
		case C.SSL_ERROR_WANT_READ:
			if err := c.fill(); err != nil {
				return 0, err
			}
		case C.SSL_ERROR_ZERO_RETURN:
			return 0, io.EOF
		default:
			return 0, opError("read", se, detail)
		}
	}
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}
	c.out.Lock()
	defer c.out.Unlock()
	total := 0
	for len(b) > 0 {
		chunk := b[:min(len(b), 16<<10)]
		c.mu.Lock()
		n, se, detail := c.op(opWrite, chunk)
		if err := c.flush(); err != nil {
			return total, err
		}
		if n <= 0 {
			return total, opError("write", se, detail)
		}
		total += n
		b = b[n:]
	}
	return total, nil
}

// Close sends close_notify after a completed handshake and closes the
// transport.
func (c *Conn) Close() error {
	c.hsMu.Lock()
	done := c.hsDone && c.hsErr == nil
	c.hsMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if done {
		c.raw.SetWriteDeadline(time.Now().Add(time.Second))
		c.op(opShutdown, nil)
		c.flush()
	} else {
		c.mu.Unlock()
	}
	err := c.raw.Close()
	c.free()
	return err
}

// free releases the OpenSSL connection.
func (c *Conn) free() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ssl != nil {
		C.SSL_free(c.ssl)
		c.ssl = nil
	}
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
