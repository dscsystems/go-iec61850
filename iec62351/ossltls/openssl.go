//go:build openssl && cgo

package ossltls

/*
#cgo pkg-config: libssl libcrypto
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <stdlib.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(DD_OPENSSL_V1)
#error "these are OpenSSL 1.0.2 headers: build with -tags openssl,openssl_v1"
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L && defined(DD_OPENSSL_V1)
#error "the build tag openssl_v1 needs OpenSSL 1.0.2: point pkg-config at it"
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// OpenSSL 1.0.2, the last release with the static-DH suites: the engine
// "openssl-v1". It needs explicit initialisation and locking callbacks, and
// names some functions differently.
#define DD_LEGACY 1
#include <openssl/bn.h>
#include <openssl/dh.h>

#ifdef _WIN32
// Windows (MinGW-w64): critical sections and thread IDs, so the binary
// needs no winpthreads DLL. NOCRYPT keeps wincrypt.h, whose X509_NAME and
// friends clash with OpenSSL's, out.
#define WIN32_LEAN_AND_MEAN
#define NOCRYPT
#include <windows.h>
typedef CRITICAL_SECTION dd_mutex;
#define dd_mutex_init(m) InitializeCriticalSection(m)
#define dd_mutex_lock(m) EnterCriticalSection(m)
#define dd_mutex_unlock(m) LeaveCriticalSection(m)
#define dd_self() ((unsigned long)GetCurrentThreadId())
#else
#include <pthread.h>
typedef pthread_mutex_t dd_mutex;
#define dd_mutex_init(m) pthread_mutex_init(m, NULL)
#define dd_mutex_lock(m) pthread_mutex_lock(m)
#define dd_mutex_unlock(m) pthread_mutex_unlock(m)
#define dd_self() ((unsigned long)pthread_self())
#endif

static dd_mutex *dd_locks;
static void dd_lock(int mode, int n, const char *file, int line) {
	(void)file; (void)line;
	if (mode & CRYPTO_LOCK) dd_mutex_lock(&dd_locks[n]);
	else dd_mutex_unlock(&dd_locks[n]);
}
static void dd_thread_id(CRYPTO_THREADID *id) { CRYPTO_THREADID_set_numeric(id, dd_self()); }
static int dd_init(void) {
	SSL_library_init();
	SSL_load_error_strings();
	int n = CRYPTO_num_locks();
	dd_locks = OPENSSL_malloc(n * sizeof(dd_mutex));
	if (!dd_locks) return 0;
	for (int i = 0; i < n; i++) dd_mutex_init(&dd_locks[i]);
	CRYPTO_THREADID_set_callback(dd_thread_id);
	CRYPTO_set_locking_callback(dd_lock);
	return 1;
}
static const char *dd_version(void) { return SSLeay_version(SSLEAY_VERSION); }
static int dd_cipher_id(const SSL_CIPHER *c) { return SSL_CIPHER_get_id(c) & 0xFFFF; }
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION 0x0304
#endif

// 1.0.2 cannot switch renegotiation off. The info callback marks a
// handshake starting after the first completed (app data 1, then 2), and
// the engine drops the connection before anything of it is sent. App data
// 3 exempts a connection (tests renegotiating on purpose).
static void dd_info_cb(const SSL *cs, int where, int ret) {
	SSL *s = (SSL *)cs;
	(void)ret;
	if ((where & SSL_CB_HANDSHAKE_DONE) && SSL_get_app_data(s) == NULL) SSL_set_app_data(s, (void *)1);
	else if ((where & SSL_CB_HANDSHAKE_START) && SSL_get_app_data(s) == (void *)1) SSL_set_app_data(s, (void *)2);
}
static int dd_renegotiating(SSL *s) { return SSL_get_app_data(s) == (void *)2; }
static int dd_renegotiate(SSL *s) {
	SSL_set_app_data(s, (void *)3);
	return SSL_renegotiate(s) == 1 && SSL_do_handshake(s) <= 0 && SSL_get_error(s, -1) == SSL_ERROR_WANT_READ;
}

// dd_tmp_dh sets the DHE group: RFC 3526 group 14 (2048 bits), the size
// OpenSSL 3 picks for a 2048-bit RSA certificate.
static int dd_tmp_dh(SSL_CTX *ctx) {
	DH *dh = DH_new();
	if (!dh) return 0;
	dh->p = get_rfc3526_prime_2048(NULL);
	dh->g = BN_new();
	int r = dh->p && dh->g && BN_set_word(dh->g, 2) && SSL_CTX_set_tmp_dh(ctx, dh) == 1;
	DH_free(dh);
	return r;
}
#else
#define DD_LEGACY 0
static int dd_init(void) { return 1; }
static const char *dd_version(void) { return OpenSSL_version(OPENSSL_VERSION); }
static int dd_cipher_id(const SSL_CIPHER *c) { return SSL_CIPHER_get_protocol_id(c); }
static int dd_renegotiating(SSL *s) { (void)s; return 0; } // SSL_OP_NO_RENEGOTIATION
static int dd_renegotiate(SSL *s) { (void)s; return 0; }
#endif

static int dd_legacy(void) { return DD_LEGACY; }

// Peer certificates are accepted during the handshake and verified in Go
// afterwards (iec62351.Options.VerifyPeer).
static int dd_accept_cb(int ok, X509_STORE_CTX *c) { (void)ok; (void)c; return 1; }

static SSL_CTX *dd_ctx_new(int server, int minv, int maxv, const char *ciphers, const char *suites13,
                           const char *groups, int tickets) {
#if DD_LEGACY
	// TLS 1.2 only: 1.0.2 has no TLS 1.3, and the older versions are off.
	(void)suites13;
	if (minv > TLS1_2_VERSION || maxv < TLS1_2_VERSION) return NULL;
	SSL_CTX *ctx = SSL_CTX_new(server ? SSLv23_server_method() : SSLv23_client_method());
	if (!ctx) return NULL;
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	if (SSL_CTX_set_cipher_list(ctx, ciphers) != 1 || SSL_CTX_set1_curves_list(ctx, groups) != 1 ||
	    SSL_CTX_set_ecdh_auto(ctx, 1) != 1 || !dd_tmp_dh(ctx)) {
		SSL_CTX_free(ctx);
		return NULL;
	}
	SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	SSL_CTX_set_info_callback(ctx, dd_info_cb);
#else
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
#endif
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

// dd_ctx_dh adds the server's static-DH certificate and its PKCS #3 key,
// which OpenSSL 1.0.2 keeps beside the RSA identity and serves the
// TLS_DH_RSA_* suites with. Chain certificates added next go with it.
static int dd_ctx_dh(SSL_CTX *ctx, const unsigned char *cert, long cn, const unsigned char *key, long kn) {
#if DD_LEGACY
	X509 *x = d2i_X509(NULL, &cert, cn);
	if (!x) return 0;
	int r = SSL_CTX_use_certificate(ctx, x);
	X509_free(x);
	if (r != 1) return 0;
	EVP_PKEY *k = d2i_AutoPrivateKey(NULL, &key, kn);
	if (!k) return 0;
	r = SSL_CTX_use_PrivateKey(ctx, k);
	EVP_PKEY_free(k);
	return r == 1 && SSL_CTX_check_private_key(ctx) == 1;
#else
	(void)ctx; (void)cert; (void)cn; (void)key; (void)kn;
	return 0;
#endif
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
	return c ? dd_cipher_id(c) : 0;
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
	"crypto/x509/pkix"
	"encoding/asn1"
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

// Legacy reports whether the build links OpenSSL 1.0.2 (the engine
// "openssl-v1"): TLS 1.2 only, and in native mode the static-DH suites.
func Legacy() bool { return C.dd_legacy() == 1 }

// Version is the linked OpenSSL's version string.
func Version() string { return C.GoString(C.dd_version()) }

var (
	initOnce sync.Once
	initErr  error
)

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
	if role == Client {
		if err := o.CheckServerName(); err != nil {
			return nil, err
		}
	}
	return newContext(o, role, "")
}

// newContext is NewContext with the TLS 1.2 cipher list overridden (tests).
func newContext(o iec62351.Options, role Role, ciphers12 string) (*Context, error) {
	initOnce.Do(func() {
		if C.dd_init() != 1 {
			initErr = errors.New("ossltls: cannot initialise OpenSSL")
		}
	})
	if initErr != nil {
		return nil, initErr
	}
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
	if Legacy() {
		if o.TLS13Only {
			return nil, fmt.Errorf("ossltls: %s has no TLS 1.3", Version())
		}
		maxv = C.TLS1_2_VERSION
		if o.NativeMode {
			ciphers = nativeCiphersV1
		}
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

// SetStaticDH adds a server's certificate with a fixed Diffie-Hellman key,
// for the static-DH suites of IEC 62351-4 Table 10 (TLS_DH_RSA_*). chain is
// the certificate and its intermediates, DER, leaf first; key is its
// private key, PKCS #8 DER. Both must be PKCS #3 (dhKeyAgreement): OpenSSL
// 1.0.2 serves no X9.42 (dhpublicnumber) key. It needs a Legacy build and a
// Server context, and keeps the RSA identity for the other suites.
func (c *Context) SetStaticDH(chain [][]byte, key []byte) error {
	if !Legacy() {
		return fmt.Errorf("ossltls: static DH needs OpenSSL 1.0.2 (engine openssl-v1); this build links %s", Version())
	}
	if c.role != Server {
		return errors.New("ossltls: a static-DH certificate is for the server")
	}
	if len(chain) == 0 || len(chain[0]) == 0 || len(key) == 0 {
		return errors.New("ossltls: static DH needs a certificate and a key")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return fmt.Errorf("ossltls: static-DH certificate: %w", err)
	}
	bits, ok := iec62351.DHPrimeBits(leaf)
	if !ok {
		return fmt.Errorf("ossltls: static-DH certificate %s holds no Diffie-Hellman key", leaf.Subject)
	}
	if bits < iec62351.MinDHBits {
		return fmt.Errorf("ossltls: static-DH certificate %s: %d-bit prime, want %d or more", leaf.Subject, bits, iec62351.MinDHBits)
	}
	if alg, ok := keyAlgorithm(leaf.RawSubjectPublicKeyInfo, false); !ok || !alg.Equal(oidDHKeyAgreement) {
		return fmt.Errorf("ossltls: static-DH certificate %s: the key must be PKCS #3 DH (dhKeyAgreement), not X9.42", leaf.Subject)
	}
	if alg, ok := keyAlgorithm(key, true); !ok || !alg.Equal(oidDHKeyAgreement) {
		return errors.New("ossltls: static-DH key: want a PKCS #8 PKCS #3 DH (dhKeyAgreement) private key")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ctx == nil {
		return errors.New("ossltls: context closed")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.dd_ctx_dh(c.ctx, (*C.uchar)(unsafe.Pointer(&chain[0][0])), C.long(len(chain[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])), C.long(len(key))) != 1 {
		return fmt.Errorf("ossltls: static-DH certificate or key refused, or they do not match: %s", lastError())
	}
	for i, der := range chain[1:] {
		if len(der) == 0 || C.dd_ctx_cert(c.ctx, (*C.uchar)(unsafe.Pointer(&der[0])), C.long(len(der)), 1) != 1 {
			return fmt.Errorf("ossltls: static-DH chain certificate %d refused: %s", i+1, lastError())
		}
	}
	return nil
}

var oidDHKeyAgreement = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1}

// keyAlgorithm returns the algorithm of a SubjectPublicKeyInfo or, with
// private, of a PKCS #8 PrivateKeyInfo.
func keyAlgorithm(der []byte, private bool) (asn1.ObjectIdentifier, bool) {
	if private {
		var k struct {
			Version   int
			Algorithm pkix.AlgorithmIdentifier
			Key       []byte
		}
		if _, err := asn1.Unmarshal(der, &k); err != nil {
			return nil, false
		}
		return k.Algorithm.Algorithm, true
	}
	var k struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &k); err != nil {
		return nil, false
	}
	return k.Algorithm.Algorithm, true
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
	n, err := c.raw.Write(out)
	if err == nil && n < len(out) {
		err = io.ErrShortWrite
	}
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

// ErrRenegotiation reports a peer starting a renegotiation, which the
// engine refuses by dropping the connection (IEC 62351-4 6.2.4 leaves
// rekeying to the application layer).
var ErrRenegotiation = errors.New("ossltls: peer started a renegotiation; connection dropped")

// refuseRenegotiation, called with c.mu held after an operation, drops the
// connection when that operation started a renegotiation (OpenSSL 1.0.2,
// which cannot refuse one itself), before any of it is sent. It releases
// c.mu when it returns an error.
func (c *Conn) refuseRenegotiation() error {
	if c.ssl == nil || C.dd_renegotiating(c.ssl) != 1 {
		return nil
	}
	c.mu.Unlock()
	c.raw.Close()
	return ErrRenegotiation
}

// renegotiate starts a renegotiation from this end, exempt from the
// refusal (tests).
func (c *Conn) renegotiate() error {
	c.mu.Lock()
	if c.ssl == nil || C.dd_renegotiate(c.ssl) != 1 {
		c.mu.Unlock()
		return errors.New("ossltls: cannot start a renegotiation")
	}
	return c.flush()
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
	fired := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		c.raw.SetDeadline(time.Unix(1, 0))
		close(fired)
	})
	defer func() {
		// A context ending as the handshake completes must not leave the
		// expired deadline on a live connection: wait for it, then clear it.
		if !stop() {
			<-fired
			c.raw.SetDeadline(time.Time{})
		}
	}()
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
		if err := c.refuseRenegotiation(); err != nil {
			return 0, err
		}
		if err := c.flush(); err != nil && n <= 0 {
			return 0, err
		}
		if n > 0 {
			return n, nil
		}
		switch se {
		case C.SSL_ERROR_WANT_READ:
			if err := c.fill(); err != nil {
				if err == io.EOF {
					// The transport ended without close_notify: truncation,
					// not the orderly close of SSL_ERROR_ZERO_RETURN.
					err = io.ErrUnexpectedEOF
				}
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
		if err := c.refuseRenegotiation(); err != nil {
			return total, err
		}
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
