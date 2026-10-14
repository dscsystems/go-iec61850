//go:build openssl && openssl_v1 && cgo

package ossltls

// The build tag openssl_v1 selects OpenSSL 1.0.2, the engine "openssl-v1".
// The tag, not only the headers pkg-config finds, decides it: Go's build
// cache does not see which OpenSSL pkg-config points at, so without a tag
// of their own the two builds would reuse each other's objects. The C code
// refuses a tag that does not match the headers.

// #cgo CFLAGS: -DDD_OPENSSL_V1
import "C"
