// Package dh implements the Diffie-Hellman groups the security protocols of
// this module use: the 2048-bit MODP group of RFC 3526 (IKE group 14) and
// the NIST curves through crypto/ecdh. It is shared by gdoi (IEC 62351-9)
// and the IEC 62351-4 end-to-end security.
//
// Peer public values are always validated before use: a MODP value must lie
// strictly between 1 and p-1, and a curve point must be on the curve and
// not the identity (crypto/ecdh enforces the latter).
package dh

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Kind is a Diffie-Hellman group, independent of how a protocol numbers it.
type Kind uint8

const (
	MODP2048 Kind = iota + 1 // RFC 3526 group 14
	P256                     // secp256r1
	P384                     // secp384r1
)

func (k Kind) String() string {
	switch k {
	case MODP2048:
		return "MODP-2048"
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	}
	return fmt.Sprintf("dh.Kind(%d)", uint8(k))
}

// PointFormat selects how an elliptic-curve public value is encoded.
type PointFormat uint8

const (
	// Uncompressed is the SEC 1 uncompressed point 04||X||Y.
	Uncompressed PointFormat = iota
	// RawXY is X||Y without the prefix octet (RFC 5903, IKE).
	RawXY
)

var (
	modp2048P, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
	modpLen = 256
)

// ErrPeerValue is a peer public value that is malformed or out of range.
var ErrPeerValue = errors.New("dh: invalid peer public value")

// Key is one side's ephemeral key pair.
type Key struct {
	kind   Kind
	format PointFormat
	pub    []byte
	x      *big.Int
	ec     *ecdh.PrivateKey
}

func curve(k Kind) ecdh.Curve {
	switch k {
	case P256:
		return ecdh.P256()
	case P384:
		return ecdh.P384()
	}
	return nil
}

// Generate creates a fresh key pair. rnd nil means crypto/rand.
func Generate(k Kind, f PointFormat, rnd io.Reader) (*Key, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	if c := curve(k); c != nil {
		priv, err := c.GenerateKey(rnd)
		if err != nil {
			return nil, err
		}
		pub := priv.PublicKey().Bytes()
		if f == RawXY {
			pub = pub[1:]
		}
		return &Key{kind: k, format: f, pub: pub, ec: priv}, nil
	}
	if k != MODP2048 {
		return nil, fmt.Errorf("dh: unsupported group %v", k)
	}
	// A 512-bit exponent exceeds twice the ~112-bit strength of the group.
	x, err := rand.Int(rnd, new(big.Int).Lsh(big.NewInt(1), 512))
	if err != nil {
		return nil, err
	}
	if x.Sign() == 0 {
		x.SetInt64(2)
	}
	y := new(big.Int).Exp(big.NewInt(2), x, modp2048P)
	return &Key{kind: k, pub: y.FillBytes(make([]byte, modpLen)), x: x}, nil
}

// Kind returns the group of the key.
func (k *Key) Kind() Kind { return k.kind }

// Public returns the public value in the key's encoding.
func (k *Key) Public() []byte { return append([]byte(nil), k.pub...) }

// Shared computes the shared secret Z with the peer's public value: for a
// curve the X coordinate, for MODP the value left-padded to the modulus
// length.
func (k *Key) Shared(peer []byte) ([]byte, error) {
	if c := curve(k.kind); c != nil {
		p := peer
		if k.format == RawXY {
			p = append([]byte{4}, peer...)
		}
		pk, err := c.NewPublicKey(p)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPeerValue, err)
		}
		return k.ec.ECDH(pk)
	}
	if err := CheckPublic(k.kind, k.format, peer); err != nil {
		return nil, err
	}
	y := new(big.Int).SetBytes(peer)
	return new(big.Int).Exp(y, k.x, modp2048P).FillBytes(make([]byte, modpLen)), nil
}

// CheckPublic validates a peer public value without computing anything
// secret.
func CheckPublic(kind Kind, f PointFormat, peer []byte) error {
	if c := curve(kind); c != nil {
		p := peer
		if f == RawXY {
			p = append([]byte{4}, peer...)
		}
		if _, err := c.NewPublicKey(p); err != nil {
			return fmt.Errorf("%w: %v", ErrPeerValue, err)
		}
		return nil
	}
	if kind != MODP2048 {
		return fmt.Errorf("dh: unsupported group %v", kind)
	}
	if len(peer) != modpLen {
		return fmt.Errorf("%w: MODP value of %d octets", ErrPeerValue, len(peer))
	}
	y := new(big.Int).SetBytes(peer)
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(modp2048P, one)
	if y.Cmp(one) <= 0 || y.Cmp(pm1) >= 0 {
		return fmt.Errorf("%w: out of range", ErrPeerValue)
	}
	return nil
}

// Destroy drops references to the private key. Go cannot guarantee the
// memory is zeroed; this only shortens its reachable lifetime.
func (k *Key) Destroy() {
	if k == nil {
		return
	}
	if k.x != nil {
		k.x.SetInt64(0)
		k.x = nil
	}
	k.ec = nil
}

// FromPrivate builds a key from fixed private key octets: the scalar for a
// curve, the big-endian exponent for MODP. It exists for test vectors.
func FromPrivate(k Kind, f PointFormat, priv []byte) (*Key, error) {
	if c := curve(k); c != nil {
		p, err := c.NewPrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pub := p.PublicKey().Bytes()
		if f == RawXY {
			pub = pub[1:]
		}
		return &Key{kind: k, format: f, pub: pub, ec: p}, nil
	}
	if k != MODP2048 {
		return nil, fmt.Errorf("dh: unsupported group %v", k)
	}
	x := new(big.Int).SetBytes(priv)
	if x.Cmp(big.NewInt(1)) <= 0 || x.Cmp(new(big.Int).Sub(modp2048P, big.NewInt(1))) >= 0 {
		return nil, errors.New("dh: exponent outside [2, p-2]")
	}
	y := new(big.Int).Exp(big.NewInt(2), x, modp2048P)
	return &Key{kind: k, pub: y.FillBytes(make([]byte, modpLen)), x: x}, nil
}

// MODPLen is the length of a MODP-2048 public value and shared secret.
const MODPLen = 256
