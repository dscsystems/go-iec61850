package rsession

import (
	"errors"
	"fmt"
	"sync"
)

// SecAlgorithm is the encryption algorithm of a key.
type SecAlgorithm uint8

// The encryption algorithms. The values are the ones libiec61850 uses;
// in protocol version 1 they are carried on the wire.
const (
	SecNone      SecAlgorithm = 0
	SecAES128GCM SecAlgorithm = 1
	SecAES256GCM SecAlgorithm = 2
)

func (a SecAlgorithm) String() string {
	switch a {
	case SecNone:
		return "none"
	case SecAES128GCM:
		return "AES-128-GCM"
	case SecAES256GCM:
		return "AES-256-GCM"
	}
	return fmt.Sprintf("SecAlgorithm(%d)", uint8(a))
}

// keyLen is the key length the algorithm requires, 0 for none.
func (a SecAlgorithm) keyLen() int {
	switch a {
	case SecAES128GCM:
		return 16
	case SecAES256GCM:
		return 32
	}
	return 0
}

// SigAlgorithm is the message authentication algorithm of a key.
type SigAlgorithm uint8

// The authentication algorithms, numbered as libiec61850 numbers them; in
// protocol version 1 they are carried on the wire. The HMACs are truncated
// to their leftmost octets. The AES-GMAC variants (4 and 5) are not
// implemented: a key naming one is refused.
const (
	SigNone           SigAlgorithm = 0
	SigHMACSHA256_80  SigAlgorithm = 1
	SigHMACSHA256_128 SigAlgorithm = 2
	SigHMACSHA256_256 SigAlgorithm = 3
	SigAESGMAC64      SigAlgorithm = 4
	SigAESGMAC128     SigAlgorithm = 5
	SigHMACSHA3_80    SigAlgorithm = 6
	SigHMACSHA3_128   SigAlgorithm = 7
	SigHMACSHA3_256   SigAlgorithm = 8
)

func (a SigAlgorithm) String() string {
	switch a {
	case SigNone:
		return "none"
	case SigHMACSHA256_80:
		return "HMAC-SHA256-80"
	case SigHMACSHA256_128:
		return "HMAC-SHA256-128"
	case SigHMACSHA256_256:
		return "HMAC-SHA256-256"
	case SigAESGMAC64:
		return "AES-GMAC-64"
	case SigAESGMAC128:
		return "AES-GMAC-128"
	case SigHMACSHA3_80:
		return "HMAC-SHA3-80"
	case SigHMACSHA3_128:
		return "HMAC-SHA3-128"
	case SigHMACSHA3_256:
		return "HMAC-SHA3-256"
	}
	return fmt.Sprintf("SigAlgorithm(%d)", uint8(a))
}

// macLen is the length of the truncated MAC, 0 for none or an
// unsupported algorithm.
func (a SigAlgorithm) macLen() int {
	switch a {
	case SigHMACSHA256_80, SigHMACSHA3_80:
		return 10
	case SigHMACSHA256_128, SigHMACSHA3_128:
		return 16
	case SigHMACSHA256_256, SigHMACSHA3_256:
		return 32
	}
	return 0
}

// minHMACKey is the shortest HMAC key accepted: 128 bits, the security
// level of the shortest tag worth having.
const minHMACKey = 16

// Key is the key material of one security association: its identifier,
// the secret, the algorithms it is used with, and the key timing the
// header carries.
type Key struct {
	ID uint32 // 0 is reserved for "no key"
	// Material is the secret. An AES key is 16 or 32 octets as the
	// algorithm requires; an HMAC key at least 16.
	Material []byte
	Sec      SecAlgorithm
	Sig      SigAlgorithm
	// TimeOfCurrentKey and TimeToNextKey are carried in every SPDU sent
	// under the key, as the key distribution center issued them
	// (IEC 62351-9). The session layer does not interpret them.
	TimeOfCurrentKey uint32
	TimeToNextKey    int16
}

// Errors of key configuration.
var (
	ErrKeyID          = errors.New("rsession: key ID 0 is reserved")
	ErrKeyAlgorithm   = errors.New("rsession: key has no algorithm")
	ErrKeyUnsupported = errors.New("rsession: algorithm not supported")
	ErrKeyLength      = errors.New("rsession: key length does not suit the algorithm")
	ErrKeyCombination = errors.New("rsession: a key either encrypts or signs")
)

// validate checks that the key is usable as configured.
func (k *Key) validate() error {
	if k.ID == 0 {
		return ErrKeyID
	}
	if k.Sec == SecNone && k.Sig == SigNone {
		return ErrKeyAlgorithm
	}
	// AES-GCM authenticates what it encrypts, and the only other
	// implementation of the protocol lays out an HMAC over an encrypted
	// payload in a way no receiver can verify; a key does one or the
	// other.
	if k.Sec != SecNone && k.Sig != SigNone {
		return ErrKeyCombination
	}
	switch {
	case k.Sec != SecNone:
		n := k.Sec.keyLen()
		if n == 0 {
			return fmt.Errorf("%w: %v", ErrKeyUnsupported, k.Sec)
		}
		if len(k.Material) != n {
			return fmt.Errorf("%w: %v needs %d octets, have %d", ErrKeyLength, k.Sec, n, len(k.Material))
		}
	default:
		if k.Sig.macLen() == 0 {
			return fmt.Errorf("%w: %v", ErrKeyUnsupported, k.Sig)
		}
		if len(k.Material) < minHMACKey {
			return fmt.Errorf("%w: %v needs at least %d octets, have %d", ErrKeyLength, k.Sig, minHMACKey, len(k.Material))
		}
	}
	return nil
}

// KeyStore holds the keys of a session: every key a receiver accepts, and
// the one a sender uses. Keys are looked up by the identifier each SPDU
// carries, so a receiver holding the current and the next key keeps
// accepting a publisher across a key change. Safe for concurrent use.
type KeyStore struct {
	mu     sync.RWMutex
	keys   map[uint32]*Key
	active uint32
}

// NewKeyStore returns a store holding keys; the first becomes the active
// one.
func NewKeyStore(keys ...Key) (*KeyStore, error) {
	s := &KeyStore{keys: map[uint32]*Key{}}
	for i, k := range keys {
		if err := s.Add(k); err != nil {
			return nil, err
		}
		if i == 0 {
			s.active = k.ID
		}
	}
	return s, nil
}

// Add adds a key, or replaces the key of the same identifier. The store
// keeps its own copy of the material.
func (s *KeyStore) Add(k Key) error {
	if err := k.validate(); err != nil {
		return err
	}
	k.Material = append([]byte(nil), k.Material...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.keys == nil {
		s.keys = map[uint32]*Key{}
	}
	s.keys[k.ID] = &k
	return nil
}

// Remove removes a key. Removing the active key leaves the sender without
// one: it sends nothing until another is made active.
func (s *KeyStore) Remove(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The material is not wiped: an SPDU being encoded or verified under
	// the key may still be reading it. It is dropped with the key.
	delete(s.keys, id)
	if s.active == id {
		s.active = 0
	}
}

// SetActive makes the key with identifier id the one a sender uses.
func (s *KeyStore) SetActive(id uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[id]; !ok {
		return fmt.Errorf("rsession: no key %d", id)
	}
	s.active = id
	return nil
}

// activeKey returns the sender's key, nil when there is none.
func (s *KeyStore) activeKey() *Key {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[s.active]
}

// Lookup returns a copy of the key with identifier id.
func (s *KeyStore) Lookup(id uint32) (Key, bool) {
	k := s.lookup(id)
	if k == nil {
		return Key{}, false
	}
	c := *k
	c.Material = append([]byte(nil), k.Material...)
	return c, true
}

// lookup returns the stored key, which the caller must not modify.
func (s *KeyStore) lookup(id uint32) *Key {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[id]
}
