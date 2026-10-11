package e2e

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

// chainInit returns the octets of h0 (register R-12).
func chainInit(c ChainInit) []byte {
	switch c {
	case ChainEmpty:
		return nil
	case ChainZeroHash:
		return make([]byte, sha256.Size)
	}
	return []byte{0}
}

func hashCat(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// handshakeSalt is salt0 = h2 = H(data2 || H(data1 || h0)) (13.3.1.3 a)).
func handshakeSalt(init ChainInit, data1, data2 []byte) []byte {
	return hashCat(data2, hashCat(data1, chainInit(init)))
}

// rekeySalt is salt_n = H(data3 || salt_{n-1}).
func rekeySalt(data3, prev []byte) []byte { return hashCat(data3, prev) }

// keySet is the keys of one key epoch: the ICV key of each direction.
type keySet struct {
	client, server []byte
}

// deriveKeys runs HKDF with SHA-256, info absent, and splits the output
// into the client key followed by the server key (13.3.1.3 c)).
func deriveKeys(alg ICVAlg, salt, z []byte) (keySet, error) {
	n := alg.keyLen()
	okm, err := hkdf.Key(sha256.New, z, salt, "", 2*n)
	if err != nil {
		return keySet{}, err
	}
	return keySet{client: okm[:n], server: okm[n:]}, nil
}

// replayCache remembers (peer, time, assoID) of accepted handshakes for the
// freshness window (14.3.4 g)).
type replayCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newReplayCache() *replayCache { return &replayCache{entries: map[string]time.Time{}} }

const maxReplayEntries = 1 << 16

// seen records key and reports whether it was already present. Entries are
// kept until expiry.
func (r *replayCache) seen(key string, now, expiry time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) > maxReplayEntries/2 {
		for k, e := range r.entries {
			if now.After(e) {
				delete(r.entries, k)
			}
		}
	}
	if e, ok := r.entries[key]; ok && now.Before(e) {
		return true
	}
	if len(r.entries) >= maxReplayEntries {
		// Full of live entries: refuse rather than forget (fail closed).
		return true
	}
	r.entries[key] = expiry
	return false
}

// idAllocator hands out the 1-3 digit association identifier parts, unique
// among the live associations of one peer (13.3.1.1 e)).
type idAllocator struct {
	mu   sync.Mutex
	used map[string]map[int]bool
	rnd  io.Reader
}

func newIDAllocator(rnd io.Reader) *idAllocator {
	if rnd == nil {
		rnd = rand.Reader
	}
	return &idAllocator{used: map[string]map[int]bool{}, rnd: rnd}
}

func (a *idAllocator) get(peer string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.used[peer]
	if m == nil {
		m = map[int]bool{}
		a.used[peer] = m
	}
	if len(m) >= 999 {
		return "", fmt.Errorf("e2e: no free association identifier for peer %s", peer)
	}
	var b [2]byte
	for {
		if _, err := io.ReadFull(a.rnd, b[:]); err != nil {
			return "", err
		}
		n := int(binary.BigEndian.Uint16(b[:]))%999 + 1
		if !m[n] {
			m[n] = true
			return strconv.Itoa(n), nil
		}
	}
}

func (a *idAllocator) put(peer, id string) {
	n, err := strconv.Atoi(id)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if m := a.used[peer]; m != nil {
		delete(m, n)
		if len(m) == 0 {
			delete(a.used, peer)
		}
	}
}

// validIDPart reports a 1-3 digit identifier part.
func validIDPart(s string) bool {
	if len(s) < 1 || len(s) > 3 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
