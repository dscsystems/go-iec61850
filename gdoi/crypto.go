package gdoi

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// Phase 1 attribute classes (RFC 2409 appendix A).
const (
	attrEncAlg    = 1
	attrHashAlg   = 2
	attrAuthMeth  = 3
	attrGroupDesc = 4
	attrLifeType  = 11
	attrLifeDur   = 12
	attrKeyLength = 14
)

// Phase 1 attribute values.
const (
	encAESCBC     = 7
	hashSHA256    = 4
	hashSHA384    = 5
	lifeSeconds   = 1
	authPSK       = 1
	authRSASig    = 3
	authECDSA256  = 9  // RFC 4754
	authECDSA384  = 10 // RFC 4754
	groupMODP2048 = 14
	groupECP256   = 19 // RFC 5903
	groupECP384   = 20
)

// Suite is one phase 1 proposal: the algorithms protecting the exchange
// with the key server.
type Suite struct {
	// KeyBits is the AES-CBC key length, 128 or 256.
	KeyBits int
	// Hash is 4 (SHA2-256) or 5 (SHA2-384); it is the PRF, as HMAC.
	Hash int
	// Group is the Diffie-Hellman group: 14 (2048-bit MODP), 19 (256-bit
	// ECP) or 20 (384-bit ECP).
	Group int
}

// DefaultSuites are offered when a configuration names none, strongest
// first.
var DefaultSuites = []Suite{
	{KeyBits: 256, Hash: hashSHA256, Group: groupECP256},
	{KeyBits: 128, Hash: hashSHA256, Group: groupECP256},
	{KeyBits: 256, Hash: hashSHA384, Group: groupECP384},
	{KeyBits: 128, Hash: hashSHA256, Group: groupMODP2048},
}

func (s Suite) valid() bool {
	return (s.KeyBits == 128 || s.KeyBits == 256) &&
		(s.Hash == hashSHA256 || s.Hash == hashSHA384) &&
		(s.Group == groupMODP2048 || s.Group == groupECP256 || s.Group == groupECP384)
}

func (s Suite) String() string {
	h := map[int]string{hashSHA256: "SHA2-256", hashSHA384: "SHA2-384"}[s.Hash]
	g := map[int]string{groupMODP2048: "MODP-2048", groupECP256: "ECP-256", groupECP384: "ECP-384"}[s.Group]
	return fmt.Sprintf("AES-CBC-%d/%s/%s", s.KeyBits, h, g)
}

func (s Suite) newHash() func() hash.Hash {
	if s.Hash == hashSHA384 {
		return sha512.New384
	}
	return sha256.New
}

// attrs is the transform's attributes with the authentication method and
// the lifetime.
func (s Suite) attrs(auth uint16, lifeSecs uint32) []attribute {
	return []attribute{
		basicAttr(attrEncAlg, encAESCBC),
		basicAttr(attrKeyLength, uint16(s.KeyBits)),
		basicAttr(attrHashAlg, uint16(s.Hash)),
		basicAttr(attrGroupDesc, uint16(s.Group)),
		basicAttr(attrAuthMeth, auth),
		basicAttr(attrLifeType, lifeSeconds),
		uintAttr(attrLifeDur, lifeSecs),
	}
}

// suiteFromAttrs reads a transform's attributes; ok is false for one
// outside what this implementation supports.
func suiteFromAttrs(as []attribute) (s Suite, auth uint16, ok bool) {
	get := func(t uint16) (uint64, bool) {
		a, found := attrByType(as, t)
		if !found || len(a.Value) > 8 {
			return 0, false
		}
		return a.uint(), true
	}
	enc, ok1 := get(attrEncAlg)
	kl, ok2 := get(attrKeyLength)
	h, ok3 := get(attrHashAlg)
	g, ok4 := get(attrGroupDesc)
	am, ok5 := get(attrAuthMeth)
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || enc != encAESCBC {
		return Suite{}, 0, false
	}
	s = Suite{KeyBits: int(kl), Hash: int(h), Group: int(g)}
	return s, uint16(am), s.valid()
}

// prf is HMAC with the negotiated hash.
func prf(h func() hash.Hash, key []byte, data ...[]byte) []byte {
	m := hmac.New(h, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// dh is one side's ephemeral Diffie-Hellman key.
type dh struct {
	group int
	pub   []byte // the KE payload value
	ecKey *ecdh.PrivateKey
	x     *big.Int // MODP private exponent
}

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

func curveOf(group int) ecdh.Curve {
	switch group {
	case groupECP256:
		return ecdh.P256()
	case groupECP384:
		return ecdh.P384()
	}
	return nil
}

func newDH(group int) (*dh, error) {
	if c := curveOf(group); c != nil {
		k, err := c.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		// RFC 5903: the KE value is x followed by y, without the
		// uncompressed-point prefix.
		return &dh{group: group, ecKey: k, pub: k.PublicKey().Bytes()[1:]}, nil
	}
	if group != groupMODP2048 {
		return nil, fmt.Errorf("gdoi: Diffie-Hellman group %d", group)
	}
	x, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 512))
	if err != nil {
		return nil, err
	}
	y := new(big.Int).Exp(big.NewInt(2), x, modp2048P)
	return &dh{group: group, x: x, pub: y.FillBytes(make([]byte, modpLen))}, nil
}

// shared computes g^xy from the peer's KE value: for an ECP group its x
// coordinate (RFC 5903), for MODP the value padded to the modulus length.
func (d *dh) shared(peer []byte) ([]byte, error) {
	if c := curveOf(d.group); c != nil {
		pk, err := c.NewPublicKey(append([]byte{4}, peer...))
		if err != nil {
			return nil, fmt.Errorf("gdoi: peer key exchange value: %w", err)
		}
		return d.ecKey.ECDH(pk)
	}
	if len(peer) != modpLen {
		return nil, fmt.Errorf("gdoi: MODP key exchange value of %d octets", len(peer))
	}
	y := new(big.Int).SetBytes(peer)
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(modp2048P, one)
	if y.Cmp(one) <= 0 || y.Cmp(pm1) >= 0 {
		return nil, errors.New("gdoi: peer key exchange value out of range")
	}
	return new(big.Int).Exp(y, d.x, modp2048P).FillBytes(make([]byte, modpLen)), nil
}

// keys is the keying material of a phase 1 SA (RFC 2409 5).
type keys struct {
	hash       func() hash.Hash
	encKey     []byte // the phase 1 encryption key derived from SKEYID_e
	skeyid     []byte
	d, a, e    []byte
	block      cipher.Block
	phase1Last []byte // last CBC output block of phase 1
}

func deriveKeys(s Suite, skeyid, gxy, ci, cr []byte) (*keys, error) {
	h := s.newHash()
	k := &keys{hash: h, skeyid: skeyid}
	k.d = prf(h, skeyid, gxy, ci, cr, []byte{0})
	k.a = prf(h, skeyid, k.d, gxy, ci, cr, []byte{1})
	k.e = prf(h, skeyid, k.a, gxy, ci, cr, []byte{2})
	// Appendix B: take the key from SKEYID_e, expanding it by feeding the
	// PRF into itself when it is too short.
	need := s.KeyBits / 8
	material := k.e
	if len(material) < need {
		var ka, prev []byte
		prev = []byte{0}
		for len(ka) < need {
			prev = prf(h, k.e, prev)
			ka = append(ka, prev...)
		}
		material = ka
	}
	k.encKey = clone(material[:need])
	block, err := aes.NewCipher(k.encKey)
	if err != nil {
		return nil, err
	}
	k.block = block
	return k, nil
}

// phase1IV is the IV of the first encrypted phase 1 message:
// hash(g^xi | g^xr), truncated to the block size.
func phase1IV(h func() hash.Hash, gxi, gxr []byte) []byte {
	m := h()
	m.Write(gxi)
	m.Write(gxr)
	return m.Sum(nil)[:aes.BlockSize]
}

// phase2IV is the IV of the first message of a phase 2 or informational
// exchange: hash(last phase 1 CBC block | M-ID).
func (k *keys) phase2IV(msgID uint32) []byte {
	m := k.hash()
	m.Write(k.phase1Last)
	m.Write([]byte{byte(msgID >> 24), byte(msgID >> 16), byte(msgID >> 8), byte(msgID)})
	return m.Sum(nil)[:aes.BlockSize]
}

// encrypt pads plain with zeros to the block size and encrypts it with
// iv, returning the ciphertext and the IV of the next message (its last
// block).
func (k *keys) encrypt(plain, iv []byte) ([]byte, []byte) {
	n := len(plain)
	if r := n % aes.BlockSize; r != 0 || n == 0 {
		n += aes.BlockSize - r
	}
	buf := make([]byte, n)
	copy(buf, plain)
	cipher.NewCBCEncrypter(k.block, iv).CryptBlocks(buf, buf)
	return buf, clone(buf[n-aes.BlockSize:])
}

// decrypt decrypts ct with iv, returning the plaintext (padding
// included) and the IV of the next message.
func (k *keys) decrypt(ct, iv []byte) ([]byte, []byte, error) {
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, nil, malformed("ciphertext of %d octets", len(ct))
	}
	next := clone(ct[len(ct)-aes.BlockSize:])
	buf := make([]byte, len(ct))
	cipher.NewCBCDecrypter(k.block, iv).CryptBlocks(buf, ct)
	return buf, next, nil
}

// sign signs HASH_I or HASH_R for the authentication method: RSA as a
// PKCS #1 private-key encryption of the hash with no algorithm identifier
// (RFC 2409 5.1), ECDSA over the hash of it as r followed by s (RFC 4754).
func sign(auth uint16, key crypto.Signer, h []byte) ([]byte, error) {
	switch auth {
	case authRSASig:
		rk, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("gdoi: RSA signature authentication needs an RSA key")
		}
		return rsa.SignPKCS1v15(rand.Reader, rk, crypto.Hash(0), h)
	case authECDSA256, authECDSA384:
		ek, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("gdoi: ECDSA authentication needs an ECDSA key")
		}
		digest, size := ecdsaDigest(auth, h)
		r, s, err := ecdsa.Sign(rand.Reader, ek, digest)
		if err != nil {
			return nil, err
		}
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out, nil
	}
	return nil, fmt.Errorf("gdoi: authentication method %d is not a signature", auth)
}

func ecdsaDigest(auth uint16, h []byte) ([]byte, int) {
	if auth == authECDSA384 {
		d := sha512.Sum384(h)
		return d[:], 48
	}
	d := sha256.Sum256(h)
	return d[:], 32
}

// verify checks a signature over HASH_I or HASH_R with the certificate's
// key, which must suit the authentication method.
func verify(auth uint16, cert *x509.Certificate, h, sig []byte) error {
	switch auth {
	case authRSASig:
		pk, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("gdoi: RSA signature from a certificate without an RSA key")
		}
		return rsa.VerifyPKCS1v15(pk, crypto.Hash(0), h, sig)
	case authECDSA256, authECDSA384:
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("gdoi: ECDSA signature from a certificate without an ECDSA key")
		}
		digest, size := ecdsaDigest(auth, h)
		if pk.Curve.Params().BitSize != size*8 {
			return fmt.Errorf("gdoi: %d-bit ECDSA key for a %d-bit method", pk.Curve.Params().BitSize, size*8)
		}
		if len(sig) != 2*size {
			return fmt.Errorf("gdoi: ECDSA signature of %d octets", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(pk, digest, r, s) {
			return errors.New("gdoi: signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("gdoi: authentication method %d is not a signature", auth)
}

// authMethodFor is the signature authentication method a key calls for.
func authMethodFor(key crypto.Signer) (uint16, error) {
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return 0, fmt.Errorf("gdoi: %d-bit RSA key, at least 2048 required", k.N.BitLen())
		}
		return authRSASig, nil
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return authECDSA256, nil
		case 384:
			return authECDSA384, nil
		}
		return 0, fmt.Errorf("gdoi: ECDSA curve %s is not supported", k.Curve.Params().Name)
	}
	return 0, fmt.Errorf("gdoi: %T keys are not supported", key.Public())
}

// constantEqual compares MACs.
func constantEqual(a, b []byte) bool { return hmac.Equal(a, b) }
