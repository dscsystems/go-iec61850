package e2e

import (
	"errors"
	"fmt"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

// The SecPDU codec follows the E2E-Security module of IEC 62351-4 Annex B
// (DEFINITIONS IMPLICIT TAGS). Decoding keeps the octets that are signed or
// MACed exactly as received; encoding always uses definite lengths.

// errProtocol marks a structural error of a SecPDU (diagnostic
// protocol-error).
var errProtocol = errors.New("e2e: protocol error")

func protoErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errProtocol, fmt.Sprintf(format, a...))
}

// maxExtensions bounds the unknown elements tolerated at the extension
// markers of the Annex B module; they are ignored after verification.
const maxExtensions = 8

// Tags of the module (implicit tagging).
var (
	tagUTF8       = asn1.TagUTF8String
	tagGenTime    = asn1.TagGeneralTime
	tagEnumerated = asn1.Tag{Class: asn1.ClassUniversal, Number: 10}
	tagExternal   = asn1.Tag{Class: asn1.ClassUniversal, Constructed: true, Number: 8}
	tagNonAEA     = asn1.ContextConstructed(0)
	tagEncr       = asn1.ContextConstructed(0)
	tagICVSet     = asn1.ContextConstructed(1)
	tagIV         = asn1.ContextPrimitive(0)
	tagRekey      = asn1.ContextPrimitive(1)
	tagReqRekey   = asn1.ContextPrimitive(2)
	tagChanged    = asn1.ContextPrimitive(3)
	// Authenticator of clause 13.4.2 (register R-04).
	tagAuthNonce13 = asn1.ContextPrimitive(0)
	tagAuthICV13   = asn1.ContextPrimitive(1)
)

// versionV1 is Version {v1} DER-encoded as BIT STRING content.
var versionV1 = []byte{0x07, 0x80}

// ClearToken1 carries the security parameters of a handshake (13.3.1).
type ClearToken1 struct {
	SigAlg     AlgorithmIdentifier
	PKCert     []byte
	CertPath   [][]byte // nil when absent
	HasVersion bool
	Version    asn1.BitString
	AssoID     string
	DHGroup    int64
	DHPublic   []byte
	HMAC       AlgorithmIdentifier
	TimeRaw    []byte
	Time       time.Time
	// AEA selects the aea alternative of encr-mode; otherwise non-aea with
	// Encr (when HasEncr) and ICV.
	AEA        bool
	AEAAlgs    []AlgorithmIdentifier
	HasEncr    bool
	Encr       []AlgorithmIdentifier
	ICV        []AlgorithmIdentifier
	ConfParams asn1.BitString
	AttCert    []byte // nil when absent
}

// ClearToken2 carries the per-message parameters of data transfer (13.3.2).
type ClearToken2 struct {
	Raw        []byte // the complete TLV as received (AEAD additional data)
	HasVersion bool
	Version    asn1.BitString
	AssoID     string
	TimeRaw    []byte
	Time       time.Time
	Seq        int64
	IV         []byte // nil when absent
	Rekey      []byte // nil when absent
	ReqRekey   bool
	ChangedKey bool
}

// ClearToken3 authenticates rejects, aborts and releases (13.3.3).
type ClearToken3 struct {
	SigAlg     AlgorithmIdentifier
	HasVersion bool
	Version    asn1.BitString
	HasAssoID  bool
	AssoID     string
	TimeRaw    []byte
	Time       time.Time
	PKCert     []byte
	CertPath   [][]byte
}

// Signature is the signature data type (13.4.1).
type Signature struct {
	Alg   AlgorithmIdentifier
	Value []byte
}

// Authenticator is the authenticator data type (13.4.2).
type Authenticator struct {
	Nonce []byte // nil when absent
	Alg   AlgorithmIdentifier
	ICV   []byte
}

// AuthenticatorTagging selects the Authenticator encoding (register R-04).
type AuthenticatorTagging uint8

const (
	// AuthAnnexB is the untagged form of the Annex B code component, the
	// default.
	AuthAnnexB AuthenticatorTagging = iota
	// AuthClause13 is the [0] nonce / [1] icv form of clause 13.4.2.
	AuthClause13
)

// Kind is a SecPDU type.
type Kind uint8

const (
	KindHandshakeReq Kind = iota + 1
	KindHandshakeAcc
	KindApplicationReject
	KindHandshakeSecReject
	KindHandshakeSecAbort
	KindDtSecAbort
	KindApplAbort
	KindReleaseReq
	KindReleaseRsp
	KindClearTransfer
	KindEncrTransfer
)

func (k Kind) String() string {
	return [...]string{"?", "HandshakeReq", "HandshakeAcc", "ApplicationReject", "HandshakeSecReject",
		"HandshakeSecAbort", "DtSecAbort", "ApplAbort", "ReleaseReq", "ReleaseRsp", "ClearTransfer", "EncrTransfer"}[k]
}

// Signed is any signed SecPDU: the handshake PDUs, rejects, aborts and the
// release PDUs. Which fields are used depends on Kind.
type Signed struct {
	Kind     Kind
	PP       string       // HandshakeReq
	Token1   *ClearToken1 // HandshakeReq, HandshakeAcc
	Token3   *ClearToken3 // all others
	ApplData []byte       // complete TLV; nil when absent
	Diag     int          // HandshakeSecReject, HandshakeSecAbort, DtSecAbort; -1 when absent
	Sig      Signature
	// Edition selects the ClearToken1 layout (Edition2020 by default).
	Edition Edition
	// TBS is the content of the tbs component including any end-of-
	// contents octets: the octets the signature covers.
	TBS []byte
}

// Transfer is a ClearTransfer or EncrTransfer SecPDU.
type Transfer struct {
	Encrypted bool
	Token2    ClearToken2
	// ApplData is the complete ApplData TLV (clear) or the encrypted octets
	// (EncrTransfer).
	ApplData []byte
	Auth     *Authenticator // nil when absent (AEAD)
	// TBP is the content of tbp including any end-of-contents octets: the
	// octets the ICV covers.
	TBP []byte
}

// ---------------------------------------------------------------------
// Encoding

func algElem(a AlgorithmIdentifier) *asn1.Element {
	e := asn1.Cons(asn1.TagSequence, asn1.OIDElem(asn1.TagOID, a.Algorithm))
	if a.Parameters != nil {
		e.Add(asn1.RawTLV(a.Parameters))
	}
	return e
}

func algSeq(t asn1.Tag, as []AlgorithmIdentifier) *asn1.Element {
	e := asn1.Cons(t)
	for _, a := range as {
		e.Add(algElem(a))
	}
	return e
}

func certPathElem(p [][]byte) *asn1.Element {
	if p == nil {
		return nil
	}
	e := asn1.Cons(asn1.TagSequence)
	for _, c := range p {
		e.Add(asn1.Prim(asn1.TagOctetString, c))
	}
	return e
}

func (t *ClearToken1) element() *asn1.Element {
	e := asn1.Cons(asn1.TagSequence,
		algElem(t.SigAlg),
		asn1.Prim(asn1.TagOctetString, t.PKCert),
		certPathElem(t.CertPath),
		versionElem(t.HasVersion, t.Version),
		asn1.Prim(tagUTF8, []byte(t.AssoID)),
		asn1.Cons(asn1.TagSequence,
			asn1.IntElem(asn1.TagInteger, t.DHGroup),
			asn1.Prim(asn1.TagOctetString, t.DHPublic)),
		algElem(t.HMAC),
		asn1.Prim(tagGenTime, t.TimeRaw),
	)
	if t.AEA {
		e.Add(algSeq(asn1.TagSequence, t.AEAAlgs))
	} else {
		na := asn1.Cons(tagNonAEA)
		if t.HasEncr {
			na.Add(algSeq(tagEncr, t.Encr))
		}
		na.Add(algSeq(tagICVSet, t.ICV))
		e.Add(na)
	}
	e.Add(asn1.BitStringElem(asn1.TagBitString, t.ConfParams))
	if t.AttCert != nil {
		e.Add(asn1.Prim(asn1.TagOctetString, t.AttCert))
	}
	return e
}

func (t *ClearToken2) element() *asn1.Element {
	e := asn1.Cons(asn1.TagSequence,
		asn1.Prim(asn1.TagBitString, versionV1),
		asn1.Prim(tagUTF8, []byte(t.AssoID)),
		asn1.Prim(tagGenTime, t.TimeRaw),
		asn1.IntElem(asn1.TagInteger, t.Seq),
	)
	if t.IV != nil {
		e.Add(asn1.Prim(tagIV, t.IV))
	}
	if t.Rekey != nil {
		e.Add(asn1.Prim(tagRekey, t.Rekey))
	}
	if t.ReqRekey {
		e.Add(asn1.BoolElem(tagReqRekey, true))
	}
	if t.ChangedKey {
		e.Add(asn1.BoolElem(tagChanged, true))
	}
	return e
}

func (t *ClearToken3) element() *asn1.Element {
	e := asn1.Cons(asn1.TagSequence,
		algElem(t.SigAlg),
		asn1.Prim(asn1.TagBitString, versionV1),
	)
	if t.HasAssoID {
		e.Add(asn1.Prim(tagUTF8, []byte(t.AssoID)))
	}
	e.Add(asn1.Prim(tagGenTime, t.TimeRaw),
		asn1.Prim(asn1.TagOctetString, t.PKCert),
		certPathElem(t.CertPath))
	return e
}

func (a *Authenticator) element(tg AuthenticatorTagging) *asn1.Element {
	nt, it := asn1.TagOctetString, asn1.TagOctetString
	if tg == AuthClause13 {
		nt, it = tagAuthNonce13, tagAuthICV13
	}
	e := asn1.Cons(asn1.TagSequence)
	if a.Nonce != nil {
		e.Add(asn1.Prim(nt, a.Nonce))
	}
	e.Add(algElem(a.Alg), asn1.Prim(it, a.ICV))
	return e
}

// tbsContent encodes the content of the tbs component of s.
func (s *Signed) tbsContent() []byte {
	var out []byte
	switch s.Kind {
	case KindHandshakeReq, KindHandshakeAcc:
		if s.Edition == Edition2018 {
			out = s.Token1.element2018().Append(out)
		} else {
			out = s.Token1.element().Append(out)
		}
	default:
		out = s.Token3.element().Append(out)
	}
	switch s.Kind {
	case KindHandshakeReq, KindHandshakeAcc, KindApplicationReject, KindApplAbort:
		if s.ApplData != nil {
			out = append(out, s.ApplData...)
		}
	case KindHandshakeSecReject, KindHandshakeSecAbort, KindDtSecAbort:
		if s.Diag >= 0 {
			out = asn1.IntElem(tagEnumerated, int64(s.Diag)).Append(out)
		}
	}
	return out
}

// encodeSigned builds the SecPDU TLV (tag SEQUENCE) with sign computing the
// signature over the tbs content.
func encodeSigned(s *Signed, signFn func(tbs []byte) ([]byte, error)) ([]byte, error) {
	tbs := s.tbsContent()
	sig, err := signFn(tbs)
	if err != nil {
		return nil, err
	}
	s.TBS = tbs
	s.Sig.Value = sig
	e := asn1.Cons(asn1.TagSequence)
	if s.Kind == KindHandshakeReq {
		e.Add(asn1.Prim(tagUTF8, []byte(s.PP)))
	}
	e.Add(asn1.RawContent(asn1.TagSequence, tbs),
		asn1.Cons(asn1.TagSequence, algElem(s.Sig.Alg), asn1.Prim(asn1.TagOctetString, sig)))
	return e.Encode(), nil
}

// encodeTransfer builds a ClearTransfer or EncrTransfer TLV, computing the
// authenticator over the tbp content with icv (nil for AEAD).
func encodeTransfer(t *Transfer, tg AuthenticatorTagging, icv func(tbp []byte) (*Authenticator, error)) ([]byte, error) {
	var tbp []byte
	tbp = t.Token2.element().Append(tbp)
	if t.Encrypted {
		tbp = asn1.Prim(asn1.TagOctetString, t.ApplData).Append(tbp)
	} else {
		tbp = append(tbp, t.ApplData...)
	}
	t.TBP = tbp
	e := asn1.Cons(asn1.TagSequence, asn1.RawContent(asn1.TagSequence, tbp))
	if icv != nil {
		a, err := icv(tbp)
		if err != nil {
			return nil, err
		}
		t.Auth = a
		e.Add(a.element(tg))
	}
	return e.Encode(), nil
}

// ---------------------------------------------------------------------
// Decoding

func readAlg(d *asn1.Decoder) (AlgorithmIdentifier, error) {
	c, err := d.Expect(asn1.TagSequence)
	if err != nil {
		return AlgorithmIdentifier{}, err
	}
	return parseAlg(c)
}

func parseAlg(c []byte) (AlgorithmIdentifier, error) {
	ad := asn1.NewDecoder(c)
	ob, err := ad.Expect(asn1.TagOID)
	if err != nil {
		return AlgorithmIdentifier{}, err
	}
	oid, err := asn1.DecodeOID(ob)
	if err != nil {
		return AlgorithmIdentifier{}, err
	}
	a := AlgorithmIdentifier{Algorithm: oid}
	if ad.More() {
		s, err := ad.ReadSpan()
		if err != nil {
			return AlgorithmIdentifier{}, err
		}
		a.Parameters = append([]byte(nil), s.Full...)
		if ad.More() {
			return AlgorithmIdentifier{}, protoErr("AlgorithmIdentifier: trailing data")
		}
	}
	return a, nil
}

// parseAlgList decodes a SEQUENCE OF / SET OF AlgorithmIdentifier content,
// allowing it to be empty: SIZE(1..MAX) violations are reported by the
// semantic checks with their specific diagnostics.
func parseAlgList(c []byte) ([]AlgorithmIdentifier, error) {
	d := asn1.NewDecoder(c)
	out := []AlgorithmIdentifier{}
	for d.More() {
		if len(out) >= 16 {
			return nil, protoErr("too many algorithms")
		}
		a, err := readAlg(d)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func parseCertPath(c []byte) ([][]byte, error) {
	d := asn1.NewDecoder(c)
	out := [][]byte{}
	for d.More() {
		if len(out) >= 8 {
			return nil, protoErr("certification path too long")
		}
		b, err := d.Expect(asn1.TagOctetString)
		if err != nil {
			return nil, err
		}
		out = append(out, append([]byte(nil), b...))
	}
	if len(out) == 0 {
		return nil, protoErr("empty certification path")
	}
	return out, nil
}

func parseVersion(b []byte) (asn1.BitString, error) {
	return asn1.DecodeBitString(b)
}

func parseTime(b []byte) (time.Time, []byte, error) {
	t, err := asn1.ParseTime62351(b)
	if err != nil {
		return time.Time{}, nil, protoErr("time: %v", err)
	}
	return t, append([]byte(nil), b...), nil
}

func parseNMTOKEN(b []byte) (string, error) {
	s := string(b)
	if len(s) == 0 || len(s) > 64 {
		return "", protoErr("bad NMTOKEN")
	}
	for _, r := range s {
		// NMTOKEN characters of the [B] constraint; ASCII control characters
		// and space are excluded.
		if r < 0x21 || r == 0x7f {
			return "", protoErr("bad NMTOKEN")
		}
	}
	return s, nil
}

func skipExtensions(d *asn1.Decoder) error {
	for n := 0; d.More(); n++ {
		if n >= maxExtensions {
			return protoErr("too many extension elements")
		}
		s, err := d.ReadSpan()
		if err != nil {
			return err
		}
		if len(s.Full) > 4096 {
			return protoErr("extension element too large")
		}
	}
	return nil
}

func wrap(err error) error {
	if err == nil || errors.Is(err, errProtocol) {
		return err
	}
	return fmt.Errorf("%w: %v", errProtocol, err)
}

func parseToken1(c []byte) (*ClearToken1, error) {
	t := &ClearToken1{}
	d := asn1.NewDecoder(c)
	var err error
	if t.SigAlg, err = readAlg(d); err != nil {
		return nil, wrap(err)
	}
	pk, err := d.Expect(asn1.TagOctetString)
	if err != nil {
		return nil, wrap(err)
	}
	t.PKCert = append([]byte(nil), pk...)
	if b, ok, err := d.Optional(asn1.TagSequence); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.CertPath, err = parseCertPath(b); err != nil {
			return nil, wrap(err)
		}
	}
	if b, ok, err := d.Optional(asn1.TagBitString); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.Version, err = parseVersion(b); err != nil {
			return nil, wrap(err)
		}
		t.HasVersion = true
	}
	b, err := d.Expect(tagUTF8)
	if err != nil {
		return nil, wrap(err)
	}
	if t.AssoID, err = parseNMTOKEN(b); err != nil {
		return nil, err
	}
	if err := parseDHSet(d, t); err != nil {
		return nil, err
	}
	if t.HMAC, err = readAlg(d); err != nil {
		return nil, wrap(err)
	}
	tb, err := d.Expect(tagGenTime)
	if err != nil {
		return nil, wrap(err)
	}
	if t.Time, t.TimeRaw, err = parseTime(tb); err != nil {
		return nil, err
	}
	tag, ok := d.PeekTag()
	if !ok {
		return nil, protoErr("encr-mode missing")
	}
	switch tag {
	case asn1.TagSequence:
		ac, _ := d.Expect(asn1.TagSequence)
		t.AEA = true
		if t.AEAAlgs, err = parseAlgList(ac); err != nil {
			return nil, wrap(err)
		}
	case tagNonAEA:
		nc, _ := d.Expect(tagNonAEA)
		nd := asn1.NewDecoder(nc)
		if b, ok, err := nd.Optional(tagEncr); err != nil {
			return nil, wrap(err)
		} else if ok {
			t.HasEncr = true
			if t.Encr, err = parseAlgList(b); err != nil {
				return nil, wrap(err)
			}
		}
		ic, err := nd.Expect(tagICVSet)
		if err != nil {
			return nil, wrap(err)
		}
		if t.ICV, err = parseAlgList(ic); err != nil {
			return nil, wrap(err)
		}
		if err := skipExtensions(nd); err != nil {
			return nil, err
		}
	default:
		return nil, protoErr("encr-mode tag %v", tag)
	}
	cb, err := d.Expect(asn1.TagBitString)
	if err != nil {
		return nil, wrap(err)
	}
	if t.ConfParams, err = asn1.DecodeBitString(cb); err != nil {
		return nil, wrap(err)
	}
	if b, ok, err := d.Optional(asn1.TagOctetString); err != nil {
		return nil, wrap(err)
	} else if ok {
		t.AttCert = append([]byte(nil), b...)
	}
	return t, skipExtensions(d)
}

// parseDHSet decodes DiffieHellmanSet into t.
func parseDHSet(d *asn1.Decoder, t *ClearToken1) error {
	dhc, err := d.Expect(asn1.TagSequence)
	if err != nil {
		return wrap(err)
	}
	dd := asn1.NewDecoder(dhc)
	gb, err := dd.Expect(asn1.TagInteger)
	if err != nil {
		return wrap(err)
	}
	if t.DHGroup, err = asn1.DecodeInt(gb); err != nil {
		return wrap(err)
	}
	pub, err := dd.Expect(asn1.TagOctetString)
	if err != nil || len(pub) == 0 {
		return protoErr("dhPublicKey")
	}
	t.DHPublic = append([]byte(nil), pub...)
	return skipExtensions(dd)
}

func parseToken2(s asn1.Span) (*ClearToken2, error) {
	t := &ClearToken2{Raw: s.Full}
	d := asn1.NewDecoder(s.Content)
	var err error
	if b, ok, err := d.Optional(asn1.TagBitString); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.Version, err = parseVersion(b); err != nil {
			return nil, wrap(err)
		}
		t.HasVersion = true
	}
	b, err := d.Expect(tagUTF8)
	if err != nil {
		return nil, wrap(err)
	}
	if t.AssoID, err = parseNMTOKEN(b); err != nil {
		return nil, err
	}
	tb, err := d.Expect(tagGenTime)
	if err != nil {
		return nil, wrap(err)
	}
	if t.Time, t.TimeRaw, err = parseTime(tb); err != nil {
		return nil, err
	}
	sb, err := d.Expect(asn1.TagInteger)
	if err != nil {
		return nil, wrap(err)
	}
	if t.Seq, err = asn1.DecodeInt(sb); err != nil || t.Seq < 0 {
		return nil, protoErr("sequence number")
	}
	if b, ok, err := d.Optional(tagIV); err != nil {
		return nil, wrap(err)
	} else if ok {
		// SIZE (12 | 16): a GCM nonce or a CBC IV (TISSUE 53/55).
		if len(b) != 12 && len(b) != 16 {
			return nil, protoErr("iv of %d octets", len(b))
		}
		t.IV = append([]byte(nil), b...)
	}
	if b, ok, err := d.Optional(tagRekey); err != nil {
		return nil, wrap(err)
	} else if ok {
		if len(b) == 0 {
			return nil, protoErr("empty rekey")
		}
		t.Rekey = append([]byte(nil), b...)
	}
	if b, ok, err := d.Optional(tagReqRekey); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.ReqRekey, err = asn1.DecodeBool(b); err != nil {
			return nil, wrap(err)
		}
	}
	if b, ok, err := d.Optional(tagChanged); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.ChangedKey, err = asn1.DecodeBool(b); err != nil {
			return nil, wrap(err)
		}
	}
	return t, skipExtensions(d)
}

func parseToken3(c []byte) (*ClearToken3, error) {
	t := &ClearToken3{}
	d := asn1.NewDecoder(c)
	var err error
	if t.SigAlg, err = readAlg(d); err != nil {
		return nil, wrap(err)
	}
	if b, ok, err := d.Optional(asn1.TagBitString); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.Version, err = parseVersion(b); err != nil {
			return nil, wrap(err)
		}
		t.HasVersion = true
	}
	if b, ok, err := d.Optional(tagUTF8); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.AssoID, err = parseNMTOKEN(b); err != nil {
			return nil, err
		}
		t.HasAssoID = true
	}
	tb, err := d.Expect(tagGenTime)
	if err != nil {
		return nil, wrap(err)
	}
	if t.Time, t.TimeRaw, err = parseTime(tb); err != nil {
		return nil, err
	}
	pk, err := d.Expect(asn1.TagOctetString)
	if err != nil {
		return nil, wrap(err)
	}
	t.PKCert = append([]byte(nil), pk...)
	if b, ok, err := d.Optional(asn1.TagSequence); err != nil {
		return nil, wrap(err)
	} else if ok {
		if t.CertPath, err = parseCertPath(b); err != nil {
			return nil, wrap(err)
		}
	}
	return t, skipExtensions(d)
}

func parseSignature(c []byte) (Signature, error) {
	d := asn1.NewDecoder(c)
	a, err := readAlg(d)
	if err != nil {
		return Signature{}, wrap(err)
	}
	v, err := d.Expect(asn1.TagOctetString)
	if err != nil {
		return Signature{}, wrap(err)
	}
	return Signature{Alg: a, Value: append([]byte(nil), v...)}, skipExtensions(d)
}

// ParseSigned decodes the content octets of a signed SecPDU of the given
// kind (the SEQUENCE content, whatever tag the environment gave it), under
// Edition2020.
func ParseSigned(kind Kind, content []byte) (*Signed, error) {
	return ParseSignedEdition(kind, content, Edition2020)
}

// ParseSignedEdition is ParseSigned for the given edition.
func ParseSignedEdition(kind Kind, content []byte, ed Edition) (*Signed, error) {
	s := &Signed{Kind: kind, Diag: -1, Edition: ed}
	d := asn1.NewDecoder(content)
	if kind == KindHandshakeReq {
		b, err := d.Expect(tagUTF8)
		if err != nil {
			return nil, wrap(err)
		}
		if s.PP, err = parseNMTOKEN(b); err != nil {
			// pp is checked against supported protocols later; keep the
			// structure error only for non-UTF8 encodings.
			s.PP = string(b)
		}
	}
	tbs, err := d.ReadSpan()
	if err != nil || tbs.Tag != asn1.TagSequence {
		return nil, protoErr("tbs")
	}
	s.TBS = tbs.ContentEOC
	td := asn1.NewDecoder(tbs.Content)
	tok, err := td.Expect(asn1.TagSequence)
	if err != nil {
		return nil, wrap(err)
	}
	switch kind {
	case KindHandshakeReq, KindHandshakeAcc:
		parse := parseToken1
		if ed == Edition2018 {
			parse = parseToken1v2018
		}
		if s.Token1, err = parse(tok); err != nil {
			return nil, err
		}
	default:
		if s.Token3, err = parseToken3(tok); err != nil {
			return nil, err
		}
	}
	switch kind {
	case KindHandshakeReq, KindHandshakeAcc, KindApplicationReject, KindApplAbort:
		if td.More() {
			a, err := td.ReadSpan()
			if err != nil {
				return nil, wrap(err)
			}
			s.ApplData = a.Full
		} else if kind == KindApplicationReject {
			return nil, protoErr("ApplicationReject without applData")
		}
	case KindHandshakeSecReject, KindHandshakeSecAbort, KindDtSecAbort:
		if b, ok, err := td.Optional(tagEnumerated); err != nil {
			return nil, wrap(err)
		} else if ok {
			n, err := asn1.DecodeInt(b)
			if err != nil || n < 0 || n > 1000 {
				return nil, protoErr("diag")
			}
			s.Diag = int(n)
		}
	}
	if err := skipExtensions(td); err != nil {
		return nil, err
	}
	sc, err := d.Expect(asn1.TagSequence)
	if err != nil {
		return nil, protoErr("sign: %v", err)
	}
	if s.Sig, err = parseSignature(sc); err != nil {
		return nil, err
	}
	return s, skipExtensions(d)
}

// ParseTransfer decodes the content octets of a ClearTransfer or an
// EncrTransfer.
func ParseTransfer(encrypted bool, content []byte, tg AuthenticatorTagging) (*Transfer, error) {
	t := &Transfer{Encrypted: encrypted}
	d := asn1.NewDecoder(content)
	tbp, err := d.ReadSpan()
	if err != nil || tbp.Tag != asn1.TagSequence {
		return nil, protoErr("tbp")
	}
	t.TBP = tbp.ContentEOC
	td := asn1.NewDecoder(tbp.Content)
	ts, err := td.ReadSpan()
	if err != nil || ts.Tag != asn1.TagSequence {
		return nil, protoErr("token2")
	}
	tok, err := parseToken2(ts)
	if err != nil {
		return nil, err
	}
	t.Token2 = *tok
	a, err := td.ReadSpan()
	if err != nil {
		return nil, protoErr("applData missing")
	}
	if encrypted {
		if a.Tag != asn1.TagOctetString {
			return nil, protoErr("encrypted applData not an OCTET STRING")
		}
		t.ApplData = a.Content
	} else {
		t.ApplData = a.Full
	}
	if err := skipExtensions(td); err != nil {
		return nil, err
	}
	if d.More() {
		ac, err := d.Expect(asn1.TagSequence)
		if err != nil {
			return nil, protoErr("auth: %v", err)
		}
		if t.Auth, err = parseAuthenticator(ac, tg); err != nil {
			return nil, err
		}
	} else if !encrypted {
		return nil, protoErr("ClearTransfer without auth")
	}
	return t, skipExtensions(d)
}

func parseAuthenticator(c []byte, tg AuthenticatorTagging) (*Authenticator, error) {
	nt, it := asn1.TagOctetString, asn1.TagOctetString
	if tg == AuthClause13 {
		nt, it = tagAuthNonce13, tagAuthICV13
	}
	a := &Authenticator{}
	d := asn1.NewDecoder(c)
	if b, ok, err := d.Optional(nt); err != nil {
		return nil, wrap(err)
	} else if ok {
		a.Nonce = append([]byte(nil), b...)
	}
	var err error
	if a.Alg, err = readAlg(d); err != nil {
		return nil, wrap(err)
	}
	v, err := d.Expect(it)
	if err != nil {
		return nil, wrap(err)
	}
	a.ICV = append([]byte(nil), v...)
	return a, skipExtensions(d)
}

// versionElem encodes Version: {v1} unless an explicit value is set (tests
// of the version checks).
func versionElem(has bool, v asn1.BitString) *asn1.Element {
	if has && v.Length > 0 {
		return asn1.BitStringElem(asn1.TagBitString, v)
	}
	return asn1.Prim(asn1.TagBitString, versionV1)
}
