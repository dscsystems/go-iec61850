package e2e

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// Edition selects the IEC 62351-4 edition whose E2E-Security module defines
// the wire format. Amendment 1:2020 replaced the ClearToken1 definition and
// the OSI Virtual API of the first edition, and the two are not wire
// compatible:
//
//   - ClearToken1 field order: 2018 has time before dHKey; 2020 has dHKey,
//     hmac, then time.
//   - hmac and the algorithm lists: 2018 carries bare object identifiers;
//     2020 carries AlgorithmIdentifiers.
//   - encr-mode: 2018 aea is a SET OF, non-aea an untagged SEQUENCE with
//     SET OF lists; 2020 aea is a SEQUENCE OF, non-aea is [0] with encr a
//     SEQUENCE OF.
//   - ApplData in the OSI environment: 2018 is the protected protocol's PDU
//     itself; 2020 (Annex F.3) wraps it in an EXTERNAL naming its
//     presentation context.
//   - HandshakeDiagnostics: 2018 defines values 0 to 16 only.
//
// The 2018 layout follows the IEC code component IEC_62351-4.ASN.1_XSD.full
// dated 2018-04-19; the 2020 layout follows Annex B of IEC
// 62351-4:2018+AMD1:2020. Everything else (tokens 2 and 3, the signed and
// protected PDUs, Authenticator, the OSI environment module) is the same.
type Edition uint8

const (
	// Edition2020 is IEC 62351-4:2018+AMD1:2020, the edition IEC TS
	// 62351-100-4 tests. The default.
	Edition2020 Edition = iota
	// Edition2018 is IEC 62351-4:2018 (edition 1.0) before the amendment,
	// for peers built against it.
	Edition2018
)

func (e Edition) String() string {
	if e == Edition2018 {
		return "IEC 62351-4:2018"
	}
	return "IEC 62351-4:2018+AMD1:2020"
}

// maxDiag2018 is the last HandshakeDiagnostics value of the first edition.
const maxDiag2018 = HDInvalidAttributeCertificate

// diagFor maps a handshake diagnostic to one the edition defines: the
// values amendment 1 added become protocol-error under the first edition.
func (e Edition) diagFor(phase Phase, d int) int {
	if e == Edition2018 && phase == PhaseHandshake && d > maxDiag2018 {
		return HDProtocolError
	}
	return d
}

func oidElem(a AlgorithmIdentifier) *asn1.Element { return asn1.OIDElem(asn1.TagOID, a.Algorithm) }

func oidSet(t asn1.Tag, as []AlgorithmIdentifier) *asn1.Element {
	e := asn1.Cons(t)
	for _, a := range as {
		e.Add(oidElem(a))
	}
	return e
}

// element2018 encodes ClearToken1 per the first-edition code component.
func (t *ClearToken1) element2018() *asn1.Element {
	e := asn1.Cons(asn1.TagSequence,
		algElem(t.SigAlg),
		asn1.Prim(asn1.TagOctetString, t.PKCert),
		certPathElem(t.CertPath),
		versionElem(t.HasVersion, t.Version),
		asn1.Prim(tagUTF8, []byte(t.AssoID)),
		asn1.Prim(tagGenTime, t.TimeRaw),
		asn1.Cons(asn1.TagSequence,
			asn1.IntElem(asn1.TagInteger, t.DHGroup),
			asn1.Prim(asn1.TagOctetString, t.DHPublic)),
		oidElem(t.HMAC),
	)
	if t.AEA {
		e.Add(oidSet(asn1.TagSet, t.AEAAlgs))
	} else {
		na := asn1.Cons(asn1.TagSequence)
		if t.HasEncr {
			na.Add(oidSet(tagEncr, t.Encr))
		}
		na.Add(oidSet(tagICVSet, t.ICV))
		e.Add(na)
	}
	e.Add(asn1.BitStringElem(asn1.TagBitString, t.ConfParams))
	if t.AttCert != nil {
		e.Add(asn1.Prim(asn1.TagOctetString, t.AttCert))
	}
	return e
}

// parseOIDList decodes a SET OF / SEQUENCE OF OBJECT IDENTIFIER content as
// AlgorithmIdentifiers without parameters; empty is allowed (semantic check).
func parseOIDList(c []byte) ([]AlgorithmIdentifier, error) {
	d := asn1.NewDecoder(c)
	out := []AlgorithmIdentifier{}
	for d.More() {
		if len(out) >= 16 {
			return nil, protoErr("too many algorithms")
		}
		b, err := d.Expect(asn1.TagOID)
		if err != nil {
			return nil, wrap(err)
		}
		oid, err := asn1.DecodeOID(b)
		if err != nil {
			return nil, wrap(err)
		}
		out = append(out, AlgorithmIdentifier{Algorithm: oid})
	}
	return out, nil
}

// parseToken1v2018 decodes ClearToken1 per the first-edition code component.
func parseToken1v2018(c []byte) (*ClearToken1, error) {
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
	tb, err := d.Expect(tagGenTime)
	if err != nil {
		return nil, wrap(err)
	}
	if t.Time, t.TimeRaw, err = parseTime(tb); err != nil {
		return nil, err
	}
	if err := parseDHSet(d, t); err != nil {
		return nil, err
	}
	hb, err := d.Expect(asn1.TagOID)
	if err != nil {
		return nil, wrap(err)
	}
	oid, err := asn1.DecodeOID(hb)
	if err != nil {
		return nil, wrap(err)
	}
	t.HMAC = AlgorithmIdentifier{Algorithm: oid}
	tag, ok := d.PeekTag()
	if !ok {
		return nil, protoErr("encr-mode missing")
	}
	switch tag {
	case asn1.TagSet:
		ac, _ := d.Expect(asn1.TagSet)
		t.AEA = true
		if t.AEAAlgs, err = parseOIDList(ac); err != nil {
			return nil, err
		}
	case asn1.TagSequence:
		nc, _ := d.Expect(asn1.TagSequence)
		nd := asn1.NewDecoder(nc)
		if b, ok, err := nd.Optional(tagEncr); err != nil {
			return nil, wrap(err)
		} else if ok {
			t.HasEncr = true
			if t.Encr, err = parseOIDList(b); err != nil {
				return nil, err
			}
		}
		ic, err := nd.Expect(tagICVSet)
		if err != nil {
			return nil, wrap(err)
		}
		if t.ICV, err = parseOIDList(ic); err != nil {
			return nil, err
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

// ParseEdition reads "2020" (also "amd1" or empty) or "2018".
func ParseEdition(s string) (Edition, error) {
	switch s {
	case "", "2020", "amd1":
		return Edition2020, nil
	case "2018":
		return Edition2018, nil
	}
	return Edition2020, fmt.Errorf("e2e: unknown edition %q (2020 or 2018)", s)
}
