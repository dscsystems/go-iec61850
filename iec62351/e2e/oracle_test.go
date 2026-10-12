package e2e

import (
	"bytes"
	stdasn1 "encoding/asn1"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

// An independent oracle for the ClearToken1 layouts: the same token
// encoded by Go's encoding/asn1 from struct definitions transcribed by hand
// from the normative modules, sharing no code with this package's codec.
//
// 2018: IEC code component IEC_62351-4.ASN.1_XSD.full (2018-04-19),
//       E2E-Security, DEFINITIONS IMPLICIT TAGS.
// 2020: IEC 62351-4:2018+AMD1:2020 Annex B (printed p.81).

type oAlgID struct {
	Algorithm  stdasn1.ObjectIdentifier
	Parameters stdasn1.RawValue `asn1:"optional"`
}

type oDHSet struct {
	GroupID     int64
	DhPublicKey []byte
}

// 2020 Annex B.
type oNonAEA2020 struct {
	Encr     []oAlgID `asn1:"optional,tag:0"` // [0] SEQUENCE SIZE (1..MAX) OF
	IcvAlgID []oAlgID `asn1:"tag:1,set"`      // [1] SET SIZE (1..MAX) OF
}

type oToken1v2020 struct {
	SigAlg     oAlgID
	PkCert     []byte
	Version    stdasn1.BitString
	AssoID     string `asn1:"utf8"`
	DHKey      oDHSet
	Hmac       oAlgID
	Time       stdasn1.RawValue
	NonAEA     oNonAEA2020 `asn1:"tag:0"` // encr-mode non-aea [0] SEQUENCE
	ConfParams stdasn1.BitString
}

// 2018 code component.
type oNonAEA2018 struct {
	Encr     []stdasn1.ObjectIdentifier `asn1:"optional,tag:0,set"` // [0] SET OF oid
	IcvAlgID []stdasn1.ObjectIdentifier `asn1:"tag:1,set"`          // [1] SET OF oid
}

type oToken1v2018 struct {
	SigAlg     oAlgID
	PkCert     []byte
	Version    stdasn1.BitString
	AssoID     string `asn1:"utf8"`
	Time       stdasn1.RawValue
	DHKey      oDHSet
	Hmac       stdasn1.ObjectIdentifier
	NonAEA     oNonAEA2018 // encr-mode non-aea: untagged SEQUENCE
	ConfParams stdasn1.BitString
}

type oAEA2018 struct {
	SigAlg     oAlgID
	PkCert     []byte
	Version    stdasn1.BitString
	AssoID     string `asn1:"utf8"`
	Time       stdasn1.RawValue
	DHKey      oDHSet
	Hmac       stdasn1.ObjectIdentifier
	AEA        []stdasn1.ObjectIdentifier `asn1:"set"` // encr-mode aea: SET OF oid
	ConfParams stdasn1.BitString
}

type oAEA2020 struct {
	SigAlg     oAlgID
	PkCert     []byte
	Version    stdasn1.BitString
	AssoID     string `asn1:"utf8"`
	DHKey      oDHSet
	Hmac       oAlgID
	Time       stdasn1.RawValue
	AEA        []oAlgID // encr-mode aea: SEQUENCE OF AlgorithmIdentifier
	ConfParams stdasn1.BitString
}

var oNull = stdasn1.RawValue{FullBytes: []byte{0x05, 0x00}}

func soid(o asn1.OID) stdasn1.ObjectIdentifier {
	out := make(stdasn1.ObjectIdentifier, len(o))
	for i, v := range o {
		out[i] = int(v)
	}
	return out
}

func oracleToken(t *testing.T) (*ClearToken1, []byte) {
	t.Helper()
	root := pkitest.NewRoot("oracle", pkitest.ECDSAP256)
	leaf := root.NewE2ELeaf(asn1.OID{1, 3, 9999, 1}, 1, pkitest.LeafOptions{})
	tm := asn1.FormatTime62351(time.Date(2026, 10, 12, 8, 30, 15, 250e6, time.UTC))
	return &ClearToken1{
		SigAlg:     SigECDSASHA256.id(),
		PKCert:     leaf.DER,
		AssoID:     "42",
		DHGroup:    23,
		DHPublic:   bytes.Repeat([]byte{0x04}, 65),
		HMAC:       hmacSHA256ID,
		TimeRaw:    tm,
		ICV:        []AlgorithmIdentifier{ICVHMACSHA256.id()},
		ConfParams: bits(0),
	}, tm
}

func TestOracleClearToken1Edition2020(t *testing.T) {
	tok, tm := oracleToken(t)
	want, err := stdasn1.Marshal(oToken1v2020{
		SigAlg:     oAlgID{Algorithm: soid(oidECDSAWithSHA256)},
		PkCert:     tok.PKCert,
		Version:    stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
		AssoID:     "42",
		DHKey:      oDHSet{23, tok.DHPublic},
		Hmac:       oAlgID{Algorithm: soid(oidHMACWithSHA256), Parameters: oNull},
		Time:       stdasn1.RawValue{Tag: 24, Bytes: tm},
		NonAEA:     oNonAEA2020{IcvAlgID: []oAlgID{{Algorithm: soid(oidHMACWithSHA256), Parameters: oNull}}},
		ConfParams: stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := tok.element().Encode()
	if !bytes.Equal(got, want) {
		t.Fatalf("2020 ClearToken1 differs from the oracle\n got % x\nwant % x", got, want)
	}
	back, err := parseToken1(content(t, want))
	if err != nil || back.AssoID != "42" || len(back.ICV) != 1 {
		t.Fatalf("decoding the oracle's 2020 token: %+v %v", back, err)
	}
}

func TestOracleClearToken1Edition2018(t *testing.T) {
	tok, tm := oracleToken(t)
	want, err := stdasn1.Marshal(oToken1v2018{
		SigAlg:     oAlgID{Algorithm: soid(oidECDSAWithSHA256)},
		PkCert:     tok.PKCert,
		Version:    stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
		AssoID:     "42",
		Time:       stdasn1.RawValue{Tag: 24, Bytes: tm},
		DHKey:      oDHSet{23, tok.DHPublic},
		Hmac:       soid(oidHMACWithSHA256),
		NonAEA:     oNonAEA2018{IcvAlgID: []stdasn1.ObjectIdentifier{soid(oidHMACWithSHA256)}},
		ConfParams: stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := tok.element2018().Encode()
	if !bytes.Equal(got, want) {
		t.Fatalf("2018 ClearToken1 differs from the oracle\n got % x\nwant % x", got, want)
	}
	back, err := parseToken1v2018(content(t, want))
	if err != nil || back.AssoID != "42" || back.HMAC.Algorithm.String() != oidHMACWithSHA256.String() {
		t.Fatalf("decoding the oracle's 2018 token: %+v %v", back, err)
	}
	// The editions are not interchangeable.
	if _, err := parseToken1(content(t, want)); err == nil {
		t.Fatal("a 2018 token decoded as 2020")
	}
}

func TestOracleAEAAlternatives(t *testing.T) {
	tok, tm := oracleToken(t)
	tok.AEA, tok.AEAAlgs = true, []AlgorithmIdentifier{{Algorithm: oidAES256GCM}}
	want18, _ := stdasn1.Marshal(oAEA2018{
		SigAlg: oAlgID{Algorithm: soid(oidECDSAWithSHA256)}, PkCert: tok.PKCert,
		Version: stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1}, AssoID: "42",
		Time: stdasn1.RawValue{Tag: 24, Bytes: tm}, DHKey: oDHSet{23, tok.DHPublic},
		Hmac: soid(oidHMACWithSHA256), AEA: []stdasn1.ObjectIdentifier{soid(oidAES256GCM)},
		ConfParams: stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
	})
	if got := tok.element2018().Encode(); !bytes.Equal(got, want18) {
		t.Fatalf("2018 aea\n got % x\nwant % x", got, want18)
	}
	want20, _ := stdasn1.Marshal(oAEA2020{
		SigAlg: oAlgID{Algorithm: soid(oidECDSAWithSHA256)}, PkCert: tok.PKCert,
		Version: stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1}, AssoID: "42",
		DHKey: oDHSet{23, tok.DHPublic}, Hmac: oAlgID{Algorithm: soid(oidHMACWithSHA256), Parameters: oNull},
		Time: stdasn1.RawValue{Tag: 24, Bytes: tm}, AEA: []oAlgID{{Algorithm: soid(oidAES256GCM)}},
		ConfParams: stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
	})
	if got := tok.element().Encode(); !bytes.Equal(got, want20) {
		t.Fatalf("2020 aea\n got % x\nwant % x", got, want20)
	}
}

// Authenticator, ClearToken2 and the Signature are the same in both
// editions and untagged where the 2018 code component and Annex B agree
// (register R-04 closed: no [0]/[1] on nonce and icv).
type oAuthenticator struct {
	Nonce []byte `asn1:"optional"`
	Algo  oAlgID
	Icv   []byte
}

type oToken2 struct {
	Version    stdasn1.BitString
	AssoID     string `asn1:"utf8"`
	Time       stdasn1.RawValue
	Seq        int64
	ChangedKey bool `asn1:"optional,tag:3"`
}

func TestOracleAuthenticatorAndToken2(t *testing.T) {
	a := &Authenticator{Nonce: bytes.Repeat([]byte{1}, 12), Alg: ICVGMACAES128.id(), ICV: bytes.Repeat([]byte{2}, 12)}
	want, _ := stdasn1.Marshal(oAuthenticator{Nonce: a.Nonce, Algo: oAlgID{Algorithm: soid(oidAES128GCM)}, Icv: a.ICV})
	if got := a.element(AuthAnnexB).Encode(); !bytes.Equal(got, want) {
		t.Fatalf("Authenticator\n got % x\nwant % x", got, want)
	}
	tm := asn1.FormatTime62351(time.Date(2026, 10, 12, 8, 30, 15, 0, time.UTC))
	tk := &ClearToken2{AssoID: "42:7", TimeRaw: tm, Seq: 3, ChangedKey: true}
	want, _ = stdasn1.Marshal(oToken2{Version: stdasn1.BitString{Bytes: []byte{0x80}, BitLength: 1},
		AssoID: "42:7", Time: stdasn1.RawValue{Tag: 24, Bytes: tm}, Seq: 3, ChangedKey: true})
	if got := tk.element().Encode(); !bytes.Equal(got, want) {
		t.Fatalf("ClearToken2\n got % x\nwant % x", got, want)
	}
}
