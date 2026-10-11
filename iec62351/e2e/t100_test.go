package e2e

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/pki/pkitest"
)

// Single-fault handshake tests after IEC TS 62351-100-4 Tables 49 (client)
// and 50 (server): each mutates one ClearToken1 field of an otherwise valid,
// correctly re-signed PDU and checks the diagnostic.

var sha1WithRSA = AlgorithmIdentifier{asn1.OID{1, 2, 840, 113549, 1, 1, 5}, nullParams}

func resign(t *testing.T, s *Signed, f *fixture, server bool) []byte {
	t.Helper()
	id := f.cli.Local
	if server {
		id = f.srv.Local
	}
	alg, _ := sigAlgFor(id.Signer.Public())
	out, err := encodeSigned(s, func(tbs []byte) ([]byte, error) { return sign(id.Signer, alg, nil, tbs) })
	if err != nil {
		t.Fatal(err)
	}
	return content(t, out)
}

func v2() asn1.BitString { return bits(1) }

func TestT100Table50Server(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *Signed)
		diag   int
		alarm  Alarm
	}{
		{"1 pp not supported", func(s *Signed) { s.PP = "IEC 61850-8-2" }, HDProtectedProtocolNotSupported, AlarmNone},
		{"2 sigAlg differs from algo", func(s *Signed) { s.Token1.SigAlg = SigRSASHA256.id() }, -1, AlarmSignatureAlgorithmMismatch},
		{"6 signature algorithm not supported", func(s *Signed) {
			s.Token1.SigAlg, s.Sig.Alg = sha1WithRSA, sha1WithRSA
		}, HDInvalidSignatureAlgorithm, AlarmNone},
		{"7 version not supported", func(s *Signed) { s.Token1.HasVersion, s.Token1.Version = true, v2() }, HDUnexpectedVersion, AlarmNone},
		{"10 DH group not supported", func(s *Signed) { s.Token1.DHGroup = 28 }, HDDHGroupNotSupported, AlarmNone},
		{"11 HMAC not supported", func(s *Signed) { s.Token1.HMAC = AlgorithmIdentifier{oidAES128GCM, nil} }, HDHMACAlgorithmNotSupported, AlarmNone},
		{"12 AEA proposed, not supported", func(s *Signed) {
			s.Token1.AEA, s.Token1.AEAAlgs = true, []AlgorithmIdentifier{{oidAES128GCM, nil}}
		}, HDEncrModeAEANotSupported, AlarmNone},
		{"16 no supported ICV", func(s *Signed) { s.Token1.ICV = []AlgorithmIdentifier{{oidSHA256, nil}} }, HDICVAlgorithmsNotSupported, AlarmNone},
		{"17 applProtected set, encryption forbidden", func(s *Signed) { s.Token1.ConfParams = bits(1) }, HDEncryptionNotRequired, AlarmNone},
		{"q encryption proposed, forbidden", func(s *Signed) {
			s.Token1.HasEncr, s.Token1.Encr = true, []AlgorithmIdentifier{{oidAES128CBC, nil}}
		}, HDEncryptionNotRequired, AlarmNone},
		{"aa attribute certificate", func(s *Signed) { s.Token1.AttCert = []byte{0x30, 0x00} }, HDInvalidAttributeCertificate, AlarmNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
			cl, _ := NewClient(f.cli)
			req, _ := cl.HandshakeRequest(appl)
			s, err := ParseSigned(KindHandshakeReq, content(t, req))
			if err != nil {
				t.Fatal(err)
			}
			c.mutate(s)
			srv, _ := NewServer(f.srv)
			_, err = srv.ProcessHandshakeRequest(resign(t, s, f, false), clientAE)
			wantHS(t, err, c.diag, c.alarm)
		})
	}
}

func TestT100Table49Client(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *Signed)
		diag   int
		alarm  Alarm
	}{
		{"1 sigAlg differs from algo", func(s *Signed) { s.Token1.SigAlg = SigRSASHA256.id() }, -1, AlarmSignatureAlgorithmMismatch},
		{"5 signature algorithm not supported", func(s *Signed) {
			s.Token1.SigAlg, s.Sig.Alg = sha1WithRSA, sha1WithRSA
		}, HDInvalidSignatureAlgorithm, AlarmNone},
		{"6 version not offered", func(s *Signed) { s.Token1.HasVersion, s.Token1.Version = true, v2() }, HDUnexpectedVersion, AlarmNone},
		{"9 DH group differs", func(s *Signed) { s.Token1.DHGroup = int64(GroupMODP2048) }, HDIllegalDHGroupSelected, AlarmNone},
		{"10 HMAC differs", func(s *Signed) { s.Token1.HMAC = AlgorithmIdentifier{oidAES128GCM, nil} }, HDHMACAlgorithmNotSupported, AlarmNone},
		{"11 AEA selected, not proposed", func(s *Signed) {
			s.Token1.AEA, s.Token1.AEAAlgs = true, []AlgorithmIdentifier{{oidAES128GCM, nil}}
		}, HDAENotUsed, AlarmNone},
		{"15 ICV not offered", func(s *Signed) { s.Token1.ICV = []AlgorithmIdentifier{{oidSHA256, nil}} }, HDICVAlgorithmsNotSupported, AlarmNone},
		{"16 multiple ICV algorithms", func(s *Signed) {
			s.Token1.ICV = []AlgorithmIdentifier{ICVHMACSHA256.id(), ICVGMACAES128.id()}
		}, HDSingleICVAlgoRequired, AlarmNone},
		{"17 empty ICV set", func(s *Signed) { s.Token1.ICV = []AlgorithmIdentifier{} }, HDSingleICVAlgoRequired, AlarmNone},
		{"19 encryption selected, not proposed", func(s *Signed) {
			s.Token1.HasEncr, s.Token1.Encr = true, []AlgorithmIdentifier{{oidAES128CBC, nil}}
		}, HDEncryptionNotRequired, AlarmNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, pkitest.ECDSAP256, pkitest.ECDSAP256)
			cl, _ := NewClient(f.cli)
			srv, _ := NewServer(f.srv)
			req, _ := cl.HandshakeRequest(appl)
			if _, err := srv.ProcessHandshakeRequest(content(t, req), clientAE); err != nil {
				t.Fatal(err)
			}
			acc, _ := srv.HandshakeAccept(appl)
			s, err := ParseSigned(KindHandshakeAcc, content(t, acc))
			if err != nil {
				t.Fatal(err)
			}
			c.mutate(s)
			_, err = cl.ProcessHandshakeAccept(resign(t, s, f, true), serverAE)
			wantHS(t, err, c.diag, c.alarm)
		})
	}
}

// T50 row 2 under the IEC TS 62351-100-4 expectations: alarms carry
// no-reason-given when the policy asks for it (register R-07).
func TestAlarmDiagnosticSetting(t *testing.T) {
	se := hsAlarm(AlarmReplay, nil)
	if se.WireDiag(AlarmOmitDiagnostic) != -1 || se.WireDiag(AlarmNoReasonGiven) != HDNoReasonGiven {
		t.Fatal("alarm diagnostic mapping")
	}
}
