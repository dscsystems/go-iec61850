package osi

import (
	"bytes"
	"errors"
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

func TestApplDataRoundTrip(t *testing.T) {
	pdu := []byte{0xa8, 0x03, 0x80, 0x01, 0x01}
	a := ApplData(3, pdu)
	got, err := ParseApplData(a, 3)
	if err != nil || !bytes.Equal(got, pdu) {
		t.Fatalf("%x %v", got, err)
	}
	if _, err := ParseApplData(a, 5); err == nil {
		t.Fatal("wrong context accepted")
	}
}

func TestAssoRspAndAbort(t *testing.T) {
	sec := asn1.Cons(asn1.TagSequence, asn1.IntElem(asn1.TagInteger, 1)).Encode()
	alt, c, err := ParseAssoRsp([][]byte{AssoRsp(5, RspSecReject, sec)}, 5)
	if err != nil || alt != RspSecReject || !bytes.Equal(c, sec[2:]) {
		t.Fatalf("%d %x %v", alt, c, err)
	}
	_, _, err = ParseAssoRsp([][]byte{AssoRsp(7, RspAccept, sec)}, 5)
	var ee *EnvError
	if !errors.As(err, &ee) || ee.Diag != DiagInvalidIndirectReference {
		t.Fatalf("indirect reference: %v", err)
	}
	alt, _, d, err := ParseAssoAbr([][]byte{AssoAbrDiag(5, DiagInvalidPCI)}, 5)
	if err != nil || alt != AbrOsiDiag || d != DiagInvalidPCI {
		t.Fatalf("osiDiag: %d %d %v", alt, d, err)
	}
	if _, _, err := ParseData(-1, sec, 5); !errors.As(err, &ee) || ee.Diag != DiagProtocolError {
		t.Fatalf("missing pci: %v", err)
	}
	if _, _, err := ParseData(3, sec, 5); !errors.As(err, &ee) || ee.Diag != DiagInvalidPCI {
		t.Fatalf("wrong pci: %v", err)
	}
}
