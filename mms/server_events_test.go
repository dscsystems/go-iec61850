package mms

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestTLSPeerVerified(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte{1}}
	st := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{cert}}
	if TLSPeer(st, false).Verified {
		t.Fatal("unchecked certificate reported verified")
	}
	if !TLSPeer(st, true).Verified {
		t.Fatal("certificate checked by the TLS layer reported unverified")
	}
	if TLSPeer(tls.ConnectionState{HandshakeComplete: true}, true).Verified {
		t.Fatal("no certificate reported verified")
	}
	st.VerifiedChains = [][]*x509.Certificate{{cert}}
	if !TLSPeer(st, false).Verified {
		t.Fatal("verified chain not reported")
	}
	if TLSPeer(tls.ConnectionState{}, true) != nil {
		t.Fatal("state before the handshake")
	}
}
