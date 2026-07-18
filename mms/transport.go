package mms

import (
	"github.com/dscsystems/go-iec61850/internal/osi/cotp"
	"github.com/dscsystems/go-iec61850/internal/osi/presentation"
	"github.com/dscsystems/go-iec61850/internal/osi/session"
)

// framing carries MMS PDUs over the session/presentation data phase on
// top of an established COTP connection.
type framing struct {
	cotp *cotp.Conn
}

func (f *framing) sendMMS(pdu []byte) error {
	return session.SendData(f.cotp, presentation.WrapData(pdu))
}

func (f *framing) recvMMS() ([]byte, error) {
	ud, err := session.ReceiveData(f.cotp)
	if err != nil {
		return nil, err
	}
	return presentation.UnwrapData(ud)
}
