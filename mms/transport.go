package mms

import (
	"errors"
	"fmt"

	"github.com/dscsystems/go-iec61850/internal/osi/acse"
	"github.com/dscsystems/go-iec61850/internal/osi/cotp"
	"github.com/dscsystems/go-iec61850/internal/osi/presentation"
	"github.com/dscsystems/go-iec61850/internal/osi/session"
)

// framing carries MMS PDUs over the session/presentation data phase on
// top of an established COTP connection.
type framing struct {
	cotp *cotp.Conn
	// mmsContext is the presentation-context-identifier the peer assigned
	// to the MMS context. It is the proposer's choice, not a constant, so
	// it comes from the association setup: tagging data with the wrong one
	// produces PDUs the peer cannot decode, which looks like silence.
	mmsContext int
	// acseContext is the identifier of the ACSE context, which carries an
	// abort.
	acseContext int
}

// ErrAborted is an association ended by an abort (ACSE A-ABORT over a
// session ABORT) rather than released: by the peer, or by Abort on this
// end.
var ErrAborted = errors.New("mms: association aborted")

func (f *framing) sendMMS(pdu []byte) error {
	return session.SendData(f.cotp, presentation.WrapData(f.mmsContext, pdu))
}

// recvMMS returns the next MMS PDU, or an error wrapping ErrAborted when
// the peer aborted the association.
func (f *framing) recvMMS() ([]byte, error) {
	ud, err := session.ReceiveData(f.cotp)
	if err != nil {
		var ab *session.AbortedError
		if errors.As(err, &ab) {
			source := "the peer"
			if abrt, err := presentation.UnwrapAbort(ab.UserData); err == nil {
				if src, err := acse.ParseABRT(abrt); err == nil && src == acse.AbortSourceProvider {
					source = "the peer's provider"
				}
			}
			return nil, fmt.Errorf("%w by %s", ErrAborted, source)
		}
		return nil, err
	}
	return presentation.UnwrapData(ud)
}

// sendAbort aborts the association as its user: an ACSE ABRT in an ARU
// presentation PDU in a session ABORT, as libiec61850 frames it.
func (f *framing) sendAbort() error {
	return session.Abort(f.cotp, presentation.WrapAbort(f.acseContext, acse.ABRT(acse.AbortSourceUser)))
}
