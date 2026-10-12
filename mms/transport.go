package mms

import (
	"errors"
	"fmt"
	"sync"

	"github.com/dscsystems/go-iec61850/iec62351/e2e"
	e2eosi "github.com/dscsystems/go-iec61850/iec62351/e2e/osi"
	"github.com/dscsystems/go-iec61850/internal/osi/acse"
	"github.com/dscsystems/go-iec61850/internal/osi/cotp"
	"github.com/dscsystems/go-iec61850/internal/osi/presentation"
	"github.com/dscsystems/go-iec61850/internal/osi/session"
)

// framing carries MMS PDUs over the session/presentation data phase on
// top of an established COTP connection. With IEC 62351-4 E2E security
// (sec non-nil) every MMS PDU travels in a ClearTransfer on the E2E
// presentation context, and nothing reaches the MMS layer before its
// integrity check value, time and sequence number have been verified.
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

	// e2eContext and sec are set for an E2E-secured association.
	e2eContext int
	sec        *e2e.Association
	edition    e2e.Edition
	alarmDiag  e2e.AlarmDiagnostic

	// wmu serialises the writes framing makes on its own (aborts, release)
	// with the callers' writes, which already hold their connection lock:
	// it is always taken innermost.
	wmu sync.Mutex
	// closed is set once an abort was sent or received; nothing more is sent.
	closed bool
}

// ErrAborted is an association ended by an abort (ACSE A-ABORT over a
// session ABORT) rather than released: by the peer, or by Abort on this
// end.
var ErrAborted = errors.New("mms: association aborted")

// releaseSignal is returned by recvMMS when the peer sent a session FINISH
// (release request) or DISCONNECT (release response).
type releaseSignal struct {
	response bool
	rel      acse.Release
}

func (r *releaseSignal) Error() string {
	if r.response {
		return "mms: release response received"
	}
	return "mms: release request received"
}

func (f *framing) sendMMS(pdu []byte) error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.closed {
		return fmt.Errorf("%w (closed)", ErrAborted)
	}
	if f.sec == nil {
		return session.SendData(f.cotp, presentation.WrapData(f.mmsContext, pdu))
	}
	sp, err := f.sec.Seal(e2eosi.ApplDataFor(f.edition, f.mmsContext, pdu))
	if err != nil {
		return err
	}
	return session.SendData(f.cotp, presentation.WrapUserData(f.e2eContext, sp))
}

// recvMMS returns the next MMS PDU, an error wrapping ErrAborted when the
// peer aborted the association, or a *releaseSignal.
func (f *framing) recvMMS() ([]byte, error) {
	kind, ud, err := session.Receive(f.cotp)
	if err != nil {
		var ab *session.AbortedError
		if errors.As(err, &ab) {
			return nil, f.peerAborted(ab.UserData)
		}
		return nil, err
	}
	switch kind {
	case session.KindFinish, session.KindDisconnect:
		// Release user data is a plain fully-encoded-data on the ACSE context.
		_, apdu, err := presentation.UnwrapDataCtx(ud)
		if err != nil {
			return nil, fmt.Errorf("mms: release PDU: %w", err)
		}
		rel, err := acse.ParseRelease(apdu)
		if err != nil {
			return nil, fmt.Errorf("mms: release APDU: %w", err)
		}
		return nil, &releaseSignal{response: kind == session.KindDisconnect, rel: rel}
	}
	if f.sec == nil {
		return presentation.UnwrapData(ud)
	}
	ctx, tlv, err := presentation.UnwrapDataCtx(ud)
	if err != nil {
		f.abortOsi(e2eosi.DiagProtocolError)
		return nil, fmt.Errorf("mms: e2e: %w", err)
	}
	content, encrypted, err := e2eosi.ParseData(ctx, tlv, f.e2eContext)
	if err != nil {
		var ee *e2eosi.EnvError
		if errors.As(err, &ee) {
			f.abortOsi(ee.Diag)
		}
		return nil, err
	}
	appl, err := f.sec.Open(content, encrypted)
	if err != nil {
		if se, ok := e2e.AsSecurityError(err); ok {
			f.abortDt(se)
		}
		return nil, err
	}
	pdu, err := e2eosi.ParseApplDataFor(f.edition, appl, f.mmsContext)
	if err != nil {
		f.abortDt(&e2e.SecurityError{Phase: e2e.PhaseData, Diag: e2e.DDProtocolError, Err: err})
		return nil, err
	}
	return pdu, nil
}

// peerAborted interprets a received session ABORT.
func (f *framing) peerAborted(ud []byte) error {
	f.wmu.Lock()
	f.closed = true
	f.wmu.Unlock()
	source := "the peer"
	_, apdu, err := presentation.UnwrapAbortCtx(ud)
	if err != nil {
		return fmt.Errorf("%w by %s", ErrAborted, source)
	}
	ab, err := acse.ParseABRTFull(apdu)
	if err != nil {
		return fmt.Errorf("%w by %s", ErrAborted, source)
	}
	if ab.Source == acse.AbortSourceProvider {
		source = "the peer's provider"
	}
	if f.sec != nil && len(ab.UserInfo) > 0 {
		alt, content, diag, err := e2eosi.ParseAssoAbr(ab.UserInfo, f.e2eContext)
		switch {
		case err != nil:
		case alt == e2eosi.AbrOsiDiag:
			return fmt.Errorf("%w by %s: osiDiag %d", ErrAborted, source, diag)
		default:
			re := f.sec.ProcessRejection(e2eosi.AbortKind(alt), content)
			return fmt.Errorf("%w by %s: %w", ErrAborted, source, re)
		}
	}
	return fmt.Errorf("%w by %s", ErrAborted, source)
}

// sendAbort aborts the association as its user: an ACSE ABRT in an ARU
// presentation PDU in a session ABORT, as libiec61850 frames it. Under E2E
// the ABRT carries a signed ApplAbort.
func (f *framing) sendAbort() error {
	if f.sec != nil {
		sp, err := f.sec.ApplAbort(nil)
		if err == nil {
			return f.sendABRT(acse.AbortSourceUser, [][]byte{e2eosi.AssoAbr(f.e2eContext, e2eosi.AbrAppl, sp)})
		}
	}
	return f.sendABRT(acse.AbortSourceUser, nil)
}

func (f *framing) sendABRT(source int, userInfo [][]byte) error {
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	return session.Abort(f.cotp, presentation.WrapAbort(f.acseContext, acse.BuildABRT(source, userInfo)))
}

// abortDt answers a data-transfer security error with a signed DtSecAbort.
func (f *framing) abortDt(se *e2e.SecurityError) {
	sp, err := f.sec.DtSecAbort(se)
	if err != nil {
		f.sendABRT(acse.AbortSourceUser, nil)
		return
	}
	f.sendABRT(acse.AbortSourceUser, [][]byte{e2eosi.AssoAbr(f.e2eContext, e2eosi.AbrDtSec, sp)})
}

// abortOsi answers an environment error with an unsigned osiDiag abort.
func (f *framing) abortOsi(diag int) {
	f.sec.Close()
	f.sendABRT(acse.AbortSourceUser, [][]byte{e2eosi.AssoAbrDiag(f.e2eContext, diag)})
}

// sendRelease sends an ACSE RLRQ (in FINISH) or RLRE (in DISCONNECT), with
// the signed ReleaseReq/ReleaseRsp under E2E.
func (f *framing) sendRelease(response bool) error {
	var userInfo [][]byte
	if f.sec != nil {
		var sp []byte
		var err error
		if response {
			sp, err = f.sec.ReleaseResponse()
		} else {
			sp, err = f.sec.ReleaseRequest()
		}
		if err != nil {
			return err
		}
		userInfo = [][]byte{e2eosi.Release(f.e2eContext, sp)}
	}
	f.wmu.Lock()
	defer f.wmu.Unlock()
	if f.closed {
		return ErrAborted
	}
	if response {
		ud := presentation.WrapUserData(f.acseContext, acse.BuildRLRE(acse.ReleaseNormal, userInfo))
		return session.Disconnect(f.cotp, ud)
	}
	ud := presentation.WrapUserData(f.acseContext, acse.BuildRLRQ(acse.ReleaseNormal, userInfo))
	return session.Finish(f.cotp, ud)
}

// checkRelease verifies the E2E part of a received release APDU.
func (f *framing) checkRelease(r *releaseSignal) error {
	if f.sec == nil {
		return nil
	}
	content, err := e2eosi.ParseRelease(r.rel.UserInfo, f.e2eContext)
	if err != nil {
		return err
	}
	if r.response {
		return f.sec.ProcessReleaseResponse(content)
	}
	return f.sec.ProcessReleaseRequest(content)
}
