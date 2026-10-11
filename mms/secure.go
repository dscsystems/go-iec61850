package mms

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
	"github.com/dscsystems/go-iec61850/iec62351/e2e"
	e2eosi "github.com/dscsystems/go-iec61850/iec62351/e2e/osi"
	"github.com/dscsystems/go-iec61850/internal/osi/acse"
	"github.com/dscsystems/go-iec61850/internal/osi/cotp"
	"github.com/dscsystems/go-iec61850/internal/osi/presentation"
	"github.com/dscsystems/go-iec61850/internal/osi/session"
)

// IEC 62351-4 native mode (end-to-end security) for MMS over the OSI
// stack: IEC 62351-4 clauses 13 to 15. The MMS Initiate travels inside the
// signed handshake, and every later MMS PDU inside an integrity-protected
// ClearTransfer.

// E2EPeer is the authenticated peer of an E2E association.
type E2EPeer = e2e.PeerSecurity

// E2ERejectedError is an association refused or aborted by the peer's E2E
// security, or by the protected protocol through it.
type E2ERejectedError = e2e.RejectedError

func aeFromIdentity(id ACSEIdentity) (e2e.AETitle, bool) {
	if len(id.APTitle) == 0 || !id.HasAEQual || id.AEQualifier < 0 {
		return e2e.AETitle{}, false
	}
	return e2e.AETitle{APTitle: asn1.OID(id.APTitle), AEQualifier: id.AEQualifier}, true
}

func identityFromAE(ae e2e.AETitle) ACSEIdentity {
	return ACSEIdentity{APTitle: []uint32(ae.APTitle), AEQualifier: ae.AEQualifier, HasAEQual: true}
}

// e2eClientAssociate runs the client side of the native-mode association
// over an established COTP connection.
func e2eClientAssociate(ct *cotp.Conn, opts Options, init InitiateRequest) (*framing, InitiateRequest, ACSEIdentity, error) {
	cfg := opts.E2E
	assoc, err := e2e.NewClient(cfg)
	if err != nil {
		return nil, InitiateRequest{}, ACSEIdentity{}, err
	}
	called, calling := opts.Called, opts.Calling
	if called.Empty() {
		called = identityFromAE(cfg.Peer)
	}
	if calling.Empty() {
		calling = identityFromAE(cfg.Local.AE)
	}
	fail := func(err error) (*framing, InitiateRequest, ACSEIdentity, error) {
		assoc.Close()
		return nil, InitiateRequest{}, ACSEIdentity{}, err
	}
	hs, err := assoc.HandshakeRequest(e2eosi.ApplData(presentation.ContextMMS, EncodeInitiateRequest(init)))
	if err != nil {
		return fail(err)
	}
	aarq := acse.BuildAARQ(e2e.OIDE2EMMSContext, called.toACSE(), calling.toACSE(),
		[][]byte{e2eosi.AssoReq(presentation.ContextE2E, hs)})
	cp := presentation.BuildCPE2E(presentation.DefaultCallingPSel, presentation.DefaultCalledPSel, aarq)
	fr := &framing{cotp: ct, mmsContext: presentation.ContextMMS, acseContext: presentation.ContextACSE,
		e2eContext: presentation.ContextE2E, sec: assoc, alarmDiag: cfg.Policy.AlarmDiagnostic}

	cpaUserData, err := session.ConnectClientExt(ct, nil, nil, cp, true)
	var refused *session.RefusedError
	if errors.As(err, &refused) {
		aare, perr := presentation.ParseCPRUserData(refused.UserData)
		if perr == nil {
			if res, perr := acse.ParseAARE(aare); perr == nil && !res.Accepted {
				if len(res.UserInfo) > 0 {
					if alt, content, perr := e2eosi.ParseAssoRsp(res.UserInfo, presentation.ContextE2E); perr == nil && alt != e2eosi.RspAccept {
						return fail(assoc.ProcessRejection(e2eosi.RspKind(alt), content))
					}
				}
				return fail(&RejectedError{Diagnostic: res.Diagnostic})
			}
		}
		return fail(fmt.Errorf("mms: association refused: %w", err))
	}
	if err != nil {
		var ab *session.AbortedError
		if errors.As(err, &ab) {
			return fail(fr.peerAborted(ab.UserData))
		}
		return fail(fmt.Errorf("mms: session connect: %w", err))
	}
	aare, err := presentation.ParseCPUserData(cpaUserData)
	if err != nil {
		return fail(fmt.Errorf("mms: presentation CPA: %w", err))
	}
	res, err := acse.ParseAARE(aare)
	if err != nil {
		fr.sendABRT(acse.AbortSourceProvider, nil)
		return fail(fmt.Errorf("mms: ACSE AARE: %w", err))
	}
	if !res.Accepted {
		return fail(&RejectedError{Diagnostic: res.Diagnostic})
	}
	if !res.ApplicationContext.Equal(e2e.OIDE2EMMSContext) {
		fr.sendABRT(acse.AbortSourceProvider, nil)
		return fail(fmt.Errorf("mms: e2e: server answered application context %v", res.ApplicationContext))
	}
	responding := identityFromACSE(res.Responding)
	// A responding identity, when present, must equal the called one
	// (IEC 62351-4 10.5.3); absent means the called one.
	respAE, ok := aeFromIdentity(responding)
	calledAE, _ := aeFromIdentity(called)
	if !ok {
		if len(responding.APTitle) > 0 {
			fr.sendABRT(acse.AbortSourceProvider, nil)
			return fail(errors.New("mms: e2e: responding AE-qualifier missing"))
		}
		respAE = calledAE
		responding = called
	} else if respAE.String() != calledAE.String() {
		fr.sendABRT(acse.AbortSourceProvider, nil)
		return fail(fmt.Errorf("mms: e2e: server answered as %v, called %v", respAE, calledAE))
	}
	alt, content, err := e2eosi.ParseAssoRsp(res.UserInfo, presentation.ContextE2E)
	if err != nil {
		var ee *e2eosi.EnvError
		if errors.As(err, &ee) {
			fr.abortOsi(ee.Diag)
		}
		return fail(err)
	}
	if alt != e2eosi.RspAccept {
		return fail(assoc.ProcessRejection(e2eosi.RspKind(alt), content))
	}
	appl, err := assoc.ProcessHandshakeAccept(content, respAE)
	if err != nil {
		if se, ok := e2e.AsSecurityError(err); ok {
			if sp, berr := assoc.HandshakeSecAbort(se); berr == nil {
				fr.sendABRT(acse.AbortSourceUser, [][]byte{e2eosi.AssoAbr(fr.e2eContext, e2eosi.AbrHandsSec, sp)})
			}
		}
		return fail(err)
	}
	resp, err := e2eosi.ParseApplData(appl, presentation.ContextMMS)
	if err != nil {
		fr.sendAbort()
		return fail(err)
	}
	negotiated, err := ParseInitiateResponse(resp)
	if err != nil {
		fr.sendAbort()
		return fail(fmt.Errorf("mms: initiate response: %w", err))
	}
	return fr, negotiated, responding, nil
}

// initiateErrorPDU is an MMS initiate-ErrorPDU with errorClass initiate (8),
// code other (0).
func initiateErrorPDU() []byte {
	return asn1.Cons(tagInitiateError, serviceErrorBody(&ServiceError{Class: 8, Code: 0})).Encode()
}

// e2eServerResult is the outcome of the server-side native handshake.
type e2eServerResult struct {
	fr         *framing
	mmsInit    []byte
	assoc      *e2e.Association
	neg        presentation.NegotiatedE2E
	responding acse.Identity
}

// isE2EContext reports a native-mode application context.
func isE2EContext(ctx asn1.OID, cfg *e2e.ServerConfig) bool {
	if ctx.Equal(e2e.OIDE2EMMSContext) {
		return true
	}
	return cfg != nil && cfg.AcceptT100AppContext && ctx.Equal(e2e.OIDE2EMMSContextT100)
}

// e2eServerRefuse sends an AARE rejection in a CPR in a session REFUSE.
func e2eServerRefuse(ct *cotp.Conn, cp presentation.CP, appCtx asn1.OID, result, diag int, responding acse.Identity, userInfo [][]byte, trace func(string, []byte)) {
	aare := acse.BuildAARE(appCtx, result, diag, responding, userInfo)
	trace("tx AARE", aare)
	sel := cp.CalledPSel
	if len(sel) == 0 {
		sel = presentation.DefaultCalledPSel
	}
	session.Refuse(ct, presentation.BuildCPRWithE2E(sel, cp.Contexts, aare, true))
}

// e2eServerHandshake verifies a native-mode AARQ. On success it returns the
// MMS InitiateRequest to process; the caller then calls e2eServerAccept or
// e2eServerApplReject.
func e2eServerHandshake(ct *cotp.Conn, cp presentation.CP, areq acse.Request, opts AcceptOptions) (*e2eServerResult, error) {
	trace := opts.trace
	cfg := opts.E2E
	// Under E2E the responding identity is the AE title the server's E2E
	// certificate names: the client checks one against the other.
	var responding acse.Identity
	if cfg != nil {
		responding = identityFromAE(cfg.Local.AE).toACSE()
	} else if opts.Responding != nil {
		responding = opts.Responding.toACSE()
	}
	if cfg == nil {
		e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, acse.DiagAppContextNotSupported, responding, nil, trace)
		return nil, fmt.Errorf("%w: native-mode (E2E) association not enabled", ErrRejected)
	}
	neg := presentation.NegotiateWithE2E(cp.Contexts, true)
	fr := &framing{cotp: ct, mmsContext: neg.MMS, acseContext: neg.ACSE, e2eContext: neg.E2E,
		alarmDiag: cfg.Policy.AlarmDiagnostic}
	if fr.acseContext == 0 {
		fr.acseContext = presentation.ContextACSE
	}
	if areq.NonKernel {
		// Protocol error in the ACSE kernel (IEC 62351-4 15.6.1).
		fr.sendABRT(acse.AbortSourceProvider, nil)
		return nil, fmt.Errorf("%w: AARQ outside the ACSE kernel in native mode", ErrRejected)
	}
	if neg.E2E == 0 || neg.MMS == 0 {
		e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, acse.DiagNoReason, responding, nil, trace)
		return nil, fmt.Errorf("%w: E2E or MMS presentation context missing", ErrRejected)
	}
	local := cfg.Local.AE
	if called, ok := aeFromIdentity(identityFromACSE(areq.Called)); ok && called.String() != local.String() {
		e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, acse.DiagCalledAPTitleNotRecognized, responding, nil, trace)
		return nil, fmt.Errorf("%w: called AE %v is not %v", ErrRejected, called, local)
	}
	calling, ok := aeFromIdentity(identityFromACSE(areq.Calling))
	if !ok {
		e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, 3 /* calling-AP-title-not-recognized */, responding, nil, trace)
		return nil, fmt.Errorf("%w: calling AE title missing", ErrRejected)
	}
	content, err := e2eosi.ParseAssoReq(areq.UserInfo, neg.E2E)
	if err != nil {
		// Register R-20: AARE rejected-permanent, no-reason-given, without
		// user-information.
		e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, acse.DiagNoReason, responding, nil, trace)
		return nil, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	assoc, err := e2e.NewServer(cfg)
	if err != nil {
		e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, acse.DiagNoReason, responding, nil, trace)
		return nil, err
	}
	fr.sec = assoc
	appl, err := assoc.ProcessHandshakeRequest(content, calling)
	if err != nil {
		se, _ := e2e.AsSecurityError(err)
		var ui [][]byte
		if se != nil {
			if sp, berr := assoc.SecReject(se); berr == nil {
				ui = [][]byte{e2eosi.AssoRsp(neg.E2E, e2eosi.RspSecReject, sp)}
			}
		}
		e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, acse.DiagNoReason, responding, ui, trace)
		return nil, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	mmsInit, err := e2eosi.ParseApplData(appl, neg.MMS)
	res := &e2eServerResult{fr: fr, mmsInit: mmsInit, assoc: assoc, neg: neg, responding: responding}
	if err != nil {
		e2eServerApplReject(ct, cp, areq, res, trace)
		return nil, fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return res, nil
}

// e2eServerApplReject refuses the association on behalf of MMS with a
// signed ApplicationReject carrying an initiate-ErrorPDU.
func e2eServerApplReject(ct *cotp.Conn, cp presentation.CP, areq acse.Request, r *e2eServerResult, trace func(string, []byte)) {
	var ui [][]byte
	if sp, err := r.assoc.ApplicationReject(e2eosi.ApplData(r.neg.MMS, initiateErrorPDU())); err == nil {
		ui = [][]byte{e2eosi.AssoRsp(r.neg.E2E, e2eosi.RspApplReject, sp)}
	}
	e2eServerRefuse(ct, cp, areq.ApplicationContext, acse.ResultRejectedPermanent, acse.DiagNoReason, r.responding, ui, trace)
}

// e2eServerAccept answers with the signed HandshakeAcc carrying the MMS
// InitiateResponse.
func e2eServerAccept(ct *cotp.Conn, cp presentation.CP, areq acse.Request, r *e2eServerResult, initResp []byte, sessionCalledSSEL []byte, trace func(string, []byte)) error {
	acc, err := r.assoc.HandshakeAccept(e2eosi.ApplData(r.neg.MMS, initResp))
	if err != nil {
		return err
	}
	aare := acse.BuildAARE(areq.ApplicationContext, acse.ResultAccepted, acse.DiagNull, r.responding,
		[][]byte{e2eosi.AssoRsp(r.neg.E2E, e2eosi.RspAccept, acc)})
	trace("tx AARE", aare)
	sel := cp.CalledPSel
	if len(sel) == 0 {
		sel = presentation.DefaultCalledPSel
	}
	_, cpa := presentation.BuildCPAWithE2E(sel, cp.Contexts, aare, true)
	trace("tx CPA", cpa)
	return session.Reply(ct, sessionCalledSSEL, cpa)
}

// E2EKeepAlive is the TCP keep-alive used under IEC 62351-4 (H.3.4: about
// one minute to detect a dead peer).
var E2EKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}
