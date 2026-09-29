// Package session implements the minimal subset of the ISO 8327-1
// connection-oriented session protocol used by the MMS profile: the
// CONNECT/ACCEPT/REFUSE SPDUs for association setup, ABORT, and the
// GIVE-TOKENS + DATA-TRANSFER prefix used for every data message. The full session
// service (tokens, activities, resynchronisation) is not used by MMS and
// is not implemented.
package session

import (
	"bytes"
	"errors"
	"fmt"
)

// Transport is the underlying COTP service the session layer runs over.
type Transport interface {
	Send([]byte) error
	Receive() ([]byte, error)
}

// SPDU type identifiers (SI octet).
const (
	siGiveTokens   = 0x01
	siDataTransfer = 0x01
	siConnect      = 0x0d
	siAccept       = 0x0e
	siRefuse       = 0x0c
	siAbort        = 0x19
	siFinish       = 0x09
	siDisconnect   = 0x0a
)

// Parameter and parameter-group identifiers.
const (
	pgiConnectAccept = 0x05
	piProtocolOpts   = 0x13
	piTSDUMaxSize    = 0x15
	piVersionNumber  = 0x16
	piSessionUserReq = 0x14
	piCallingSSEL    = 0x33
	piCalledSSEL     = 0x34
	piTransportDisc  = 0x11
	piReasonCode     = 0x32
	pgiUserData      = 0xc1
)

// Reason codes of a REFUSE SPDU (ISO 8327-1).
const (
	// ReasonUserData is a rejection by the called session user whose
	// following octets carry its user data (the presentation CPR).
	ReasonUserData = 2
)

// RefusedError is a CONNECT the peer refused, with the user data of its
// REFUSE SPDU: the presentation CPR carrying the ACSE AARE.
type RefusedError struct {
	Reason   byte
	UserData []byte
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("session: connection refused (reason %d)", e.Reason)
}

// AbortedError is an ABORT SPDU received from the peer, with its user
// data: the presentation ARU carrying the ACSE ABRT.
type AbortedError struct {
	UserData []byte
}

func (e *AbortedError) Error() string { return "session: connection aborted by the peer" }

// ErrAborted matches an AbortedError with errors.Is.
var ErrAborted = errors.New("session: connection aborted by the peer")

func (e *AbortedError) Is(target error) bool { return target == ErrAborted }

// ConnectClient sends a CONNECT SPDU carrying userData (the presentation
// CP PDU) and returns the user data from the peer's ACCEPT SPDU.
func ConnectClient(t Transport, callingSSEL, calledSSEL, userData []byte) ([]byte, error) {
	spdu := buildConnect(siConnect, callingSSEL, calledSSEL, userData)
	if err := t.Send(spdu); err != nil {
		return nil, err
	}
	resp, err := t.Receive()
	if err != nil {
		return nil, err
	}
	if len(resp) > 0 && resp[0] == siRefuse {
		params, err := spduParams(resp)
		if err != nil {
			return nil, err
		}
		rc := findParam(params, piReasonCode)
		if len(rc) == 0 {
			return nil, &RefusedError{}
		}
		return nil, &RefusedError{Reason: rc[0], UserData: rc[1:]}
	}
	si, _, ud, err := parseConnectLike(resp)
	if err != nil {
		return nil, err
	}
	if si != siAccept {
		return nil, fmt.Errorf("session: expected ACCEPT, got SI 0x%02x", si)
	}
	return ud, nil
}

// AcceptResult is returned by AcceptServer with the CONNECT user data and
// a function to send the ACCEPT reply.
type AcceptResult struct {
	UserData    []byte
	CallingSSEL []byte
	CalledSSEL  []byte
}

// AcceptServer reads a CONNECT SPDU and returns its user data. The caller
// then invokes Reply to send the ACCEPT.
func AcceptServer(t Transport) (*AcceptResult, error) {
	spdu, err := t.Receive()
	if err != nil {
		return nil, err
	}
	si, params, ud, err := parseConnectLike(spdu)
	if err != nil {
		return nil, err
	}
	if si != siConnect {
		return nil, fmt.Errorf("session: expected CONNECT, got SI 0x%02x", si)
	}
	return &AcceptResult{
		UserData:    ud,
		CallingSSEL: findParam(params, piCallingSSEL),
		CalledSSEL:  findParam(params, piCalledSSEL),
	}, nil
}

// Reply sends the ACCEPT SPDU carrying userData (the presentation CPA PDU).
//
// calledSSEL is echoed back when the peer addressed one: a responder that
// answers a CONNECT without naming the session selector it was reached at
// leaves a peer that checks it unable to confirm it reached the right end.
func Reply(t Transport, calledSSEL, userData []byte) error {
	return t.Send(buildConnect(siAccept, nil, calledSSEL, userData))
}

// Refuse sends a REFUSE SPDU, the session user's rejection of a CONNECT,
// carrying userData (the presentation CPR) after reason code 2. The
// transport connection is to be released after it.
func Refuse(t Transport, userData []byte) error {
	var params bytes.Buffer
	writePI(&params, piTransportDisc, []byte{0x01}) // release the transport
	writePI(&params, piReasonCode, append([]byte{ReasonUserData}, userData...))
	return t.Send(spdu(siRefuse, params.Bytes()))
}

// Abort sends an ABORT SPDU carrying userData (the presentation ARU). The
// transport disconnect parameter says the transport is released, by the
// user, for no stated reason, as libiec61850 sends it.
func Abort(t Transport, userData []byte) error {
	var params bytes.Buffer
	writePI(&params, piTransportDisc, []byte{0x0b})
	writePGI(&params, pgiUserData, userData)
	return t.Send(spdu(siAbort, params.Bytes()))
}

func spdu(si byte, params []byte) []byte {
	out := []byte{si}
	out = appendLen(out, len(params))
	return append(out, params...)
}

// SendData sends a data-phase message: the GIVE-TOKENS and DATA-TRANSFER
// SPDUs followed by userData (the presentation user-data PDU).
func SendData(t Transport, userData []byte) error {
	buf := make([]byte, 0, 4+len(userData))
	buf = append(buf, siGiveTokens, 0x00)   // GIVE TOKENS, LI 0
	buf = append(buf, siDataTransfer, 0x00) // DATA TRANSFER, LI 0
	buf = append(buf, userData...)
	return t.Send(buf)
}

// ReceiveData reads a data-phase message and returns the presentation
// user data, stripping the session SPDU prefix.
func ReceiveData(t Transport) ([]byte, error) {
	tsdu, err := t.Receive()
	if err != nil {
		return nil, err
	}
	if len(tsdu) > 0 && tsdu[0] == siAbort {
		params, err := spduParams(tsdu)
		if err != nil {
			return nil, &AbortedError{}
		}
		ud, _ := findUserData(params)
		return nil, &AbortedError{UserData: ud}
	}
	return stripDataPrefix(tsdu)
}

func stripDataPrefix(tsdu []byte) ([]byte, error) {
	// The data phase is prefixed by GIVE-TOKENS then DATA-TRANSFER. Both
	// SPDUs share SI 0x01, so they cannot be told apart by value; strip up
	// to two such SPDUs and return the presentation user data that follows.
	// Some stacks omit GIVE-TOKENS, leaving a single DATA-TRANSFER.
	rest := tsdu
	for i := 0; i < 2 && len(rest) >= 2; i++ {
		if rest[0] != siDataTransfer { // 0x01 covers both GT and DT
			break
		}
		li := int(rest[1])
		if 2+li > len(rest) {
			return nil, fmt.Errorf("session: bad SPDU LI %d", li)
		}
		rest = rest[2+li:]
	}
	return rest, nil
}

func buildConnect(si byte, callingSSEL, calledSSEL, userData []byte) []byte {
	var params bytes.Buffer

	// Connect/Accept Item parameter group.
	var cai bytes.Buffer
	writePI(&cai, piProtocolOpts, []byte{0x00}) // no extended concatenation
	writePI(&cai, piVersionNumber, []byte{0x02})
	writePGI(&params, pgiConnectAccept, cai.Bytes())

	// Session user requirements: duplex functional unit (bit 1) = 0x0002.
	writePI(&params, piSessionUserReq, []byte{0x00, 0x02})

	if len(callingSSEL) > 0 {
		writePI(&params, piCallingSSEL, callingSSEL)
	}
	if len(calledSSEL) > 0 {
		writePI(&params, piCalledSSEL, calledSSEL)
	}

	// User data parameter group carries the presentation PDU.
	writePGI(&params, pgiUserData, userData)

	return spdu(si, params.Bytes())
}

// appendLen appends a session length indicator: one octet up to 254, else
// 0xff and two octets (ISO 8327-1 8.2.5).
func appendLen(b []byte, n int) []byte {
	if n < 255 {
		return append(b, byte(n))
	}
	return append(b, 0xff, byte(n>>8), byte(n))
}

// readLen reads a length indicator at b[0], returning the length and the
// octets the indicator took.
func readLen(b []byte) (int, int, bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	if b[0] != 0xff {
		return int(b[0]), 1, true
	}
	if len(b) < 3 {
		return 0, 0, false
	}
	return int(b[1])<<8 | int(b[2]), 3, true
}

// spduParams returns the parameter field of an SPDU.
func spduParams(spdu []byte) ([]byte, error) {
	if len(spdu) < 2 {
		return nil, fmt.Errorf("session: short SPDU")
	}
	li, n, ok := readLen(spdu[1:])
	if !ok || 1+n+li > len(spdu) {
		return nil, fmt.Errorf("session: SPDU length exceeds buffer")
	}
	return spdu[1+n : 1+n+li], nil
}

// parseConnectLike parses a CONNECT/ACCEPT SPDU and returns its SI and
// the user-data parameter contents.
func parseConnectLike(spdu []byte) (si byte, params, userData []byte, err error) {
	params, err = spduParams(spdu)
	if err != nil {
		return 0, nil, nil, err
	}
	si = spdu[0]
	ud, err := findUserData(params)
	if err != nil {
		return 0, nil, nil, err
	}
	return si, params, ud, nil
}

// findParam returns the value of a session parameter, or nil when absent.
func findParam(params []byte, code byte) []byte {
	for len(params) >= 2 {
		plen, n, ok := readLen(params[1:])
		if !ok || 1+n+plen > len(params) {
			return nil
		}
		if params[0] == code {
			return append([]byte(nil), params[1+n:1+n+plen]...)
		}
		params = params[1+n+plen:]
	}
	return nil
}

// findUserData walks the parameter fields looking for the user-data PGI.
func findUserData(params []byte) ([]byte, error) {
	for len(params) >= 2 {
		code := params[0]
		plen, n, ok := readLen(params[1:])
		if !ok || 1+n+plen > len(params) {
			return nil, fmt.Errorf("session: parameter length %d overflows", plen)
		}
		val := params[1+n : 1+n+plen]
		if code == pgiUserData {
			return val, nil
		}
		params = params[1+n+plen:]
	}
	return nil, nil
}

func writePI(b *bytes.Buffer, code byte, val []byte) {
	b.WriteByte(code)
	b.Write(appendLen(nil, len(val)))
	b.Write(val)
}

func writePGI(b *bytes.Buffer, code byte, content []byte) { writePI(b, code, content) }
