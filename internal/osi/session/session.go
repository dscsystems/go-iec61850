// Package session implements the minimal subset of the ISO 8327-1
// connection-oriented session protocol used by the MMS profile: the
// CONNECT/ACCEPT SPDUs for association setup and the GIVE-TOKENS +
// DATA-TRANSFER prefix used for every data message. The full session
// service (tokens, activities, resynchronisation) is not used by MMS and
// is not implemented.
package session

import (
	"bytes"
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
	pgiUserData      = 0xc1
)

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

	out := make([]byte, 0, 2+params.Len())
	out = append(out, si)
	// LI: for SPDUs whose length exceeds 254, the long form is used, but
	// MMS CONNECTs stay small; guard anyway.
	if params.Len() < 255 {
		out = append(out, byte(params.Len()))
	} else {
		out = append(out, 0xff, byte(params.Len()>>8), byte(params.Len()))
	}
	out = append(out, params.Bytes()...)
	return out
}

// parseConnectLike parses a CONNECT/ACCEPT SPDU and returns its SI and
// the user-data parameter contents.
func parseConnectLike(spdu []byte) (si byte, params, userData []byte, err error) {
	if len(spdu) < 2 {
		return 0, nil, nil, fmt.Errorf("session: short SPDU")
	}
	si = spdu[0]
	off := 2
	li := int(spdu[1])
	if spdu[1] == 0xff {
		if len(spdu) < 4 {
			return 0, nil, nil, fmt.Errorf("session: short long-form LI")
		}
		li = int(spdu[2])<<8 | int(spdu[3])
		off = 4
	}
	if off+li > len(spdu) {
		return 0, nil, nil, fmt.Errorf("session: SPDU LI %d exceeds buffer", li)
	}
	params = spdu[off : off+li]
	ud, err := findUserData(params)
	if err != nil {
		return 0, nil, nil, err
	}
	return si, params, ud, nil
}

// findParam returns the value of a session parameter, or nil when absent.
func findParam(params []byte, code byte) []byte {
	for len(params) >= 2 {
		plen := int(params[1])
		if 2+plen > len(params) {
			return nil
		}
		if params[0] == code {
			return append([]byte(nil), params[2:2+plen]...)
		}
		params = params[2+plen:]
	}
	return nil
}

// findUserData walks the parameter fields looking for the user-data PGI.
func findUserData(params []byte) ([]byte, error) {
	for len(params) >= 2 {
		code := params[0]
		plen := int(params[1])
		if 2+plen > len(params) {
			return nil, fmt.Errorf("session: parameter length %d overflows", plen)
		}
		val := params[2 : 2+plen]
		if code == pgiUserData {
			return val, nil
		}
		params = params[2+plen:]
	}
	return nil, nil
}

func writePI(b *bytes.Buffer, code byte, val []byte) {
	b.WriteByte(code)
	b.WriteByte(byte(len(val)))
	b.Write(val)
}

func writePGI(b *bytes.Buffer, code byte, content []byte) {
	b.WriteByte(code)
	b.WriteByte(byte(len(content)))
	b.Write(content)
}
