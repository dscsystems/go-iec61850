package e2e

import (
	"errors"
	"fmt"
)

// HandshakeDiagnostics values of the Annex B code component (register R-03:
// Annex B inserts altSig-mismatch (19), shifting the values of clause 14.2.1).
const (
	HDNoReasonGiven                 = 0
	HDProtocolError                 = 1
	HDProtectedProtocolNotSupported = 2
	HDInvalidSignatureAlgorithm     = 3
	HDUnexpectedVersion             = 4
	HDHMACAlgorithmNotSupported     = 5
	HDEncryptionNotRequired         = 6
	HDEncryptionRequired            = 7
	HDInvalidPublicKeyCertificate   = 8
	HDInvalidCertificationPath      = 9
	HDInvalidTimeValue              = 10
	HDDHGroupNotSupported           = 11
	HDIllegalDHGroupSelected        = 12
	HDICVAlgorithmsNotSupported     = 13
	HDEncryptAlgorithmsNotSupported = 14
	HDAEAAlgorithmsNotSupported     = 15
	HDInvalidAttributeCertificate   = 16
	HDEncrModeAEANotSupported       = 17
	HDAEIsRequired                  = 18
	HDAltSigMismatch                = 19
	HDAEASelectButEncrypNotSupp     = 20
	HDInvalidAEAlgorithm            = 21
	HDSingleAEAlgorithmRequired     = 22
	HDAENotUsed                     = 23
	HDInvalidEncryptionAlgorithm    = 24
	HDSingleEncryptAlgoRequired     = 25
	HDSingleICVAlgoRequired         = 26
)

// DtDiagnostics values. Value 5 is gmac-init-vector-required in the 2018
// code component and "not used" in Annex B of AMD1:2020; neither edition
// has this implementation send it.
const (
	DDNoReasonGiven          = 0
	DDProtocolError          = 1
	DDUnexpectedVersion      = 2
	DDEncryptionNotSelected  = 3
	DDEncryptionRequired     = 4
	DDGMACInitVectorRequired = 5 // Edition2018 only
	DDGMACNonceRequired      = 6
	DDInvalidTimeValue       = 7
	DDInvalidSequenceNumber  = 8
	DDAESInitVectorRequired  = 9
	DDUnexpectedDHPublicKey  = 10
	DDUnexpectedChangedKey   = 11 // unexpected-changedCypher in Annex B
)

var hdNames = map[int]string{
	0: "no-reason-given", 1: "protocol-error", 2: "protected-protocol-not-supported",
	3: "invalid-signatureAlgorithm", 4: "unexpected-version", 5: "hmac-algorithm-not-supported",
	6: "encryption-not-required", 7: "encryption-required", 8: "invalid-public-key-certificate",
	9: "invalid-certification-path", 10: "invalid-time-value", 11: "dhGroup-not-supported",
	12: "illegal-dhGroup-selected", 13: "icv-algorithms-not-supported", 14: "encrypt-algorithms-not-supported",
	15: "aea-algorithms-not-supported", 16: "invalid-attribute-certificate", 17: "encr-mode-aea-not-supported",
	18: "ae-is-required", 19: "altSig-mismatch", 20: "aea-select-but-encryp-not-supp",
	21: "invalid-ae-algorithm", 22: "single-ae-algorithm-required", 23: "ae-not-used",
	24: "invalid-encryption-algorithm", 25: "single-encrypt-algo-required", 26: "single-icv-algo-required",
}

var ddNames = map[int]string{
	0: "no-reason-given", 1: "protocol-error", 2: "unexpected-version", 3: "encryption-not-selected",
	4: "encryption-required", 5: "gmac-init-vector-required", 6: "gmac-nonce-required", 7: "invalid-time-value", 8: "invalid-sequence-number",
	9: "aes-init-vector-required", 10: "unexpected-dhPublicKey", 11: "unexpected-changedCypher",
}

// HandshakeDiagName and DtDiagName name a diagnostic value.
func HandshakeDiagName(v int) string { return diagName(hdNames, v) }
func DtDiagName(v int) string        { return diagName(ddNames, v) }

func diagName(m map[int]string, v int) string {
	if v < 0 {
		return "absent"
	}
	if s, ok := m[v]; ok {
		return s
	}
	return fmt.Sprintf("diag-%d", v)
}

// Phase is where a security error was found.
type Phase uint8

const (
	PhaseHandshake Phase = iota + 1
	PhaseData
	PhaseRelease
)

// Alarm is a security alarm (IEC 62351-4 clause 14): a condition that may
// be caused by an adversary, reported without a diagnostic.
type Alarm uint8

const (
	AlarmNone Alarm = iota
	AlarmSignatureAlgorithmMismatch
	AlarmInvalidSignature
	AlarmAddressMismatch
	AlarmReplay
	AlarmInvalidICV
	AlarmInvalidICVAlgorithm
)

func (a Alarm) String() string {
	return [...]string{"none", "signature-algorithm-mismatch", "invalid-signature", "address-mismatch",
		"replay", "invalid-icv", "invalid-icv-algorithm"}[a]
}

// SecurityError is an exception condition of E2E security. The environment
// turns it into the matching SecPDU (HandshakeSecReject, HandshakeSecAbort
// or DtSecAbort).
type SecurityError struct {
	Phase Phase
	Diag  int // HandshakeDiagnostics or DtDiagnostics value; -1 for none
	Alarm Alarm
	Err   error // internal cause; never sent
}

func (e *SecurityError) Error() string {
	name := HandshakeDiagName(e.Diag)
	if e.Phase == PhaseData {
		name = DtDiagName(e.Diag)
	}
	if e.Alarm != AlarmNone {
		name = "alarm " + e.Alarm.String()
	}
	if e.Err != nil {
		return fmt.Sprintf("e2e: %s: %v", name, e.Err)
	}
	return "e2e: " + name
}

func (e *SecurityError) Unwrap() error { return e.Err }

// WireDiag is the diagnostic to send for e: absent for an alarm, unless the
// policy asks for no-reason-given (register R-07).
func (e *SecurityError) WireDiag(p AlarmDiagnostic) int {
	if e.Alarm != AlarmNone {
		if p == AlarmNoReasonGiven {
			return 0
		}
		return -1
	}
	return e.Diag
}

func hsErr(diag int, err error) *SecurityError {
	return &SecurityError{Phase: PhaseHandshake, Diag: diag, Err: err}
}

func hsAlarm(a Alarm, err error) *SecurityError {
	return &SecurityError{Phase: PhaseHandshake, Diag: -1, Alarm: a, Err: err}
}

func dtErr(diag int, err error) *SecurityError {
	return &SecurityError{Phase: PhaseData, Diag: diag, Err: err}
}

func dtAlarm(a Alarm, err error) *SecurityError {
	return &SecurityError{Phase: PhaseData, Diag: -1, Alarm: a, Err: err}
}

// AsSecurityError extracts a *SecurityError.
func AsSecurityError(err error) (*SecurityError, bool) {
	var se *SecurityError
	ok := errors.As(err, &se)
	return se, ok
}

// RejectedError is a peer's signed rejection or abort of the association.
type RejectedError struct {
	Kind Kind
	// Diag is the peer's diagnostic, -1 when absent (an alarm on its side).
	Diag int
	// ApplData is the protected protocol's reject or abort information
	// (an MMS initiate-ErrorPDU for an ApplicationReject), nil when absent.
	ApplData []byte
	// Authenticated reports that the signature and certificate of the
	// rejecting PDU were verified. An unauthenticated rejection still ends
	// the association attempt but must not be trusted for diagnosis.
	Authenticated bool
}

func (e *RejectedError) Error() string {
	d := HandshakeDiagName(e.Diag)
	if e.Kind == KindDtSecAbort {
		d = DtDiagName(e.Diag)
	}
	auth := ""
	if !e.Authenticated {
		auth = " (unauthenticated)"
	}
	return fmt.Sprintf("e2e: peer sent %v, diagnostic %s%s", e.Kind, d, auth)
}
