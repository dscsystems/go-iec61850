package e2e

import (
	"crypto/sha256"
	"time"
)

// EventClass grades a security event (IEC 62351-4 clause 14, IEC 62351-14).
type EventClass uint8

const (
	ClassInfo EventClass = iota
	ClassWarning
	ClassIncident
	ClassAlarm
)

func (c EventClass) String() string {
	return [...]string{"info", "warning", "incident", "alarm"}[c]
}

// EventCode identifies a security event.
type EventCode string

const (
	EventHandshakeAccepted     EventCode = "handshake-accepted"
	EventHandshakeRejected     EventCode = "handshake-rejected"
	EventCertificateTooLarge   EventCode = "certificate-too-large"
	EventRevocationUnavailable EventCode = "revocation-unavailable"
	EventCertificateRevoked    EventCode = "certificate-revoked"
	EventCertificateExpired    EventCode = "certificate-expired"
	EventSignatureAlgMismatch  EventCode = "signature-algorithm-mismatch"
	EventInvalidSignature      EventCode = "invalid-signature"
	EventAddressMismatch       EventCode = "address-mismatch"
	EventReplay                EventCode = "replay"
	EventInvalidICV            EventCode = "invalid-icv"
	EventInvalidICVAlgorithm   EventCode = "invalid-icv-algorithm"
	EventDiagnosticSent        EventCode = "diagnostic-sent"
	EventDiagnosticReceived    EventCode = "diagnostic-received"
	EventRekeyStarted          EventCode = "rekey-started"
	EventRekeyCompleted        EventCode = "rekey-completed"
	EventRekeyTimeout          EventCode = "rekey-timeout"
	EventClockRegression       EventCode = "clock-regression"
	EventReleaseCompleted      EventCode = "release-completed"
	EventAbortSent             EventCode = "abort-sent"
	EventAbortReceived         EventCode = "abort-received"
	EventPeerInvalidated       EventCode = "peer-invalidated-during-association"
	EventResourceLimit         EventCode = "resource-limit"
	EventAttCertIgnored        EventCode = "attribute-certificate-ignored"
)

// Event is a security event. It never carries key material.
type Event struct {
	Time    time.Time
	Code    EventCode
	Class   EventClass
	Role    string // "client" or "server"
	AssoID  string
	PeerAE  string // AE-title object identifier, when known
	CertSHA [32]byte
	Diag    string // diagnostic sent or received, when relevant
	Detail  string
}

func alarmEvent(a Alarm) EventCode {
	switch a {
	case AlarmSignatureAlgorithmMismatch:
		return EventSignatureAlgMismatch
	case AlarmInvalidSignature:
		return EventInvalidSignature
	case AlarmAddressMismatch:
		return EventAddressMismatch
	case AlarmReplay:
		return EventReplay
	case AlarmInvalidICV:
		return EventInvalidICV
	case AlarmInvalidICVAlgorithm:
		return EventInvalidICVAlgorithm
	}
	return ""
}

func certSHA(der []byte) [32]byte {
	if der == nil {
		return [32]byte{}
	}
	return sha256.Sum256(der)
}
