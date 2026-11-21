// Package secevent is the cyber-security event channel of the library: one
// structured callback (a Sink) receives typed security events from every
// layer — transport, TLS, association and authentication, MMS and ACSI
// services, GOOSE, SV, R-GOOSE/R-SV and GDOI.
//
// Events are observations. With no sink attached nothing is computed: a
// protocol endpoint checks one pointer and carries on. With a sink attached
// events go through a Dispatcher, which never blocks the protocol, folds
// repeats of one event into one with a Count, and accounts for every event
// it has to drop.
//
//	d := secevent.NewDispatcher(secevent.JSONLinesSink(os.Stdout), secevent.Options{})
//	defer d.Close()
//	srv := server.New(m, server.WithCyberEventSink(d))
//
// Kinds ("conn.accepted", "goose.duplicate", …) are stable identifiers:
// they are never renamed. Each has a fixed Category, Severity, MITRE ATT&CK
// for ICS hint and IEC 62351-14 event identifier (KindInfo).
package secevent

import (
	"crypto/x509"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// Severity grades an event, in the order of RFC 5424 severities.
type Severity uint8

const (
	Info Severity = iota
	Notice
	Warning
	Alert
	Critical
)

var severityNames = [...]string{"info", "notice", "warning", "alert", "critical"}

func (s Severity) String() string {
	if int(s) < len(severityNames) {
		return severityNames[s]
	}
	return "unknown"
}

// MarshalText encodes the severity by name.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText decodes a severity name.
func (s *Severity) UnmarshalText(b []byte) error {
	for i, n := range severityNames {
		if n == string(b) {
			*s = Severity(i)
			return nil
		}
	}
	*s = Info
	return nil
}

// Category groups kinds.
type Category string

const (
	CatConnection    Category = "connection"
	CatPeer          Category = "peer"
	CatTLS           Category = "tls"
	CatAssociation   Category = "association"
	CatProtocol      Category = "protocol"
	CatAccess        Category = "access"
	CatControl       Category = "control"
	CatConfiguration Category = "configuration"
	CatProcessBus    Category = "process-bus"
	CatUnsolicited   Category = "unsolicited"
	CatFlood         Category = "flood"
	CatResource      Category = "resource"
	CatFile          Category = "file"
	CatKeyManagement Category = "key-management"
	CatMeta          Category = "meta"
)

// Action is what the library did about what it observed.
type Action string

const (
	Observed     Action = "observed"     // reported, nothing else done
	Ignored      Action = "ignored"      // the PDU or frame was dropped
	Rejected     Action = "rejected"     // the request was refused with a protocol answer
	Throttled    Action = "throttled"    // refused because of a rate limit
	Disconnected Action = "disconnected" // the connection or association was ended
	Blocked      Action = "blocked"      // refused by an access policy before any exchange
)

// Event is one security event. Fields that do not apply are zero; Fields
// says which of the numeric protocol fields are set, since zero is a real
// value for most of them.
type Event struct {
	Time      time.Time
	Kind      Kind
	Category  Category
	Severity  Severity
	Action    Action
	Protocol  string // "mms", "goose", "sv", "r-goose", "r-sv", "gdoi", "tls", "e2e"
	Role      string // "server", "client", "publisher", "subscriber", "keyserver", "member"
	SessionID uint64 // correlates the events of one connection or association
	Peer      PeerInfo
	Stream    *StreamInfo // a GOOSE/SV/R-* stream; nil otherwise
	Local     string      // local address or interface name

	// Protocol context.
	Fields      FieldMask
	Stage       string // association setup stage, for setup failures
	Service     int    // MMS confirmed service tag
	InvokeID    uint32
	ObjectRef   string // ACSI reference, or MMS domain/item
	FC          string
	AccessError int // MMS DataAccessError
	AddCause    int // IEC 61850-7-2 AddCause, for controls
	CtlNum      uint8
	OrCat       int
	OrIdent     string // as the client claimed it; at most 64 octets
	Test        bool
	StNum       uint32
	SqNum       uint32
	SmpCnt      uint16
	ConfRev     uint32
	Value       string // a human-readable value, bounded

	// Session summarises a connection that ended (conn.closed).
	Session *SessionSummary

	Count     int       // repeats folded into this event; 1 when not aggregated
	FirstSeen time.Time // start of the aggregation window
	Detail    string    // one-line explanation; never secrets
	Err       error
	Raw       []byte // copy of the offending PDU or frame, truncated

	Technique string // MITRE ATT&CK for ICS technique, a routing hint
	Std62351  string // IEC 62351-14 event identifier, or a library extension one ("x-…")
}

// FieldMask says which numeric protocol fields of an Event are set.
type FieldMask uint32

const (
	HasService FieldMask = 1 << iota
	HasInvokeID
	HasAccessError
	HasAddCause
	HasCtlNum
	HasOrigin
	HasTest
	HasStNum
	HasSqNum
	HasSmpCnt
	HasConfRev
)

// SessionSummary describes a connection or association that ended.
type SessionSummary struct {
	Reason    string
	Duration  time.Duration
	Requests  uint64
	OctetsIn  uint64
	OctetsOut uint64
}

// MACSource says where a peer's MAC address came from.
type MACSource string

const (
	MACNone     MACSource = ""         // not known
	MACNeighbor MACSource = "neighbor" // the OS neighbour (ARP/NDP) table: the peer's own
	MACGateway  MACSource = "gateway"  // off-link peer: the next hop's MAC, not the peer's
	MACStatic   MACSource = "static"   // configured
	MACCustom   MACSource = "custom"   // supplied by a user resolver
	MACFrame    MACSource = "frame"    // the source address of a layer-2 frame
)

// PeerInfo identifies the remote end of a connection.
type PeerInfo struct {
	Network     string // "tcp", "udp"
	RemoteAddr  netip.AddrPort
	LocalAddr   netip.AddrPort
	MAC         net.HardwareAddr
	MACSource   MACSource
	OnLink      bool
	Interface   string
	TLS         *TLSPeer
	ACSE        *ACSEPeer
	ConnectedAt time.Time
}

// TLSPeer is the TLS state of a connection. Certificate fields describe the
// leaf the peer presented, verified or not.
type TLSPeer struct {
	Version           uint16
	CipherSuite       uint16
	ServerName        string
	Subject           string
	Issuer            string
	SerialHex         string
	NotAfter          time.Time
	FingerprintSHA256 string
	Verified          bool
}

// ACSEPeer is what the peer stated, and proved, at association.
type ACSEPeer struct {
	CallingAPTitle     string
	CallingAEQualifier *int32
	CalledAPTitle      string
	CalledAEQualifier  *int32
	PasswordPresented  bool // never the password itself
	AProfileSubject    string
	AProfileSHA256     string
	E2E                bool
	E2EPeerAE          string
	E2EAssoID          string
}

// StreamInfo identifies a GOOSE or SV stream.
type StreamInfo struct {
	Kind         string // "goose" or "sv"
	AppID        uint16
	SrcMAC       net.HardwareAddr
	DstMAC       net.HardwareAddr
	VLANID       uint16
	VLANPriority uint8
	HasVLAN      bool
	ControlRef   string // goCbRef or svID
	DatSet       string
	GoID         string
	Simulation   bool
	Via          string // "l2", or the R-session sender's address
}

// AddrPort converts a net.Addr to a netip.AddrPort, the zero value when it
// is not an IP address.
func AddrPort(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	case *net.UDPAddr:
		return v.AddrPort()
	}
	if a == nil {
		return netip.AddrPort{}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

// CertFields fills the certificate fields of a TLSPeer.
func (t *TLSPeer) CertFields(c *x509.Certificate) {
	if c == nil {
		return
	}
	t.Subject = c.Subject.String()
	t.Issuer = c.Issuer.String()
	t.SerialHex = c.SerialNumber.Text(16)
	t.NotAfter = c.NotAfter
	t.FingerprintSHA256 = Fingerprint(c.Raw)
}

// detach replaces what the event shares with its submitter (stream, peer
// and session details, addresses) with copies.
func (e *Event) detach() {
	if e.Stream != nil {
		s := *e.Stream
		s.SrcMAC, s.DstMAC = slices.Clone(s.SrcMAC), slices.Clone(s.DstMAC)
		e.Stream = &s
	}
	if e.Session != nil {
		s := *e.Session
		e.Session = &s
	}
	e.Peer.MAC = slices.Clone(e.Peer.MAC)
	if e.Peer.TLS != nil {
		t := *e.Peer.TLS
		e.Peer.TLS = &t
	}
	if e.Peer.ACSE != nil {
		a := *e.Peer.ACSE
		a.CallingAEQualifier = clonePtr(a.CallingAEQualifier)
		a.CalledAEQualifier = clonePtr(a.CalledAEQualifier)
		e.Peer.ACSE = &a
	}
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

var sessionIDs atomic.Uint64

// NextSessionID returns a process-wide unique, increasing session
// identifier.
func NextSessionID() uint64 { return sessionIDs.Add(1) }

// String renders the event on one line.
func (e Event) String() string {
	var b strings.Builder
	b.WriteString(e.Time.UTC().Format(time.RFC3339Nano))
	b.WriteByte(' ')
	b.WriteString(strings.ToUpper(e.Severity.String()))
	b.WriteByte(' ')
	b.WriteString(string(e.Kind))
	if e.Action != "" && e.Action != Observed {
		b.WriteString(" action=")
		b.WriteString(string(e.Action))
	}
	if e.Peer.RemoteAddr.IsValid() {
		b.WriteString(" peer=")
		b.WriteString(e.Peer.RemoteAddr.String())
	}
	if e.Stream != nil {
		b.WriteString(" stream=")
		b.WriteString(e.Stream.ControlRef)
		if len(e.Stream.SrcMAC) > 0 {
			b.WriteString(" src=")
			b.WriteString(e.Stream.SrcMAC.String())
		}
	}
	if e.SessionID != 0 {
		b.WriteString(" session=")
		b.WriteString(uitoa(e.SessionID))
	}
	if e.Stage != "" {
		b.WriteString(" stage=")
		b.WriteString(e.Stage)
	}
	if e.ObjectRef != "" {
		b.WriteString(" ref=")
		b.WriteString(e.ObjectRef)
	}
	if e.Count > 1 {
		b.WriteString(" count=")
		b.WriteString(uitoa(uint64(e.Count)))
	}
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	if e.Err != nil {
		b.WriteString(" (")
		b.WriteString(e.Err.Error())
		b.WriteByte(')')
	}
	return b.String()
}

func uitoa(v uint64) string {
	var buf [20]byte
	i := len(buf)
	for {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			return string(buf[i:])
		}
	}
}
