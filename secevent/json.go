package secevent

import (
	"encoding/hex"
	"encoding/json"
	"time"
)

// jsonEvent is the wire form of an Event. Field names are stable: they are
// never renamed, only added.
type jsonEvent struct {
	Time      time.Time   `json:"time"`
	Kind      Kind        `json:"kind"`
	Category  Category    `json:"category"`
	Severity  Severity    `json:"severity"`
	Action    Action      `json:"action,omitempty"`
	Protocol  string      `json:"protocol,omitempty"`
	Role      string      `json:"role,omitempty"`
	SessionID uint64      `json:"session,omitempty"`
	Peer      *jsonPeer   `json:"peer,omitempty"`
	Stream    *jsonStream `json:"stream,omitempty"`
	Local     string      `json:"local,omitempty"`

	Stage       string  `json:"stage,omitempty"`
	Service     *int    `json:"service,omitempty"`
	InvokeID    *uint32 `json:"invoke_id,omitempty"`
	ObjectRef   string  `json:"ref,omitempty"`
	FC          string  `json:"fc,omitempty"`
	AccessError *int    `json:"access_error,omitempty"`
	AddCause    *int    `json:"add_cause,omitempty"`
	CtlNum      *uint8  `json:"ctl_num,omitempty"`
	OrCat       *int    `json:"or_cat,omitempty"`
	OrIdent     *string `json:"or_ident,omitempty"`
	Test        *bool   `json:"test,omitempty"`
	StNum       *uint32 `json:"st_num,omitempty"`
	SqNum       *uint32 `json:"sq_num,omitempty"`
	SmpCnt      *uint16 `json:"smp_cnt,omitempty"`
	ConfRev     *uint32 `json:"conf_rev,omitempty"`
	Value       string  `json:"value,omitempty"`

	Session *jsonSession `json:"session_summary,omitempty"`

	Count     int        `json:"count,omitempty"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	Detail    string     `json:"detail,omitempty"`
	Err       string     `json:"error,omitempty"`
	Raw       string     `json:"raw,omitempty"`

	Technique string `json:"technique,omitempty"`
	Std62351  string `json:"iec62351_14,omitempty"`
}

type jsonPeer struct {
	Network     string     `json:"network,omitempty"`
	RemoteAddr  string     `json:"remote,omitempty"`
	LocalAddr   string     `json:"local,omitempty"`
	MAC         string     `json:"mac,omitempty"`
	MACSource   MACSource  `json:"mac_source,omitempty"`
	OnLink      bool       `json:"on_link,omitempty"`
	Interface   string     `json:"interface,omitempty"`
	TLS         *jsonTLS   `json:"tls,omitempty"`
	ACSE        *jsonACSE  `json:"acse,omitempty"`
	ConnectedAt *time.Time `json:"connected_at,omitempty"`
}

type jsonTLS struct {
	Version           uint16     `json:"version,omitempty"`
	CipherSuite       uint16     `json:"cipher_suite,omitempty"`
	ServerName        string     `json:"server_name,omitempty"`
	Subject           string     `json:"subject,omitempty"`
	Issuer            string     `json:"issuer,omitempty"`
	SerialHex         string     `json:"serial,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	FingerprintSHA256 string     `json:"sha256,omitempty"`
	Verified          bool       `json:"verified"`
}

type jsonACSE struct {
	CallingAPTitle     string `json:"calling_ap_title,omitempty"`
	CallingAEQualifier *int32 `json:"calling_ae_qualifier,omitempty"`
	CalledAPTitle      string `json:"called_ap_title,omitempty"`
	CalledAEQualifier  *int32 `json:"called_ae_qualifier,omitempty"`
	PasswordPresented  bool   `json:"password_presented,omitempty"`
	AProfileSubject    string `json:"aprofile_subject,omitempty"`
	AProfileSHA256     string `json:"aprofile_sha256,omitempty"`
	E2E                bool   `json:"e2e,omitempty"`
	E2EPeerAE          string `json:"e2e_peer_ae,omitempty"`
	E2EAssoID          string `json:"e2e_asso_id,omitempty"`
}

type jsonStream struct {
	Kind         string  `json:"kind,omitempty"`
	AppID        uint16  `json:"appid"`
	SrcMAC       string  `json:"src_mac,omitempty"`
	DstMAC       string  `json:"dst_mac,omitempty"`
	VLANID       *uint16 `json:"vlan_id,omitempty"`
	VLANPriority *uint8  `json:"vlan_priority,omitempty"`
	ControlRef   string  `json:"control_ref,omitempty"`
	DatSet       string  `json:"dat_set,omitempty"`
	GoID         string  `json:"go_id,omitempty"`
	Simulation   bool    `json:"simulation,omitempty"`
	Via          string  `json:"via,omitempty"`
}

type jsonSession struct {
	Reason     string `json:"reason,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	Requests   uint64 `json:"requests"`
	OctetsIn   uint64 `json:"octets_in"`
	OctetsOut  uint64 `json:"octets_out"`
}

func ptr[T any](v T) *T { return &v }

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// MarshalJSON encodes the event with stable snake_case field names; fields
// that are not set are left out, Err is its message and Raw is hex.
func (e Event) MarshalJSON() ([]byte, error) {
	j := jsonEvent{
		Time: e.Time, Kind: e.Kind, Category: e.Category, Severity: e.Severity,
		Action: e.Action, Protocol: e.Protocol, Role: e.Role, SessionID: e.SessionID,
		Local: e.Local, Stage: e.Stage, ObjectRef: e.ObjectRef, FC: e.FC, Value: e.Value,
		Count: e.Count, FirstSeen: timePtr(e.FirstSeen), Detail: e.Detail,
		Technique: e.Technique, Std62351: e.Std62351,
	}
	if e.Err != nil {
		j.Err = e.Err.Error()
	}
	if len(e.Raw) > 0 {
		j.Raw = hex.EncodeToString(e.Raw)
	}
	f := e.Fields
	if f&HasService != 0 {
		j.Service = ptr(e.Service)
	}
	if f&HasInvokeID != 0 {
		j.InvokeID = ptr(e.InvokeID)
	}
	if f&HasAccessError != 0 {
		j.AccessError = ptr(e.AccessError)
	}
	if f&HasAddCause != 0 {
		j.AddCause = ptr(e.AddCause)
	}
	if f&HasCtlNum != 0 {
		j.CtlNum = ptr(e.CtlNum)
	}
	if f&HasOrigin != 0 {
		j.OrCat, j.OrIdent = ptr(e.OrCat), ptr(e.OrIdent)
	}
	if f&HasTest != 0 {
		j.Test = ptr(e.Test)
	}
	if f&HasStNum != 0 {
		j.StNum = ptr(e.StNum)
	}
	if f&HasSqNum != 0 {
		j.SqNum = ptr(e.SqNum)
	}
	if f&HasSmpCnt != 0 {
		j.SmpCnt = ptr(e.SmpCnt)
	}
	if f&HasConfRev != 0 {
		j.ConfRev = ptr(e.ConfRev)
	}
	if s := e.Session; s != nil {
		j.Session = &jsonSession{Reason: s.Reason, DurationMS: s.Duration.Milliseconds(),
			Requests: s.Requests, OctetsIn: s.OctetsIn, OctetsOut: s.OctetsOut}
	}
	if s := e.Stream; s != nil {
		js := &jsonStream{Kind: s.Kind, AppID: s.AppID, ControlRef: s.ControlRef, DatSet: s.DatSet,
			GoID: s.GoID, Simulation: s.Simulation, Via: s.Via}
		if len(s.SrcMAC) > 0 {
			js.SrcMAC = s.SrcMAC.String()
		}
		if len(s.DstMAC) > 0 {
			js.DstMAC = s.DstMAC.String()
		}
		if s.HasVLAN {
			js.VLANID, js.VLANPriority = ptr(s.VLANID), ptr(s.VLANPriority)
		}
		j.Stream = js
	}
	j.Peer = e.Peer.json()
	return json.Marshal(j)
}

func (p PeerInfo) json() *jsonPeer {
	j := &jsonPeer{Network: p.Network, MACSource: p.MACSource, OnLink: p.OnLink,
		Interface: p.Interface, ConnectedAt: timePtr(p.ConnectedAt)}
	if p.RemoteAddr.IsValid() {
		j.RemoteAddr = p.RemoteAddr.String()
	}
	if p.LocalAddr.IsValid() {
		j.LocalAddr = p.LocalAddr.String()
	}
	if len(p.MAC) > 0 {
		j.MAC = p.MAC.String()
	}
	if t := p.TLS; t != nil {
		j.TLS = &jsonTLS{Version: t.Version, CipherSuite: t.CipherSuite, ServerName: t.ServerName,
			Subject: t.Subject, Issuer: t.Issuer, SerialHex: t.SerialHex, NotAfter: timePtr(t.NotAfter),
			FingerprintSHA256: t.FingerprintSHA256, Verified: t.Verified}
	}
	if a := p.ACSE; a != nil {
		ja := jsonACSE(*a)
		j.ACSE = &ja
	}
	if *j == (jsonPeer{}) {
		return nil
	}
	return j
}
