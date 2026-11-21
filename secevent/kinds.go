package secevent

import "strings"

// Kind identifies an event. Kinds are part of the API: once released they
// are never renamed or removed, only added to and deprecated.
type Kind string

// KindInfo is the fixed classification of a kind.
type KindInfo struct {
	Category  Category
	Severity  Severity
	Technique string // MITRE ATT&CK for ICS technique ID, a hint only
	// Std62351 is the IEC 62351-14 event identifier when one is mapped;
	// otherwise the library extension identifier "x-go-iec61850.<kind>",
	// which never collides with a standard one.
	Std62351 string
	// Always is set for kinds delivered every time, never folded into an
	// aggregate.
	Always bool
}

// Connection.
const (
	KindConnAccepted        Kind = "conn.accepted"
	KindConnUnexpected      Kind = "conn.unexpected"
	KindConnUnexpectedMAC   Kind = "conn.unexpected_mac"
	KindConnRejectedLimit   Kind = "conn.rejected_limit"
	KindConnRate            Kind = "conn.rate"
	KindConnNoData          Kind = "conn.no_data"
	KindConnNeverAssociated Kind = "conn.never_associated"
	KindConnIdleTimeout     Kind = "conn.idle_timeout"
	KindConnClosed          Kind = "conn.closed"
	KindConnDialFailed      Kind = "conn.dial_failed"
	KindConnAcceptError     Kind = "conn.accept_error"
)

// TLS (IEC 62351-3).
const (
	KindTLSCertRejected       Kind = "tls.cert_rejected"
	KindTLSCertRevoked        Kind = "tls.cert_revoked"
	KindTLSCRLStale           Kind = "tls.crl_stale"
	KindTLSNoClientCert       Kind = "tls.no_client_cert"
	KindTLSLocalCertRejected  Kind = "tls.local_cert_rejected"
	KindTLSPlaintextOnTLSPort Kind = "tls.plaintext_on_tls_port"
	KindTLSNonTLSProbe        Kind = "tls.non_tls_probe"
	KindTLSHandshakeFailed    Kind = "tls.handshake_failed"
	KindTLSHandshakeTimeout   Kind = "tls.handshake_timeout"
	KindTLSWeakParams         Kind = "tls.weak_params"
	KindTLSRenegotiation      Kind = "tls.renegotiation_attempt"
	KindTLSCertExpiring       Kind = "tls.cert_expiring"
	KindTLSCertChanged        Kind = "tls.cert_changed"
)

// Peer identity.
const (
	KindPeerMACChanged           Kind = "peer.mac_changed"
	KindPeerMACChangedMidsession Kind = "peer.mac_changed_midsession"
	KindPeerMACPinningViolation  Kind = "peer.mac_pinning_violation"
	KindPeerIPChanged            Kind = "peer.ip_changed"
	KindPeerMACShared            Kind = "peer.mac_shared"
	KindPeerMACUnavailable       Kind = "peer.mac_unavailable"
	KindPeerIdentityChanged      Kind = "peer.identity_changed"
)

// Association and authentication.
const (
	KindAssocEstablished       Kind = "assoc.established"
	KindAssocSetupFailed       Kind = "assoc.setup_failed"
	KindAssocAuthFailed        Kind = "assoc.auth_failed"
	KindAssocAuthRequired      Kind = "assoc.auth_required"
	KindAssocAProfileFailed    Kind = "assoc.aprofile_failed"
	KindAssocAProfileNoTLS     Kind = "assoc.aprofile_without_tls"
	KindAssocE2ERequired       Kind = "assoc.e2e_required"
	KindAssocNoMMSContext      Kind = "assoc.no_mms_context"
	KindAssocCalledMismatch    Kind = "assoc.called_mismatch"
	KindAssocBruteForce        Kind = "assoc.brute_force"
	KindAssocAbortedByPeer     Kind = "assoc.aborted_by_peer"
	KindAssocReleaseUnverified Kind = "assoc.release_unverified"
)

// Protocol validity.
const (
	KindProtoTPKTBad               Kind = "proto.tpkt_bad"
	KindProtoCOTPBad               Kind = "proto.cotp_bad"
	KindProtoTSDUOversized         Kind = "proto.tsdu_oversized"
	KindProtoSessionBad            Kind = "proto.session_bad"
	KindProtoPresentationBad       Kind = "proto.presentation_bad"
	KindProtoACSEBad               Kind = "proto.acse_bad"
	KindProtoPresentationContext   Kind = "proto.presentation_context"
	KindProtoMMSReject             Kind = "proto.mms_reject"
	KindProtoMMSDecode             Kind = "proto.mms_decode"
	KindProtoUnsupportedAccessSpec Kind = "proto.unsupported_access_spec"
	KindProtoOutstandingExceeded   Kind = "proto.outstanding_exceeded"
	KindProtoPDUExceedsNegotiated  Kind = "proto.pdu_exceeds_negotiated"
	KindProtoUnexpectedPDU         Kind = "proto.unexpected_pdu"
)

// Data access and discovery.
const (
	KindAccessObjectNonexistent   Kind = "access.object_nonexistent"
	KindAccessDomainUnknown       Kind = "access.domain_unknown"
	KindAccessDenied              Kind = "access.denied"
	KindAccessInvalidValue        Kind = "access.invalid_value"
	KindAccessSettingNotEditing   Kind = "access.setting_not_editing"
	KindAccessUnrecognizedService Kind = "access.unrecognized_service"
	KindAccessScan                Kind = "access.scan"
	KindAccessEnumeration         Kind = "access.enumeration"
	KindAccessServiceBlocked      Kind = "access.service_blocked"
	KindAccessOversizedRequest    Kind = "access.oversized_request"
)

// Controls.
const (
	KindCmdReceived             Kind = "cmd.received"
	KindCmdRejected             Kind = "cmd.rejected"
	KindCmdBruteForce           Kind = "cmd.brute_force"
	KindCmdOperateWithoutSelect Kind = "cmd.operate_without_select"
	KindCmdTestOnEnhanced       Kind = "cmd.test_on_enhanced"
	KindCmdOrIdentInvalid       Kind = "cmd.orident_invalid"
	KindCmdOriginMismatch       Kind = "cmd.origin_mismatch"
	KindCmdStaleTime            Kind = "cmd.stale_time"
	KindCmdNoTime               Kind = "cmd.no_time"
	KindCmdDuplicate            Kind = "cmd.duplicate"
	KindCmdTerminatedNegative   Kind = "cmd.terminated_negative"
	KindRemoteRejected          Kind = "remote.rejected"
)

// Configuration and mode changes.
const (
	KindCtrlModeChange         Kind = "ctrl.mode_change"
	KindCtrlSimulationMode     Kind = "ctrl.simulation_mode"
	KindCtrlSettingGroupChange Kind = "ctrl.setting_group_change"
	KindCtrlSettingEdit        Kind = "ctrl.setting_edit"
	KindCtrlConfigWrite        Kind = "ctrl.config_write"
	KindCtrlReportDisabled     Kind = "ctrl.report_disabled"
	KindCtrlLogDisabled        Kind = "ctrl.log_disabled"
	KindCtrlJournalInitialized Kind = "ctrl.journal_initialized"
	KindCtrlGooseCBChange      Kind = "ctrl.goose_cb_change"
	KindCtrlDatasetDefined     Kind = "ctrl.dataset_defined"
	KindCtrlDatasetDeleted     Kind = "ctrl.dataset_deleted"
)

// GOOSE.
const (
	KindGooseParseError             Kind = "goose.parse_error"
	KindGooseStNumRegressed         Kind = "goose.stnum_regressed"
	KindGoosePublisherRestart       Kind = "goose.publisher_restart"
	KindGooseSqNumGap               Kind = "goose.sqnum_gap"
	KindGooseDuplicate              Kind = "goose.duplicate"
	KindGooseStNumJump              Kind = "goose.stnum_jump"
	KindGooseDataChangeWithoutStNum Kind = "goose.data_change_without_stnum"
	KindGooseStNumWithoutDataChange Kind = "goose.stnum_without_data_change"
	KindGooseTimeRegressed          Kind = "goose.time_regressed"
	KindGooseStale                  Kind = "goose.stale"
	KindGooseTALExpired             Kind = "goose.tal_expired"
	KindGooseConfRevMismatch        Kind = "goose.confrev_mismatch"
	KindGooseDatasetMismatch        Kind = "goose.dataset_mismatch"
	KindGooseSourceMACChanged       Kind = "goose.source_mac_changed"
	KindGooseUnexpectedSource       Kind = "goose.unexpected_source"
	KindGooseUnexpectedStream       Kind = "goose.unexpected_stream"
	KindGooseTestFlag               Kind = "goose.test_flag"
	KindGooseSimulatedDropped       Kind = "goose.simulated_dropped"
	KindGooseNdsCom                 Kind = "goose.ndscom"
	KindGooseUntrackedStream        Kind = "goose.untracked_stream"
	KindGooseFlood                  Kind = "goose.flood"
)

// Sampled values.
const (
	KindSVParseError       Kind = "sv.parse_error"
	KindSVLEDecodeError    Kind = "sv.le_decode_error"
	KindSVSmpCntGap        Kind = "sv.smpcnt_gap"
	KindSVSmpCntDuplicate  Kind = "sv.smpcnt_duplicate"
	KindSVSmpCntRegressed  Kind = "sv.smpcnt_regressed"
	KindSVConfRevMismatch  Kind = "sv.confrev_mismatch"
	KindSVDatasetMismatch  Kind = "sv.dataset_mismatch"
	KindSVSyncLost         Kind = "sv.sync_lost"
	KindSVSourceMACChanged Kind = "sv.source_mac_changed"
	KindSVSimulatedDropped Kind = "sv.simulated_dropped"
	KindSVStreamLost       Kind = "sv.stream_lost"
	KindSVRateAnomaly      Kind = "sv.rate_anomaly"
)

// R-GOOSE and R-SV sessions.
const (
	KindRSessionMalformed         Kind = "rsession.malformed"
	KindRSessionUnknownKey        Kind = "rsession.unknown_key"
	KindRSessionUnauthentic       Kind = "rsession.unauthentic"
	KindRSessionUnsecured         Kind = "rsession.unsecured"
	KindRSessionUnsecuredAccepted Kind = "rsession.unsecured_accepted"
	KindRSessionReplay            Kind = "rsession.replay"
	KindRSessionNoActiveKey       Kind = "rsession.no_active_key"
)

// MMS client: unsolicited PDUs.
const (
	KindUnsolResponse           Kind = "unsol.response"
	KindUnsolReport             Kind = "unsol.report"
	KindUnsolCommandTermination Kind = "unsol.command_termination"
	KindUnsolLastApplError      Kind = "unsol.last_appl_error"
	KindUnsolServerRequest      Kind = "unsol.server_request"
)

// Files.
const (
	KindFileDirectory   Kind = "file.directory"
	KindFileRead        Kind = "file.read"
	KindFileObtain      Kind = "file.obtain"
	KindFileDelete      Kind = "file.delete"
	KindFileRename      Kind = "file.rename"
	KindFileInvalidName Kind = "file.invalid_name"
	KindFileRejected    Kind = "file.rejected"
	KindFileBusy        Kind = "file.busy"
)

// Key management (GDOI, IEC 62351-9).
const (
	KindGDOIRegistered     Kind = "gdoi.registered"
	KindGDOIRejected       Kind = "gdoi.rejected"
	KindGDOICookieMismatch Kind = "gdoi.cookie_mismatch"
	KindGDOIPhase1Flood    Kind = "gdoi.phase1_flood"
	KindGDOIPullFailed     Kind = "gdoi.pull_failed"
	KindGDOIRekeyFailed    Kind = "gdoi.rekey_failed"
	KindGDOIKeyExpiring    Kind = "gdoi.key_expiring"
)

// Flooding and resources.
const (
	KindFloodRequests     Kind = "flood.requests"
	KindFloodControls     Kind = "flood.controls"
	KindFloodWrites       Kind = "flood.writes"
	KindFloodReads        Kind = "flood.reads"
	KindFloodGI           Kind = "flood.gi"
	KindFloodDiscovery    Kind = "flood.discovery"
	KindFloodFile         Kind = "flood.file"
	KindDoSReportQueue    Kind = "dos.report_queue_full"
	KindDoSWriteStall     Kind = "dos.write_stall"
	KindDoSSlowFrame      Kind = "dos.slow_frame"
	KindDoSDatasetLimit   Kind = "dos.dataset_limit"
	KindDoSSelectionHold  Kind = "dos.selection_hold"
	KindDoSRCBReservation Kind = "dos.rcb_reservation"
)

// The event channel itself.
const (
	KindMetaEventsDropped Kind = "meta.events_dropped"
	KindMetaSinkPanic     Kind = "meta.sink_panic"
)

// E2EPrefix prefixes the kinds bridged from IEC 62351-4 E2E events:
// "e2e." followed by the e2e package's EventCode.
const E2EPrefix = "e2e."

// kinds is the classification table. Technique IDs are hints for SIEM
// routing, not attribution.
var kinds = map[Kind]KindInfo{
	KindConnAccepted:        {Category: CatConnection, Severity: Info},
	KindConnUnexpected:      {Category: CatConnection, Severity: Warning},
	KindConnUnexpectedMAC:   {Category: CatConnection, Severity: Alert, Technique: "T0830"},
	KindConnRejectedLimit:   {Category: CatConnection, Severity: Warning, Technique: "T0814"},
	KindConnRate:            {Category: CatConnection, Severity: Alert, Technique: "T0814"},
	KindConnNoData:          {Category: CatConnection, Severity: Notice, Technique: "T0846"},
	KindConnNeverAssociated: {Category: CatConnection, Severity: Warning, Technique: "T0814"},
	KindConnIdleTimeout:     {Category: CatConnection, Severity: Notice},
	KindConnClosed:          {Category: CatConnection, Severity: Info},
	KindConnDialFailed:      {Category: CatConnection, Severity: Notice},
	KindConnAcceptError:     {Category: CatResource, Severity: Critical, Technique: "T0814"},

	KindTLSCertRejected:       {Category: CatTLS, Severity: Alert, Technique: "T0830", Always: true},
	KindTLSCertRevoked:        {Category: CatTLS, Severity: Alert, Technique: "T0830", Always: true},
	KindTLSCRLStale:           {Category: CatTLS, Severity: Warning},
	KindTLSNoClientCert:       {Category: CatTLS, Severity: Alert},
	KindTLSLocalCertRejected:  {Category: CatTLS, Severity: Warning, Technique: "T0830"},
	KindTLSPlaintextOnTLSPort: {Category: CatTLS, Severity: Warning},
	KindTLSNonTLSProbe:        {Category: CatTLS, Severity: Notice, Technique: "T0846"},
	KindTLSHandshakeFailed:    {Category: CatTLS, Severity: Warning},
	KindTLSHandshakeTimeout:   {Category: CatTLS, Severity: Warning, Technique: "T0814"},
	KindTLSWeakParams:         {Category: CatTLS, Severity: Notice},
	KindTLSRenegotiation:      {Category: CatTLS, Severity: Warning},
	KindTLSCertExpiring:       {Category: CatTLS, Severity: Notice},
	KindTLSCertChanged:        {Category: CatTLS, Severity: Notice, Technique: "T0830"},

	KindPeerMACChanged:           {Category: CatPeer, Severity: Alert, Technique: "T0830", Always: true},
	KindPeerMACChangedMidsession: {Category: CatPeer, Severity: Critical, Technique: "T0830", Always: true},
	KindPeerMACPinningViolation:  {Category: CatPeer, Severity: Critical, Technique: "T0830", Always: true},
	KindPeerIPChanged:            {Category: CatPeer, Severity: Info},
	KindPeerMACShared:            {Category: CatPeer, Severity: Notice, Technique: "T0830"},
	KindPeerMACUnavailable:       {Category: CatPeer, Severity: Info},
	KindPeerIdentityChanged:      {Category: CatPeer, Severity: Warning, Technique: "T0849"},

	KindAssocEstablished:       {Category: CatAssociation, Severity: Info},
	KindAssocSetupFailed:       {Category: CatAssociation, Severity: Warning},
	KindAssocAuthFailed:        {Category: CatAssociation, Severity: Warning, Technique: "T0859"},
	KindAssocAuthRequired:      {Category: CatAssociation, Severity: Notice},
	KindAssocAProfileFailed:    {Category: CatAssociation, Severity: Alert, Technique: "T0849"},
	KindAssocAProfileNoTLS:     {Category: CatAssociation, Severity: Warning},
	KindAssocE2ERequired:       {Category: CatAssociation, Severity: Warning},
	KindAssocNoMMSContext:      {Category: CatAssociation, Severity: Warning},
	KindAssocCalledMismatch:    {Category: CatAssociation, Severity: Notice, Technique: "T0830"},
	KindAssocBruteForce:        {Category: CatAssociation, Severity: Alert, Technique: "T0859"},
	KindAssocAbortedByPeer:     {Category: CatAssociation, Severity: Notice},
	KindAssocReleaseUnverified: {Category: CatAssociation, Severity: Warning},

	KindProtoTPKTBad:               {Category: CatProtocol, Severity: Warning},
	KindProtoCOTPBad:               {Category: CatProtocol, Severity: Warning},
	KindProtoTSDUOversized:         {Category: CatProtocol, Severity: Warning, Technique: "T0814"},
	KindProtoSessionBad:            {Category: CatProtocol, Severity: Warning},
	KindProtoPresentationBad:       {Category: CatProtocol, Severity: Warning},
	KindProtoACSEBad:               {Category: CatProtocol, Severity: Warning},
	KindProtoPresentationContext:   {Category: CatProtocol, Severity: Warning},
	KindProtoMMSReject:             {Category: CatProtocol, Severity: Warning, Technique: "T0866"},
	KindProtoMMSDecode:             {Category: CatProtocol, Severity: Warning, Technique: "T0866"},
	KindProtoUnsupportedAccessSpec: {Category: CatProtocol, Severity: Notice},
	KindProtoOutstandingExceeded:   {Category: CatProtocol, Severity: Notice},
	KindProtoPDUExceedsNegotiated:  {Category: CatProtocol, Severity: Warning},
	KindProtoUnexpectedPDU:         {Category: CatProtocol, Severity: Notice},

	KindAccessObjectNonexistent:   {Category: CatAccess, Severity: Notice, Technique: "T0861"},
	KindAccessDomainUnknown:       {Category: CatAccess, Severity: Warning, Technique: "T0861"},
	KindAccessDenied:              {Category: CatAccess, Severity: Warning},
	KindAccessInvalidValue:        {Category: CatAccess, Severity: Notice},
	KindAccessSettingNotEditing:   {Category: CatAccess, Severity: Notice},
	KindAccessUnrecognizedService: {Category: CatAccess, Severity: Warning},
	KindAccessScan:                {Category: CatAccess, Severity: Alert, Technique: "T0861"},
	KindAccessEnumeration:         {Category: CatAccess, Severity: Info, Technique: "T0846"},
	KindAccessServiceBlocked:      {Category: CatAccess, Severity: Warning},
	KindAccessOversizedRequest:    {Category: CatAccess, Severity: Warning},

	KindCmdReceived:             {Category: CatControl, Severity: Notice},
	KindCmdRejected:             {Category: CatControl, Severity: Notice},
	KindCmdBruteForce:           {Category: CatControl, Severity: Alert, Technique: "T0806"},
	KindCmdOperateWithoutSelect: {Category: CatControl, Severity: Warning, Technique: "T0855"},
	KindCmdTestOnEnhanced:       {Category: CatControl, Severity: Warning},
	KindCmdOrIdentInvalid:       {Category: CatControl, Severity: Warning},
	KindCmdOriginMismatch:       {Category: CatControl, Severity: Warning, Technique: "T0849"},
	KindCmdStaleTime:            {Category: CatControl, Severity: Alert, Technique: "T0855"},
	KindCmdNoTime:               {Category: CatControl, Severity: Info},
	KindCmdDuplicate:            {Category: CatControl, Severity: Warning, Technique: "T0855"},
	KindCmdTerminatedNegative:   {Category: CatControl, Severity: Notice},
	KindRemoteRejected:          {Category: CatControl, Severity: Notice},

	KindCtrlModeChange:         {Category: CatConfiguration, Severity: Alert, Technique: "T0858", Always: true},
	KindCtrlSimulationMode:     {Category: CatConfiguration, Severity: Critical, Technique: "T0858", Always: true},
	KindCtrlSettingGroupChange: {Category: CatConfiguration, Severity: Alert, Technique: "T0836"},
	KindCtrlSettingEdit:        {Category: CatConfiguration, Severity: Alert, Technique: "T0836"},
	KindCtrlConfigWrite:        {Category: CatConfiguration, Severity: Alert, Technique: "T0836"},
	KindCtrlReportDisabled:     {Category: CatConfiguration, Severity: Notice, Technique: "T0815"},
	KindCtrlLogDisabled:        {Category: CatConfiguration, Severity: Warning, Technique: "T0878"},
	KindCtrlJournalInitialized: {Category: CatConfiguration, Severity: Alert, Technique: "T0872", Always: true},
	KindCtrlGooseCBChange:      {Category: CatConfiguration, Severity: Warning, Technique: "T0815"},
	KindCtrlDatasetDefined:     {Category: CatConfiguration, Severity: Info},
	KindCtrlDatasetDeleted:     {Category: CatConfiguration, Severity: Info},

	KindGooseParseError:             {Category: CatProcessBus, Severity: Notice},
	KindGooseStNumRegressed:         {Category: CatProcessBus, Severity: Alert, Technique: "T0856"},
	KindGoosePublisherRestart:       {Category: CatProcessBus, Severity: Notice},
	KindGooseSqNumGap:               {Category: CatProcessBus, Severity: Notice},
	KindGooseDuplicate:              {Category: CatProcessBus, Severity: Alert, Technique: "T0856"},
	KindGooseStNumJump:              {Category: CatProcessBus, Severity: Warning, Technique: "T0856"},
	KindGooseDataChangeWithoutStNum: {Category: CatProcessBus, Severity: Alert, Technique: "T0856"},
	KindGooseStNumWithoutDataChange: {Category: CatProcessBus, Severity: Notice},
	KindGooseTimeRegressed:          {Category: CatProcessBus, Severity: Warning, Technique: "T0856"},
	KindGooseStale:                  {Category: CatProcessBus, Severity: Warning, Technique: "T0815"},
	KindGooseTALExpired:             {Category: CatProcessBus, Severity: Warning, Technique: "T0814"},
	KindGooseConfRevMismatch:        {Category: CatProcessBus, Severity: Warning},
	KindGooseDatasetMismatch:        {Category: CatProcessBus, Severity: Warning},
	KindGooseSourceMACChanged:       {Category: CatProcessBus, Severity: Alert, Technique: "T0830", Always: true},
	KindGooseUnexpectedSource:       {Category: CatProcessBus, Severity: Warning, Technique: "T0849"},
	KindGooseUnexpectedStream:       {Category: CatProcessBus, Severity: Notice},
	KindGooseTestFlag:               {Category: CatProcessBus, Severity: Notice},
	KindGooseSimulatedDropped:       {Category: CatProcessBus, Severity: Notice},
	KindGooseNdsCom:                 {Category: CatProcessBus, Severity: Notice},
	KindGooseUntrackedStream:        {Category: CatProcessBus, Severity: Warning, Technique: "T0814"},
	KindGooseFlood:                  {Category: CatFlood, Severity: Warning, Technique: "T0814"},

	KindSVParseError:       {Category: CatProcessBus, Severity: Notice},
	KindSVLEDecodeError:    {Category: CatProcessBus, Severity: Notice},
	KindSVSmpCntGap:        {Category: CatProcessBus, Severity: Notice},
	KindSVSmpCntDuplicate:  {Category: CatProcessBus, Severity: Alert, Technique: "T0856"},
	KindSVSmpCntRegressed:  {Category: CatProcessBus, Severity: Warning, Technique: "T0856"},
	KindSVConfRevMismatch:  {Category: CatProcessBus, Severity: Warning},
	KindSVDatasetMismatch:  {Category: CatProcessBus, Severity: Warning},
	KindSVSyncLost:         {Category: CatProcessBus, Severity: Warning},
	KindSVSourceMACChanged: {Category: CatProcessBus, Severity: Alert, Technique: "T0830", Always: true},
	KindSVSimulatedDropped: {Category: CatProcessBus, Severity: Notice},
	KindSVStreamLost:       {Category: CatProcessBus, Severity: Warning, Technique: "T0814"},
	KindSVRateAnomaly:      {Category: CatProcessBus, Severity: Warning},

	KindRSessionMalformed:         {Category: CatProcessBus, Severity: Notice},
	KindRSessionUnknownKey:        {Category: CatProcessBus, Severity: Warning},
	KindRSessionUnauthentic:       {Category: CatProcessBus, Severity: Alert, Technique: "T0856"},
	KindRSessionUnsecured:         {Category: CatProcessBus, Severity: Warning},
	KindRSessionUnsecuredAccepted: {Category: CatProcessBus, Severity: Notice},
	KindRSessionReplay:            {Category: CatProcessBus, Severity: Alert, Technique: "T0856"},
	KindRSessionNoActiveKey:       {Category: CatKeyManagement, Severity: Warning, Technique: "T0814"},

	KindUnsolResponse:           {Category: CatUnsolicited, Severity: Warning},
	KindUnsolReport:             {Category: CatUnsolicited, Severity: Notice, Technique: "T0856"},
	KindUnsolCommandTermination: {Category: CatUnsolicited, Severity: Warning},
	KindUnsolLastApplError:      {Category: CatUnsolicited, Severity: Notice},
	KindUnsolServerRequest:      {Category: CatUnsolicited, Severity: Notice},

	KindFileDirectory:   {Category: CatFile, Severity: Info, Technique: "T0846"},
	KindFileRead:        {Category: CatFile, Severity: Notice, Technique: "T0845"},
	KindFileObtain:      {Category: CatFile, Severity: Alert, Technique: "T0843", Always: true},
	KindFileDelete:      {Category: CatFile, Severity: Alert, Technique: "T0872"},
	KindFileRename:      {Category: CatFile, Severity: Warning},
	KindFileInvalidName: {Category: CatFile, Severity: Notice},
	KindFileRejected:    {Category: CatFile, Severity: Notice},
	KindFileBusy:        {Category: CatFile, Severity: Notice},

	KindGDOIRegistered:     {Category: CatKeyManagement, Severity: Info},
	KindGDOIRejected:       {Category: CatKeyManagement, Severity: Warning},
	KindGDOICookieMismatch: {Category: CatKeyManagement, Severity: Warning},
	KindGDOIPhase1Flood:    {Category: CatKeyManagement, Severity: Alert, Technique: "T0814"},
	KindGDOIPullFailed:     {Category: CatKeyManagement, Severity: Warning},
	KindGDOIRekeyFailed:    {Category: CatKeyManagement, Severity: Warning},
	KindGDOIKeyExpiring:    {Category: CatKeyManagement, Severity: Notice},

	KindFloodRequests:     {Category: CatFlood, Severity: Warning, Technique: "T0814"},
	KindFloodControls:     {Category: CatFlood, Severity: Warning, Technique: "T0806"},
	KindFloodWrites:       {Category: CatFlood, Severity: Warning, Technique: "T0806"},
	KindFloodReads:        {Category: CatFlood, Severity: Warning, Technique: "T0814"},
	KindFloodGI:           {Category: CatFlood, Severity: Warning, Technique: "T0814"},
	KindFloodDiscovery:    {Category: CatFlood, Severity: Warning, Technique: "T0846"},
	KindFloodFile:         {Category: CatFlood, Severity: Warning, Technique: "T0814"},
	KindDoSReportQueue:    {Category: CatResource, Severity: Warning, Technique: "T0815"},
	KindDoSWriteStall:     {Category: CatResource, Severity: Warning, Technique: "T0814"},
	KindDoSSlowFrame:      {Category: CatResource, Severity: Warning, Technique: "T0814"},
	KindDoSDatasetLimit:   {Category: CatResource, Severity: Notice},
	KindDoSSelectionHold:  {Category: CatResource, Severity: Warning, Technique: "T0814"},
	KindDoSRCBReservation: {Category: CatResource, Severity: Warning, Technique: "T0815"},

	KindMetaEventsDropped: {Category: CatMeta, Severity: Warning, Always: true},
	KindMetaSinkPanic:     {Category: CatMeta, Severity: Critical, Always: true},
}

// ExtensionPrefix starts every library extension event identifier.
const ExtensionPrefix = "x-go-iec61850."

func init() {
	for kind, info := range kinds {
		if info.Std62351 == "" {
			info.Std62351 = ExtensionPrefix + string(kind)
			kinds[kind] = info
		}
	}
}

// Info returns the classification of k. A kind the table does not hold —
// a bridged e2e event, or one an application reports itself — gets a
// Notice in the meta category (Warning for e2e) and an extension
// identifier.
func (kd Kind) Info() KindInfo {
	if info, ok := kinds[kd]; ok {
		return info
	}
	info := KindInfo{Category: CatMeta, Severity: Notice, Std62351: ExtensionPrefix + string(kd)}
	if strings.HasPrefix(string(kd), E2EPrefix) {
		info.Category, info.Severity = CatAssociation, Warning
	}
	return info
}

// Kinds returns every kind in the table.
func Kinds() []Kind {
	out := make([]Kind, 0, len(kinds))
	for kd := range kinds {
		out = append(out, kd)
	}
	return out
}
