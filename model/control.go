package model

import "fmt"

// CtlModel is the control model of a controllable object (the ctlModel
// configuration attribute, IEC 61850-7-2).
type CtlModel uint8

const (
	CtlStatusOnly     CtlModel = 0
	CtlDirectNormal   CtlModel = 1
	CtlSBONormal      CtlModel = 2
	CtlDirectEnhanced CtlModel = 3
	CtlSBOEnhanced    CtlModel = 4
)

func (c CtlModel) String() string {
	switch c {
	case CtlStatusOnly:
		return "status-only"
	case CtlDirectNormal:
		return "direct-with-normal-security"
	case CtlSBONormal:
		return "sbo-with-normal-security"
	case CtlDirectEnhanced:
		return "direct-with-enhanced-security"
	case CtlSBOEnhanced:
		return "sbo-with-enhanced-security"
	}
	return fmt.Sprintf("ctlModel(%d)", uint8(c))
}

// HasSelect reports whether the model requires a select step.
func (c CtlModel) HasSelect() bool { return c == CtlSBONormal || c == CtlSBOEnhanced }

// Enhanced reports whether the model uses enhanced security
// (CommandTermination).
func (c CtlModel) Enhanced() bool { return c == CtlDirectEnhanced || c == CtlSBOEnhanced }

// OrCat is the originator category (orCat).
type OrCat uint8

const (
	OrCatNotSupported     OrCat = 0
	OrCatBayControl       OrCat = 1
	OrCatStationControl   OrCat = 2
	OrCatRemoteControl    OrCat = 3
	OrCatAutomaticBay     OrCat = 4
	OrCatAutomaticStation OrCat = 5
	OrCatAutomaticRemote  OrCat = 6
	OrCatMaintenance      OrCat = 7
	OrCatProcess          OrCat = 8
)

func (o OrCat) String() string {
	names := [...]string{
		"not-supported", "bay-control", "station-control", "remote-control",
		"automatic-bay", "automatic-station", "automatic-remote",
		"maintenance", "process",
	}
	if int(o) < len(names) {
		return names[o]
	}
	return fmt.Sprintf("orCat(%d)", uint8(o))
}

// AddCause is the additional cause diagnosis returned with negative
// control responses and CommandTermination- (IEC 61850-7-2).
type AddCause uint8

const (
	AddCauseUnknown                     AddCause = 0
	AddCauseNotSupported                AddCause = 1
	AddCauseBlockedBySwitchingHierarchy AddCause = 2
	AddCauseSelectFailed                AddCause = 3
	AddCauseInvalidPosition             AddCause = 4
	AddCausePositionReached             AddCause = 5
	AddCauseParameterChangeInExecution  AddCause = 6
	AddCauseStepLimit                   AddCause = 7
	AddCauseBlockedByMode               AddCause = 8
	AddCauseBlockedByProcess            AddCause = 9
	AddCauseBlockedByInterlocking       AddCause = 10
	AddCauseBlockedBySynchrocheck       AddCause = 11
	AddCauseCommandAlreadyInExecution   AddCause = 12
	AddCauseBlockedByHealth             AddCause = 13
	AddCauseOneOfNControl               AddCause = 14
	AddCauseAbortionByCancel            AddCause = 15
	AddCauseTimeLimitOver               AddCause = 16
	AddCauseAbortionByTrip              AddCause = 17
	AddCauseObjectNotSelected           AddCause = 18
	AddCauseObjectAlreadySelected       AddCause = 19
	AddCauseNoAccessAuthority           AddCause = 20
	AddCauseEndedWithOvershoot          AddCause = 21
	AddCauseAbortionDueToDeviation      AddCause = 22
	AddCauseAbortionByCommunicationLoss AddCause = 23
	AddCauseBlockedByCommand            AddCause = 24
	// AddCauseNoneReported is the standard's "None": the peer answered
	// negatively without naming a cause. It is a value seen on the wire,
	// unlike the AddCauseNone sentinel below.
	AddCauseNoneReported AddCause = 25
	// AddCauseInconsistentParameters is the diagnosis for an operate whose
	// parameters do not match the select that reserved the object — a
	// different ctlNum above all.
	AddCauseInconsistentParameters AddCause = 26
	AddCauseLockedByOtherClient    AddCause = 27

	// AddCauseNone is not an IEC 61850 value: it is this library's "no
	// error", returned by a ControlHandler to accept a command. Every
	// value a peer can send is 0..27, so 255 cannot collide with one.
	AddCauseNone AddCause = 255
)

func (a AddCause) String() string {
	names := map[AddCause]string{
		0: "unknown", 1: "not-supported", 2: "blocked-by-switching-hierarchy",
		3: "select-failed", 4: "invalid-position", 5: "position-reached",
		6: "parameter-change-in-execution", 7: "step-limit",
		8: "blocked-by-mode", 9: "blocked-by-process",
		10: "blocked-by-interlocking", 11: "blocked-by-synchrocheck",
		12: "command-already-in-execution", 13: "blocked-by-health",
		14: "1-of-n-control", 15: "abortion-by-cancel", 16: "time-limit-over",
		17: "abortion-by-trip", 18: "object-not-selected",
		19: "object-already-selected", 20: "no-access-authority",
		21: "ended-with-overshoot", 22: "abortion-due-to-deviation",
		23: "abortion-by-communication-loss", 24: "blocked-by-command",
		25: "none-reported", 26: "inconsistent-parameters",
		27: "locked-by-other-client", 255: "none",
	}
	if s, ok := names[a]; ok {
		return s
	}
	return fmt.Sprintf("addCause(%d)", uint8(a))
}
