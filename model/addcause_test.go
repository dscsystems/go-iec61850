package model

import "testing"

// The AddCause values travel on the wire in LastApplError and
// CommandTermination-, so they have to be exactly the IEC 61850-7-2
// numbering. Several of the upper ones were previously assigned by name
// rather than by number, which mistranslated a real IED's diagnosis.
func TestAddCauseNumbering(t *testing.T) {
	for _, tc := range []struct {
		cause AddCause
		n     uint8
		name  string
	}{
		{AddCauseUnknown, 0, "unknown"},
		{AddCauseNotSupported, 1, "not-supported"},
		{AddCauseBlockedBySwitchingHierarchy, 2, "blocked-by-switching-hierarchy"},
		{AddCauseSelectFailed, 3, "select-failed"},
		{AddCauseInvalidPosition, 4, "invalid-position"},
		{AddCausePositionReached, 5, "position-reached"},
		{AddCauseParameterChangeInExecution, 6, "parameter-change-in-execution"},
		{AddCauseStepLimit, 7, "step-limit"},
		{AddCauseBlockedByMode, 8, "blocked-by-mode"},
		{AddCauseBlockedByProcess, 9, "blocked-by-process"},
		{AddCauseBlockedByInterlocking, 10, "blocked-by-interlocking"},
		{AddCauseBlockedBySynchrocheck, 11, "blocked-by-synchrocheck"},
		{AddCauseCommandAlreadyInExecution, 12, "command-already-in-execution"},
		{AddCauseBlockedByHealth, 13, "blocked-by-health"},
		{AddCauseOneOfNControl, 14, "1-of-n-control"},
		{AddCauseAbortionByCancel, 15, "abortion-by-cancel"},
		{AddCauseTimeLimitOver, 16, "time-limit-over"},
		{AddCauseAbortionByTrip, 17, "abortion-by-trip"},
		{AddCauseObjectNotSelected, 18, "object-not-selected"},
		{AddCauseObjectAlreadySelected, 19, "object-already-selected"},
		{AddCauseNoAccessAuthority, 20, "no-access-authority"},
		{AddCauseEndedWithOvershoot, 21, "ended-with-overshoot"},
		{AddCauseAbortionDueToDeviation, 22, "abortion-due-to-deviation"},
		{AddCauseAbortionByCommunicationLoss, 23, "abortion-by-communication-loss"},
		{AddCauseBlockedByCommand, 24, "blocked-by-command"},
		{AddCauseNoneReported, 25, "none-reported"},
		{AddCauseInconsistentParameters, 26, "inconsistent-parameters"},
		{AddCauseLockedByOtherClient, 27, "locked-by-other-client"},
	} {
		if uint8(tc.cause) != tc.n {
			t.Errorf("%s = %d, want %d", tc.name, uint8(tc.cause), tc.n)
		}
		if got := tc.cause.String(); got != tc.name {
			t.Errorf("AddCause(%d).String() = %q, want %q", tc.n, got, tc.name)
		}
	}
}

// The success sentinel is not an IEC 61850 value and must stay clear of
// every value a peer can send.
func TestAddCauseNoneIsOutsideTheWireRange(t *testing.T) {
	if AddCauseNone <= AddCauseLockedByOtherClient {
		t.Fatalf("AddCauseNone = %d collides with the wire values", uint8(AddCauseNone))
	}
	if got := AddCauseNone.String(); got != "none" {
		t.Errorf("AddCauseNone.String() = %q", got)
	}
	// And it is distinct from the standard's "None", which is a real
	// diagnosis a server can report.
	if AddCauseNone == AddCauseNoneReported {
		t.Error("the sentinel and the reported none are the same value")
	}
}

func TestAddCauseUnknownValue(t *testing.T) {
	if got := AddCause(200).String(); got != "addCause(200)" {
		t.Errorf("String() = %q", got)
	}
}
