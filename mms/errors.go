package mms

import "fmt"

// DataAccessError codes (ISO 9506-2 DataAccessError).
type DataAccessError uint8

const (
	AccessObjectInvalidated           DataAccessError = 0
	AccessHardwareFault               DataAccessError = 1
	AccessTemporarilyUnavailable      DataAccessError = 2
	AccessObjectAccessDenied          DataAccessError = 3
	AccessObjectUndefined             DataAccessError = 4
	AccessInvalidAddress              DataAccessError = 5
	AccessTypeUnsupported             DataAccessError = 6
	AccessTypeInconsistent            DataAccessError = 7
	AccessObjectAttributeInconsistent DataAccessError = 8
	AccessObjectAccessUnsupported     DataAccessError = 9
	AccessObjectNonExistent           DataAccessError = 10
	AccessObjectValueInvalid          DataAccessError = 11
)

var accessErrorNames = map[DataAccessError]string{
	AccessObjectInvalidated:           "object-invalidated",
	AccessHardwareFault:               "hardware-fault",
	AccessTemporarilyUnavailable:      "temporarily-unavailable",
	AccessObjectAccessDenied:          "object-access-denied",
	AccessObjectUndefined:             "object-undefined",
	AccessInvalidAddress:              "invalid-address",
	AccessTypeUnsupported:             "type-unsupported",
	AccessTypeInconsistent:            "type-inconsistent",
	AccessObjectAttributeInconsistent: "object-attribute-inconsistent",
	AccessObjectAccessUnsupported:     "object-access-unsupported",
	AccessObjectNonExistent:           "object-non-existent",
	AccessObjectValueInvalid:          "object-value-invalid",
}

func (e DataAccessError) String() string {
	if s, ok := accessErrorNames[e]; ok {
		return s
	}
	return fmt.Sprintf("data-access-error(%d)", uint8(e))
}

// Error implements error so per-element failures can be returned directly.
func (e DataAccessError) Error() string { return "mms: " + e.String() }

// ServiceError is an MMS confirmed-ErrorPDU or reject surfaced to the
// caller of a confirmed service.
type ServiceError struct {
	Class    uint8 // errorClass CHOICE index (vmd-state(0) ... others(11))
	Code     uint8 // value within the class
	Rejected bool  // true when the PDU was a rejectPDU rather than an error
	Detail   string
}

var errorClassNames = [...]string{
	"vmd-state", "application-reference", "definition", "resource",
	"service", "service-preempt", "time-resolution", "access",
	"initiate", "conclude", "cancel", "file", "others",
}

func (e *ServiceError) Error() string {
	kind := "error"
	if e.Rejected {
		kind = "reject"
	}
	class := "unknown"
	if int(e.Class) < len(errorClassNames) {
		class = errorClassNames[e.Class]
	}
	if e.Detail != "" {
		return fmt.Sprintf("mms: service %s: %s(%d): %s", kind, class, e.Code, e.Detail)
	}
	return fmt.Sprintf("mms: service %s: %s(%d)", kind, class, e.Code)
}
