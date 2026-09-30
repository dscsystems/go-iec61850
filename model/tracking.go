package model

// ServiceType identifies an ACSI service in a service tracking object's
// serviceType (IEC 61850-7-2 Edition 2, the ServiceType enumeration). The
// values are the standard's, as libiec61850 numbers them too.
type ServiceType int32

const (
	ServiceUnknown                ServiceType = 0
	ServiceAssociate              ServiceType = 1
	ServiceAbort                  ServiceType = 2
	ServiceRelease                ServiceType = 3
	ServiceGetServerDirectory     ServiceType = 4
	ServiceGetLogicalDeviceDir    ServiceType = 5
	ServiceGetAllDataValues       ServiceType = 6
	ServiceGetDataValues          ServiceType = 7
	ServiceSetDataValues          ServiceType = 8
	ServiceGetDataDirectory       ServiceType = 9
	ServiceGetDataDefinition      ServiceType = 10
	ServiceGetDataSetValues       ServiceType = 11
	ServiceSetDataSetValues       ServiceType = 12
	ServiceCreateDataSet          ServiceType = 13
	ServiceDeleteDataSet          ServiceType = 14
	ServiceGetDataSetDirectory    ServiceType = 15
	ServiceSelectActiveSG         ServiceType = 16
	ServiceSelectEditSG           ServiceType = 17
	ServiceSetEditSGValue         ServiceType = 18
	ServiceConfirmEditSGValues    ServiceType = 19
	ServiceGetEditSGValue         ServiceType = 20
	ServiceGetSGCBValues          ServiceType = 21
	ServiceReport                 ServiceType = 22
	ServiceGetBRCBValues          ServiceType = 23
	ServiceSetBRCBValues          ServiceType = 24
	ServiceGetURCBValues          ServiceType = 25
	ServiceSetURCBValues          ServiceType = 26
	ServiceGetLCBValues           ServiceType = 27
	ServiceSetLCBValues           ServiceType = 28
	ServiceQueryLogByTime         ServiceType = 29
	ServiceQueryLogAfter          ServiceType = 30
	ServiceGetLogStatus           ServiceType = 31
	ServiceSendGOOSEMessage       ServiceType = 32
	ServiceGetGoCBValues          ServiceType = 33
	ServiceSetGoCBValues          ServiceType = 34
	ServiceGetGoReference         ServiceType = 35
	ServiceGetGOOSEElementNumber  ServiceType = 36
	ServiceSendMSVMessage         ServiceType = 37
	ServiceGetMSVCBValues         ServiceType = 38
	ServiceSetMSVCBValues         ServiceType = 39
	ServiceSendUSVMessage         ServiceType = 40
	ServiceGetUSVCBValues         ServiceType = 41
	ServiceSetUSVCBValues         ServiceType = 42
	ServiceSelect                 ServiceType = 43
	ServiceSelectWithValue        ServiceType = 44
	ServiceCancel                 ServiceType = 45
	ServiceOperate                ServiceType = 46
	ServiceCommandTermination     ServiceType = 47
	ServiceTimeActivatedOperate   ServiceType = 48
	ServiceGetFile                ServiceType = 49
	ServiceSetFile                ServiceType = 50
	ServiceDeleteFile             ServiceType = 51
	ServiceGetFileAttributeValues ServiceType = 52
	ServiceTimeSynchronisation    ServiceType = 53
	ServiceInternalChange         ServiceType = 54
)

// ServiceError is the outcome of a tracked service, a tracking object's
// errorCode (IEC 61850-7-2 Edition 2, the ServiceError enumeration).
type ServiceError int32

const (
	ServiceErrorNone                        ServiceError = 0
	ServiceErrorInstanceNotAvailable        ServiceError = 1
	ServiceErrorInstanceInUse               ServiceError = 2
	ServiceErrorAccessViolation             ServiceError = 3
	ServiceErrorAccessNotAllowedInState     ServiceError = 4
	ServiceErrorParameterValueInappropriate ServiceError = 5
	ServiceErrorParameterValueInconsistent  ServiceError = 6
	ServiceErrorClassNotSupported           ServiceError = 7
	ServiceErrorInstanceLockedByOtherClient ServiceError = 8
	ServiceErrorControlMustBeSelected       ServiceError = 9
	ServiceErrorTypeConflict                ServiceError = 10
	ServiceErrorFailedDueToCommConstraint   ServiceError = 11
	ServiceErrorFailedDueToServerConstraint ServiceError = 12
)
