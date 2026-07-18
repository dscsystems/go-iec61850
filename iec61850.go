// Package iec61850 provides a pure-Go implementation of the IEC 61850
// protocol family: MMS client/server (IEC 61850-8-1), GOOSE and Sampled
// Values publish/subscribe, and SCL configuration handling.
//
// Most applications use the high-level subpackages:
//
//   - client: ACSI client for talking to IEDs (browse, read, write,
//     datasets, reporting, controls, file transfer)
//   - server: ACSI server for building IEDs, simulators and gateways
//   - goose, sv: layer-2 publish/subscribe
//   - scl: SCL (ICD/CID/SCD) parsing and model instantiation
//   - model: the IEC 61850 object model and common data types
//
// The lower layers (mms, asn1, internal/osi) are exported where useful for
// tooling but are not needed for typical use.
package iec61850
