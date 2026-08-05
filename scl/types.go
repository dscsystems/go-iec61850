// Package scl parses IEC 61850-6 SCL files (ICD, CID, SCD, IID) with the
// standard library XML decoder and instantiates the runtime object model
// of the model package.
//
// The parser covers the common subset needed to configure a server or a
// GOOSE subscriber: IEDs with access points, servers, logical devices and
// nodes, data type templates, datasets, report/GOOSE/SV/log/setting-group
// control blocks, initial values (DOI/SDI/DAI) and the Communication
// section. Substation topology, Services capabilities, KDC/certificate
// elements and private extensions are decoded loosely or ignored.
package scl

import "encoding/xml"

// SCL is the document root. Element matching is by local name, so any
// SCL namespace revision is accepted.
type SCL struct {
	XMLName           xml.Name           `xml:"SCL"`
	Version           string             `xml:"version,attr"`
	Revision          string             `xml:"revision,attr"`
	Header            Header             `xml:"Header"`
	Communication     *Communication     `xml:"Communication"`
	IEDs              []IED              `xml:"IED"`
	DataTypeTemplates *DataTypeTemplates `xml:"DataTypeTemplates"`
}

// Header identifies the configuration file.
type Header struct {
	ID       string `xml:"id,attr"`
	Version  string `xml:"version,attr"`
	Revision string `xml:"revision,attr"`
	ToolID   string `xml:"toolID,attr"`
}

// Communication describes subnetworks and the addresses of connected
// access points.
type Communication struct {
	SubNetworks []SubNetwork `xml:"SubNetwork"`
}

// SubNetwork is one communication subnetwork.
type SubNetwork struct {
	Name         string        `xml:"name,attr"`
	Type         string        `xml:"type,attr"`
	ConnectedAPs []ConnectedAP `xml:"ConnectedAP"`
}

// ConnectedAP binds an IED access point to the subnetwork and carries its
// addresses and GSE/SMV multicast parameters.
type ConnectedAP struct {
	IEDName string   `xml:"iedName,attr"`
	APName  string   `xml:"apName,attr"`
	Address *Address `xml:"Address"`
	GSEs    []GSE    `xml:"GSE"`
	SMVs    []SMV    `xml:"SMV"`
}

// Address is a list of typed address parameters.
type Address struct {
	Ps []P `xml:"P"`
}

// P is one address parameter, e.g. <P type="MAC-Address">01-0C-CD-01-00-01</P>.
type P struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

// GSE carries the multicast address and timing of one GOOSE control block.
type GSE struct {
	LDInst  string    `xml:"ldInst,attr"`
	CBName  string    `xml:"cbName,attr"`
	Address *Address  `xml:"Address"`
	MinTime *DurUnits `xml:"MinTime"`
	MaxTime *DurUnits `xml:"MaxTime"`
}

// SMV carries the multicast address of one sampled-value control block.
type SMV struct {
	LDInst  string   `xml:"ldInst,attr"`
	CBName  string   `xml:"cbName,attr"`
	Address *Address `xml:"Address"`
}

// DurUnits is a duration with unit and multiplier attributes. Values are
// interpreted as milliseconds (unit "s", multiplier "m"), the only form
// seen in practice for GSE MinTime/MaxTime.
type DurUnits struct {
	Unit       string `xml:"unit,attr"`
	Multiplier string `xml:"multiplier,attr"`
	Value      string `xml:",chardata"`
}

// IED is one physical device configuration.
type IED struct {
	Name          string        `xml:"name,attr"`
	Type          string        `xml:"type,attr"`
	Manufacturer  string        `xml:"manufacturer,attr"`
	ConfigVersion string        `xml:"configVersion,attr"`
	Services      *Services     `xml:"Services"`
	AccessPoints  []AccessPoint `xml:"AccessPoint"`
}

// AccessPoint is one communication access point of an IED.
type AccessPoint struct {
	Name     string    `xml:"name,attr"`
	Services *Services `xml:"Services"`
	Server   *Server   `xml:"Server"`
}

// Server holds the logical devices visible through an access point.
type Server struct {
	LDevices []LDevice `xml:"LDevice"`
}

// LDevice is one logical device.
type LDevice struct {
	Inst string `xml:"inst,attr"`
	LN0  *LN    `xml:"LN0"`
	LNs  []LN   `xml:"LN"`
}

// LN is a logical node instance (LN or LN0). Control blocks and Inputs
// are decoded on every LN, although they normally appear on LN0 only.
type LN struct {
	LNClass string `xml:"lnClass,attr"`
	Inst    string `xml:"inst,attr"`
	LNType  string `xml:"lnType,attr"`
	Prefix  string `xml:"prefix,attr"`

	DOIs []DOI `xml:"DOI"`

	DataSets             []DataSet             `xml:"DataSet"`
	ReportControls       []ReportControl       `xml:"ReportControl"`
	GSEControls          []GSEControl          `xml:"GSEControl"`
	SampledValueControls []SampledValueControl `xml:"SampledValueControl"`
	LogControls          []LogControl          `xml:"LogControl"`
	SettingControl       *SettingControl       `xml:"SettingControl"`
	Inputs               *Inputs               `xml:"Inputs"`
}

// DOI is an instantiated data object carrying initial values.
type DOI struct {
	Name string `xml:"name,attr"`
	DAIs []DAI  `xml:"DAI"`
	SDIs []SDI  `xml:"SDI"`
}

// SDI addresses a sub-object or a structured attribute inside a DOI.
type SDI struct {
	Name string `xml:"name,attr"`
	DAIs []DAI  `xml:"DAI"`
	SDIs []SDI  `xml:"SDI"`
}

// DAI is an instantiated data attribute with optional values.
type DAI struct {
	Name string `xml:"name,attr"`
	Vals []Val  `xml:"Val"`
}

// Val is an initial value; sGroup selects the setting group it applies to.
type Val struct {
	SGroup string `xml:"sGroup,attr"`
	Value  string `xml:",chardata"`
}

// DataSet is a dataset definition.
type DataSet struct {
	Name  string `xml:"name,attr"`
	Desc  string `xml:"desc,attr"`
	FCDAs []FCDA `xml:"FCDA"`
}

// FCDA is one dataset member reference.
type FCDA struct {
	LDInst  string `xml:"ldInst,attr"`
	Prefix  string `xml:"prefix,attr"`
	LNClass string `xml:"lnClass,attr"`
	LNInst  string `xml:"lnInst,attr"`
	DOName  string `xml:"doName,attr"`
	DAName  string `xml:"daName,attr"`
	FC      string `xml:"fc,attr"`
}

// Services declares an IED's or access point's service capabilities. Only
// the report-buffer capacity is read from it.
type Services struct {
	ConfReportControl *ConfReportControl `xml:"ConfReportControl"`
}

// ConfReportControl is the report-control capability. MaxBuf is how many
// reports a buffered control block can retain, which the server applies to
// the blocks that do not configure a depth of their own.
type ConfReportControl struct {
	Max    int `xml:"max,attr"`
	MaxBuf int `xml:"maxBuf,attr"`
}

// ReportControl configures a (buffered or unbuffered) report control block.
type ReportControl struct {
	Name      string      `xml:"name,attr"`
	Desc      string      `xml:"desc,attr"`
	RptID     string      `xml:"rptID,attr"`
	DatSet    string      `xml:"datSet,attr"`
	ConfRev   uint32      `xml:"confRev,attr"`
	Buffered  bool        `xml:"buffered,attr"`
	BufTime   uint32      `xml:"bufTime,attr"`
	IntgPd    uint32      `xml:"intgPd,attr"`
	TrgOps    *TrgOps     `xml:"TrgOps"`
	OptFields *OptFields  `xml:"OptFields"`
	RptEnab   *RptEnabled `xml:"RptEnabled"`
}

// TrgOps holds report/log trigger option flags. The gi attribute defaults
// to true in the schema, hence the string type.
type TrgOps struct {
	Dchg   bool   `xml:"dchg,attr"`
	Qchg   bool   `xml:"qchg,attr"`
	Dupd   bool   `xml:"dupd,attr"`
	Period bool   `xml:"period,attr"`
	GI     string `xml:"gi,attr"`
}

// OptFields holds report optional field flags.
type OptFields struct {
	SeqNum       bool `xml:"seqNum,attr"`
	TimeStamp    bool `xml:"timeStamp,attr"`
	DataSet      bool `xml:"dataSet,attr"`
	ReasonCode   bool `xml:"reasonCode,attr"`
	DataRef      bool `xml:"dataRef,attr"`
	EntryID      bool `xml:"entryID,attr"`
	ConfigRef    bool `xml:"configRef,attr"`
	BufOvfl      bool `xml:"bufOvfl,attr"`
	Segmentation bool `xml:"segmentation,attr"`
}

// RptEnabled limits the number of report control block instances.
type RptEnabled struct {
	Max int `xml:"max,attr"`
}

// GSEControl configures a GOOSE control block. The appID attribute is the
// GoID string, not the Ethernet APPID (which lives in Communication/GSE).
type GSEControl struct {
	Name    string `xml:"name,attr"`
	Desc    string `xml:"desc,attr"`
	AppID   string `xml:"appID,attr"`
	DatSet  string `xml:"datSet,attr"`
	ConfRev uint32 `xml:"confRev,attr"`
	Type    string `xml:"type,attr"` // "GOOSE" (default) or "GSSE"
}

// SampledValueControl configures a sampled-value control block. The
// multicast attribute defaults to true in the schema, hence the string.
type SampledValueControl struct {
	Name      string `xml:"name,attr"`
	SmvID     string `xml:"smvID,attr"`
	DatSet    string `xml:"datSet,attr"`
	ConfRev   uint32 `xml:"confRev,attr"`
	SmpRate   uint32 `xml:"smpRate,attr"`
	NofASDU   uint32 `xml:"nofASDU,attr"`
	Multicast string `xml:"multicast,attr"`
}

// LogControl configures a log control block. logEna defaults to true in
// the schema, hence the string.
type LogControl struct {
	Name    string  `xml:"name,attr"`
	DatSet  string  `xml:"datSet,attr"`
	LogName string  `xml:"logName,attr"`
	LogEna  string  `xml:"logEna,attr"`
	IntgPd  uint32  `xml:"intgPd,attr"`
	TrgOps  *TrgOps `xml:"TrgOps"`
}

// SettingControl declares the setting groups of a logical device.
type SettingControl struct {
	NumOfSGs uint8 `xml:"numOfSGs,attr"`
	ActSG    uint8 `xml:"actSG,attr"`
}

// Inputs lists the external references consumed by a logical node.
type Inputs struct {
	ExtRefs []ExtRef `xml:"ExtRef"`
}

// ExtRef binds a local input to data published by another IED. The src*
// attributes identify the publishing control block (Edition 2).
type ExtRef struct {
	IEDName     string `xml:"iedName,attr"`
	LDInst      string `xml:"ldInst,attr"`
	Prefix      string `xml:"prefix,attr"`
	LNClass     string `xml:"lnClass,attr"`
	LNInst      string `xml:"lnInst,attr"`
	DOName      string `xml:"doName,attr"`
	DAName      string `xml:"daName,attr"`
	IntAddr     string `xml:"intAddr,attr"`
	ServiceType string `xml:"serviceType,attr"`
	SrcLDInst   string `xml:"srcLDInst,attr"`
	SrcPrefix   string `xml:"srcPrefix,attr"`
	SrcLNClass  string `xml:"srcLNClass,attr"`
	SrcLNInst   string `xml:"srcLNInst,attr"`
	SrcCBName   string `xml:"srcCBName,attr"`
}

// DataTypeTemplates holds the reusable type definitions.
type DataTypeTemplates struct {
	LNodeTypes []LNodeType `xml:"LNodeType"`
	DOTypes    []DOType    `xml:"DOType"`
	DATypes    []DAType    `xml:"DAType"`
	EnumTypes  []EnumType  `xml:"EnumType"`
}

// LNodeType is a logical node type template.
type LNodeType struct {
	ID      string `xml:"id,attr"`
	LNClass string `xml:"lnClass,attr"`
	DOs     []DO   `xml:"DO"`
}

// DO declares a data object of a logical node type.
type DO struct {
	Name      string `xml:"name,attr"`
	Type      string `xml:"type,attr"`
	Transient bool   `xml:"transient,attr"`
}

// DOType is a data object type template (a CDC specialisation).
type DOType struct {
	ID   string `xml:"id,attr"`
	CDC  string `xml:"cdc,attr"`
	DAs  []DA   `xml:"DA"`
	SDOs []SDO  `xml:"SDO"`
}

// SDO declares a sub data object inside a DOType.
type SDO struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// DA declares a data attribute inside a DOType. count may be a number or
// (rarely) an enum value name; only numeric counts are honoured.
type DA struct {
	Name  string `xml:"name,attr"`
	FC    string `xml:"fc,attr"`
	BType string `xml:"bType,attr"`
	Type  string `xml:"type,attr"`
	Count string `xml:"count,attr"`
	Dchg  bool   `xml:"dchg,attr"`
	Qchg  bool   `xml:"qchg,attr"`
	Dupd  bool   `xml:"dupd,attr"`
	Vals  []Val  `xml:"Val"`
}

// DAType is a constructed attribute type template.
type DAType struct {
	ID   string `xml:"id,attr"`
	BDAs []BDA  `xml:"BDA"`
}

// BDA declares a member of a constructed attribute type.
type BDA struct {
	Name  string `xml:"name,attr"`
	BType string `xml:"bType,attr"`
	Type  string `xml:"type,attr"`
	Count string `xml:"count,attr"`
	Vals  []Val  `xml:"Val"`
}

// EnumType is an enumeration type template.
type EnumType struct {
	ID       string    `xml:"id,attr"`
	EnumVals []EnumVal `xml:"EnumVal"`
}

// EnumVal is one enumeration literal.
type EnumVal struct {
	Ord  int    `xml:"ord,attr"`
	Name string `xml:",chardata"`
}
