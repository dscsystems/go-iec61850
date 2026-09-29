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
// See parse.go for the entry points and the package contract, and
// edition.go for the SCL editions recognised.
package scl

// Substation is the substation section of a system configuration. It is
// decoded so that a document round-trips and so the audit can distinguish a
// recognised-but-unused element from an unknown one; it does not contribute
// to the model of an IED.
type Substation struct {
	Name       string       `xml:"name,attr"`
	Desc       string       `xml:"desc,attr"`
	VoltageLvl []VoltageLvl `xml:"VoltageLevel"`
	Functions  []Function   `xml:"Function"`
	Conducting []Conducting `xml:"ConductingEquipment"`
}

// VoltageLvl is a voltage level of a substation.
type VoltageLvl struct {
	Name string `xml:"name,attr"`
	Desc string `xml:"desc,attr"`
}

// Function is a function assigned to a voltage level or bay.
type Function struct {
	Name string `xml:"name,attr"`
	Desc string `xml:"desc,attr"`
}

// Conducting is a piece of conducting equipment. Its concrete type
// (PowerTransformer, Bay, ...) is vendor- and edition-specific, so only the
// identifying attributes are decoded.
type Conducting struct {
	Name  string `xml:"name,attr"`
	Desc  string `xml:"desc,attr"`
	Desc2 string `xml:"desc2,attr"`
}

// Line is a transmission or distribution line of a system description.
type Line struct {
	Name string `xml:"name,attr"`
	Desc string `xml:"desc,attr"`
}

// Process is a process of a system description, used by application areas
// other than substations.
type Process struct {
	Name string `xml:"name,attr"`
	Desc string `xml:"desc,attr"`
}

// Header identifies the configuration file.
type Header struct {
	ID            string   `xml:"id,attr"`
	Version       string   `xml:"version,attr"`
	Revision      string   `xml:"revision,attr"`
	ToolID        string   `xml:"toolID,attr"`
	NameStructure string   `xml:"nameStructure,attr"`
	Source        string   `xml:"source,attr"`
	SentBy        string   `xml:"sentBy,attr"`
	Text          string   `xml:"Text"`
	History       *History `xml:"History"`
}

// History is the revision history of the file (IEC 61850-6, Ed 2.1).
type History struct {
	Hitem []Hitem `xml:"Hitem"`
}

// Hitem is one revision history entry.
type Hitem struct {
	Version  string `xml:"version,attr"`
	Revision string `xml:"revision,attr"`
	When     string `xml:"when,attr"`
	Who      string `xml:"who,attr"`
	What     string `xml:"what,attr"`
	Why      string `xml:"why,attr"`
}

// Communication describes subnetworks and the addresses of connected
// access points.
type Communication struct {
	SubNetworks []SubNetwork `xml:"SubNetwork"`
}

// SubNetwork is one communication subnetwork.
type SubNetwork struct {
	Name         string        `xml:"name,attr"`
	Desc         string        `xml:"desc,attr"`
	Type         string        `xml:"type,attr"`
	BitRate      *DurUnits     `xml:"BitRate"`
	ConnectedAPs []ConnectedAP `xml:"ConnectedAP"`
}

// ConnectedAP binds an IED access point to the subnetwork and carries its
// addresses and GSE/SMV multicast parameters. RedProt is the redundancy
// protocol (none, hsr, prp, rstp) and PhysConn lists the protocol
// connections of the access point, including IEC 60870-5-104/101.
type ConnectedAP struct {
	IEDName  string     `xml:"iedName,attr"`
	APName   string     `xml:"apName,attr"`
	Desc     string     `xml:"desc,attr"`
	RedProt  string     `xml:"redProt,attr"`
	Address  *Address   `xml:"Address"`
	GSEs     []GSE      `xml:"GSE"`
	SMVs     []SMV      `xml:"SMV"`
	PhysConn []PhysConn `xml:"PhysConn"`
}

// PhysConn is one physical protocol connection of an access point.
type PhysConn struct {
	Type    string   `xml:"type,attr"`
	Address *Address `xml:"Address"`
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
	Desc    string    `xml:"desc,attr"`
	Address *Address  `xml:"Address"`
	MinTime *DurUnits `xml:"MinTime"`
	MaxTime *DurUnits `xml:"MaxTime"`
}

// SMV carries the multicast address of one sampled-value control block.
// LANRedundancy names a redundancy group, the Ed 2 way of sending the same
// stream on two networks (IEC 61850-6:2009+AMD2).
type SMV struct {
	LDInst        string          `xml:"ldInst,attr"`
	CBName        string          `xml:"cbName,attr"`
	Desc          string          `xml:"desc,attr"`
	Address       *Address        `xml:"Address"`
	LANRedundancy []LANRedundancy `xml:"LANRedundancy"`
}

// LANRedundancy binds a sampled-value control block to a redundancy group.
type LANRedundancy struct {
	LANGrpInst  string    `xml:"lanGrpInst,attr"`
	ShmGrpInst  string    `xml:"shmGrpInst,attr"`
	RedProt     string    `xml:"redProt,attr"`
	Sequencing  string    `xml:"sequencing,attr"`
	TimeQuality string    `xml:"timeQuality,attr"`
	Direction   string    `xml:"direction,attr"`
	AnyMax      *DurUnits `xml:"AnyMax"`
	SuperseqMax *DurUnits `xml:"SuperSeqMax"`
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
	Name          string `xml:"name,attr"`
	Type          string `xml:"type,attr"`
	Manufacturer  string `xml:"manufacturer,attr"`
	ConfigVersion string `xml:"configVersion,attr"`
	// OriginalSclVersion/Revision/Release record the SCL the IED was
	// originally configured from, which differs from the document's own
	// version when a file has been upgraded (IEC 61850-6, Ed 2.1).
	OriginalSclVersion  string `xml:"originalSclVersion,attr"`
	OriginalSclRevision string `xml:"originalSclRevision,attr"`
	OriginalSclRelease  string `xml:"originalSclRelease,attr"`
	// EngRight, Owner and EngRevision are the Ed 2.1 file-ownership and
	// engineering-rights attributes.
	EngRight     string        `xml:"engRight,attr"`
	Owner        string        `xml:"owner,attr"`
	EngRevision  string        `xml:"engRevision,attr"`
	Services     *Services     `xml:"Services"`
	AccessPoints []AccessPoint `xml:"AccessPoint"`
	// KDC lists the key distribution clients of the IED.
	KDC []KDC `xml:"KDC"`
}

// KDC is a key distribution client.
type KDC struct {
	IEDName string `xml:"iedName,attr"`
	APName  string `xml:"apName,attr"`
	LDInst  string `xml:"ldInst,attr"`
	IEDType string `xml:"iedType,attr"`
}

// AccessPoint is one communication access point of an IED.
type AccessPoint struct {
	Name     string    `xml:"name,attr"`
	Router   bool      `xml:"router,attr"`
	Clock    bool      `xml:"clock,attr"`
	KDC      bool      `xml:"kdc,attr"`
	Services *Services `xml:"Services"`
	Server   *Server   `xml:"Server"`
	// ServerAt names the peer access point this one pre-establishes
	// associations with (IEC 61850-6, Ed 2.1).
	ServerAt      []ServerAt `xml:"ServerAt"`
	GOOSESecurity []Security `xml:"GOOSESecurity"`
	SMVSecurity   []Security `xml:"SMVSecurity"`
}

// ServerAt is a pre-established association.
type ServerAt struct {
	IEDName string `xml:"iedName,attr"`
	APName  string `xml:"apName,attr"`
	LDInst  string `xml:"ldInst,attr"`
}

// Security is a security participant entry of an access point.
type Security struct {
	IEDName      string `xml:"iedName,attr"`
	APName       string `xml:"apName,attr"`
	LDInst       string `xml:"ldInst,attr"`
	Subject      string `xml:"Subject,attr"`
	IssuerName   string `xml:"IssuerName,attr"`
	SerialNumber string `xml:"serialNumber,attr"`
	XferNumber   int    `xml:"xferNumber,attr"`
}

// Server holds the logical devices visible through an access point.
// Authentication is the authentication level required of a client
// (IEC 61850-6, Ed 2.1); Association lists the associations the server
// pre-establishes.
type Server struct {
	Timeout        int           `xml:"timeout,attr"`
	Authentication *AuthKind     `xml:"Authentication"`
	Association    []Association `xml:"Association"`
	LDevices       []LDevice     `xml:"LDevice"`
}

// AuthKind is the authentication level of an access point: none, password,
// weak, strong or certificate.
type AuthKind string

// Association is one pre-established association.
type Association struct {
	IEDName       string `xml:"iedName,attr"`
	LDInst        string `xml:"ldInst,attr"`
	Prefix        string `xml:"prefix,attr"`
	LNClass       string `xml:"lnClass,attr"`
	LNInst        string `xml:"lnInst,attr"`
	Kind          int    `xml:"kind,attr"`
	AssociationID int    `xml:"associationID,attr"`
}

// LDevice is one logical device. LDName is the Ed 2.1 name of the device,
// which may differ from the MMS domain name built from Inst.
type LDevice struct {
	Inst   string `xml:"inst,attr"`
	LdName string `xml:"ldName,attr"`
	LN0    *LN    `xml:"LN0"`
	LNs    []LN   `xml:"LN"`
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
	// Log names the log capability of a logical node (IEC 61850-8-1).
	Log []LNLog `xml:"Log"`
}

// LNLog is a log capability declared on a logical node.
type LNLog struct {
	Name string `xml:"name,attr"`
}

// DOI is an instantiated data object carrying initial values. Ix is the
// instance index of the data object, used when a DO is an array.
type DOI struct {
	Name string `xml:"name,attr"`
	Ix   string `xml:"ix,attr"`
	DAIs []DAI  `xml:"DAI"`
	SDIs []SDI  `xml:"SDI"`
}

// SDI addresses a sub-object or a structured attribute inside a DOI.
type SDI struct {
	Name  string `xml:"name,attr"`
	Ix    string `xml:"ix,attr"`
	SAddr string `xml:"sAddr,attr"`
	DAIs  []DAI  `xml:"DAI"`
	SDIs  []SDI  `xml:"SDI"`
}

// DAI is an instantiated data attribute with optional values. SAddr is the
// sub-address selecting an element of an array or a member of a structure,
// so a DAI may target part of an attribute rather than the whole of it.
type DAI struct {
	Name      string `xml:"name,attr"`
	Ix        string `xml:"ix,attr"`
	SAddr     string `xml:"sAddr,attr"`
	ValKind   string `xml:"valKind,attr"`
	ValImport string `xml:"valImport,attr"`
	Vals      []Val  `xml:"Val"`
}

// Val is an initial value; sGroup selects the setting group it applies to.
// A Val without sGroup applies to the active setting group. ValKind, when
// present, states how the value is to be interpreted: Conf marks a
// parameter-set reference and Inconsistent a value that violates the
// configured one.
type Val struct {
	SGroup  string `xml:"sGroup,attr"`
	ValKind string `xml:"valKind,attr"`
	Value   string `xml:",chardata"`
}

// DataSet is a dataset definition.
type DataSet struct {
	Name  string `xml:"name,attr"`
	Desc  string `xml:"desc,attr"`
	FCDAs []FCDA `xml:"FCDA"`
}

// FCDA is one dataset member reference. DOName and DAName may carry array
// index notation, e.g. doName="AnIn3" daName="phsA(2).mag.f", and Ix is the
// alternative Ed 2 way of expressing the same thing.
type FCDA struct {
	LDInst  string `xml:"ldInst,attr"`
	Prefix  string `xml:"prefix,attr"`
	LNClass string `xml:"lnClass,attr"`
	LNInst  string `xml:"lnInst,attr"`
	DOName  string `xml:"doName,attr"`
	DAName  string `xml:"daName,attr"`
	FC      string `xml:"fc,attr"`
	Ix      string `xml:"ix,attr"`
	// Desc and ApRef are the Ed 2 description and cross-access-point
	// reference of the member.
	Desc  string `xml:"desc,attr"`
	ApRef string `xml:"apRef,attr"`
}

// Services declares an IED's or access point's service capabilities.
// The elements are decoded for coverage and for the report-buffer capacity,
// which the server applies to blocks that do not configure a depth of their
// own. Capabilities that change the model are honoured; the rest are
// available to a caller that wants to inspect them.
type Services struct {
	// NameLength is the maximum length of the data names the IED supports
	// (32, 64 or 65 per IEC 61850-6). Empty when the document omits it.
	NameLength string `xml:"nameLength,attr"`

	DynAssociation        *Empty             `xml:"DynAssociation"`
	SettingGroups         *SettingGroups     `xml:"SettingGroups"`
	GetDirectory          *GetDirectory      `xml:"GetDirectory"`
	ReadWrite             *ReadWrite         `xml:"ReadWrite"`
	TimerActivatedControl *TimerActivated    `xml:"TimerActivatedControl"`
	GetCBValues           *GetCBValues       `xml:"GetCBValues"`
	DataSetDirectory      *Empty             `xml:"DataSetDirectory"`
	DataObjectDirectory   *Empty             `xml:"DataObjectDirectory"`
	DataObjectDefinition  *Empty             `xml:"GetDataObjectDefinition"`
	GetDataSetValue       *Empty             `xml:"GetDataSetValue"`
	SetDataSetValue       *Empty             `xml:"SetDataSetValue"`
	SupSubscription       *SupSubscription   `xml:"SupSubscription"`
	ConfSigRef            *Empty             `xml:"ConfSigRef"`
	RedProt               *RedProt           `xml:"RedProt"`
	TimeSyncProt          *TimeSyncProt      `xml:"TimeSyncProt"`
	CommProt              *CommProt          `xml:"CommProt"`
	ValueHandling         *ValueHandling     `xml:"ValueHandling"`
	FileHandling          *FileHandling      `xml:"FileHandling"`
	ConfLNs               *Empty             `xml:"ConfLNs"`
	ConfDataSet           *ConfDataSet       `xml:"ConfDataSet"`
	ConfReportControl     *ConfReportControl `xml:"ConfReportControl"`
	ReportSettings        *Empty             `xml:"ReportSettings"`
	ConfLogControl        *ConfLogControl    `xml:"ConfLogControl"`
	LogSettings           *Empty             `xml:"LogSettings"`
	GSESettings           *Empty             `xml:"GSESettings"`
	GOOSE                 *GOOSE             `xml:"GOOSE"`
	GSSE                  *GSSE              `xml:"GSSE"`
	SMVSettings           *Empty             `xml:"SMVSettings"`
	SMVsc                 *SMVsc             `xml:"SMVsc"`
	ClientServices        *ClientServices    `xml:"ClientServices"`
	ConfSG                *Empty             `xml:"ConfSG"`
	// GSEDir is the Ed 2.1 GOOSE-directory capability.
	GSEDir *Empty `xml:"GSEDir"`
}

// Empty is a capability element with no attributes, present or absent.
type Empty struct{}

// DynAssociation is pre-established dynamic associations.
type DynAssociation struct {
	Max    int `xml:"max,attr"`
	MaxEEA int `xml:"maxEEA,attr"`
}

// SettingGroups is the setting-group editing capability.
type SettingGroups struct {
	SGEdit *SGEdit `xml:"SGEdit"`
	ConfSG *ConfSG `xml:"ConfSG"`
}

// SGEdit is the number of setting groups that may be edited.
type SGEdit struct {
	Max int `xml:"max,attr"`
}

// ConfSG is the setting-group configuration capability.
type ConfSG struct {
	Max int `xml:"max,attr"`
}

// GetDirectory is the directory service capability.
type GetDirectory struct {
	GetMaxAttributes int `xml:"getMaxAttributes,attr"`
}

// ReadWrite is the read/write capability.
type ReadWrite struct {
	Max           int `xml:"max,attr"`
	MaxAttributes int `xml:"maxAttributes,attr"`
}

// TimerActivated is the timer-activated control capability.
type TimerActivated struct {
	Max int `xml:"max,attr"`
}

// GetCBValues is the get-control-block-values capability.
type GetCBValues struct {
	Max int `xml:"max,attr"`
}

// SupSubscription is the subscription supervision capability. MaxGo and
// MaxSv are how many GOOSE and SV subscriptions the IED supervises.
type SupSubscription struct {
	MaxGo      int `xml:"maxGo,attr"`
	MaxSv      int `xml:"maxSv,attr"`
	MaxSvGOOSE int `xml:"maxSvGOOSE,attr"`
}

// RedProt is the redundancy protocol in use on the subnetwork.
type RedProt struct {
	Lang Language `xml:"Language,attr"`
}

// Language is the encoding of a redundant-protocol attribute.
type Language string

// TimeSyncProt is the time-synchronisation protocol.
type TimeSyncProt struct {
	Max int `xml:"max,attr"`
}

// CommProt is the communication protocol capability.
type CommProt struct {
	Max int `xml:"max,attr"`
}

// ValueHandling is the value-handling capability.
type ValueHandling struct {
	Max int `xml:"max,attr"`
}

// FileHandling is the file-handling capability.
type FileHandling struct {
	Max int `xml:"max,attr"`
}

// ConfDataSet is the dataset capability: how many datasets the IED
// supports and how many members each may have.
type ConfDataSet struct {
	Max           int  `xml:"max,attr"`
	MaxAttributes int  `xml:"maxAttributes,attr"`
	Modify        bool `xml:"modify,attr"`
}

// ConfLogControl is the log control block capability.
type ConfLogControl struct {
	Max    int `xml:"max,attr"`
	MaxBuf int `xml:"maxBuf,attr"`
}

// GOOSE is the GOOSE capability. RGGOOSE reports support for routable
// GOOSE (R-GOOSE, IEC 61850-8-1 / 90-5).
type GOOSE struct {
	Max       int  `xml:"max,attr"`
	FixedOffs bool `xml:"fixedOffs,attr"`
	RGGOOSE   bool `xml:"rGOOSE,attr"`
}

// GSSE is the legacy GSSE capability.
type GSSE struct {
	Max int `xml:"max,attr"`
}

// SMVsc is the sampled-value capability, multicast and unicast.
type SMVsc struct {
	Max      int    `xml:"max,attr"`
	Delivery string `xml:"delivery,attr"`
}

// ClientServices is the client-side capability, used by a server to
// configure a client role. RGOOSE and RSV report R-GOOSE and R-SV.
type ClientServices struct {
	MaxAttributes  int  `xml:"maxAttributes,attr"`
	MaxReports     int  `xml:"maxReports,attr"`
	MaxGOOSE       int  `xml:"maxGOOSE,attr"`
	MaxSMV         int  `xml:"maxSMV,attr"`
	RGOOSE         bool `xml:"rGOOSE,attr"`
	RSV            bool `xml:"rSV,attr"`
	SupportsLdName bool `xml:"supportsLdName,attr"`
}

// ConfReportControl is the report-control capability. MaxBuf is how many
// reports a buffered control block can retain, which the server applies to
// the blocks that do not configure a depth of their own. BufMode and
// BufConf state whether a block may be buffered (BufBuffered), must be
// (BufUnbuffered) or may be either (BufBoth); the string type keeps
// absence distinguishable from a value.
type ConfReportControl struct {
	Max     int    `xml:"max,attr"`
	MaxBuf  int    `xml:"maxBuf,attr"`
	BufMode string `xml:"bufMode,attr"`
	BufConf string `xml:"bufConf,attr"`
}

// Buffering modes of ConfReportControl@bufMode.
const (
	BufUnbuffered = "unbuffered"
	BufBuffered   = "buffered"
	BufBoth       = "both"
)

// ReportControl configures a (buffered or unbuffered) report control block.
// DBPrefix is the Ed 2 database prefix of the dataset, which is not always
// the name of the enclosing logical device. BufDepth is the Ed 1 per-block
// buffer depth, superseded by Services/ConfReportControl@maxBuf in Ed 2.
type ReportControl struct {
	Name      string      `xml:"name,attr"`
	Desc      string      `xml:"desc,attr"`
	RptID     string      `xml:"rptID,attr"`
	DatSet    string      `xml:"datSet,attr"`
	DBPrefix  string      `xml:"dbprefix,attr"`
	ConfRev   uint32      `xml:"confRev,attr"`
	Buffered  bool        `xml:"buffered,attr"`
	BufTime   uint32      `xml:"bufTime,attr"`
	IntgPd    uint32      `xml:"intgPd,attr"`
	BufDepth  int         `xml:"bufDepth,attr"`
	TrgOps    *TrgOps     `xml:"TrgOps"`
	OptFields *OptFields  `xml:"OptFields"`
	RptEnab   *RptEnabled `xml:"RptEnabled"`
	// Indexed is the xs:boolean indexed attribute; absent means true.
	Indexed string `xml:"indexed,attr"`
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

// OptFields holds report optional field flags. Each is a string because
// bufOvfl defaults to true in the schema, so absence must be distinguished
// from false; the others tolerate either form.
type OptFields struct {
	SeqNum       string `xml:"seqNum,attr"`
	TimeStamp    string `xml:"timeStamp,attr"`
	DataSet      string `xml:"dataSet,attr"`
	ReasonCode   string `xml:"reasonCode,attr"`
	DataRef      string `xml:"dataRef,attr"`
	EntryID      string `xml:"entryID,attr"`
	ConfigRef    string `xml:"configRef,attr"`
	BufOvfl      string `xml:"bufOvfl,attr"`
	Segmentation string `xml:"segmentation,attr"`
}

// RptEnabled limits the number of report control block instances and lists
// the client logical nodes the block is reserved for.
type RptEnabled struct {
	Max      int        `xml:"max,attr"`
	ClientLN []ClientLN `xml:"ClientLN"`
}

// ClientLN reserves a report control block instance for one client
// logical node. APName, when present, names the client's access point, so a
// block may be reserved for a remote IED. IEDName/InstAddr are the Ed 2.1
// additions that identify a client on another IED.
type ClientLN struct {
	IEDName  string `xml:"iedName,attr"`
	APName   string `xml:"apName,attr"`
	APRef    string `xml:"apRef,attr"`
	LDInst   string `xml:"ldInst,attr"`
	Prefix   string `xml:"prefix,attr"`
	LNClass  string `xml:"lnClass,attr"`
	LNInst   string `xml:"lnInst,attr"`
	InstAddr string `xml:"instAddr,attr"`
}

// GSEControl configures a GOOSE control block. The appID attribute is the
// GoID string, not the Ethernet APPID (which lives in Communication/GSE).
// Type is "GOOSE" (the default) or the legacy "GSSE"; Protocol names the
// transmission profile, "R-GOOSE" for routable GOOSE (IEC 61850-8-1 and
// IEC 61850-90-5). SecurityEnable requests IEC 62351-6 protection.
type GSEControl struct {
	Name     string `xml:"name,attr"`
	Desc     string `xml:"desc,attr"`
	AppID    string `xml:"appID,attr"`
	DatSet   string `xml:"datSet,attr"`
	DBPrefix string `xml:"dbprefix,attr"`
	ConfRev  uint32 `xml:"confRev,attr"`
	Type     string `xml:"type,attr"` // "GOOSE" (default) or "GSSE"
	// FixedOffs selects the fixed-offset encoding of IEC 61850-8-1, in
	// which every dataset member has a fixed position and length in the
	// frame. It is a flag on the control block, not a time.
	FixedOffs      bool       `xml:"fixedOffs,attr"`
	SecurityEnable string     `xml:"securityEnable,attr"`
	Protocol       *Protocol  `xml:"Protocol"`
	IEDName        []ClientLN `xml:"IEDName"`
}

// SampledValueControl configures a sampled-value control block. The
// multicast attribute defaults to true in the schema, hence the string.
// SmpMod is the sample mode, "SmpPerPeriod" (the default), "SmpPerSec" or
// "SecPerSmp". Protocol names the transmission profile, "R-SV" for routable
// sampled values. SmvOpts selects which optional ASDU fields are present;
// see SVOpts.
type SampledValueControl struct {
	Name           string     `xml:"name,attr"`
	Desc           string     `xml:"desc,attr"`
	SmvID          string     `xml:"smvID,attr"`
	DatSet         string     `xml:"datSet,attr"`
	DBPrefix       string     `xml:"dbprefix,attr"`
	ConfRev        uint32     `xml:"confRev,attr"`
	SmpRate        uint32     `xml:"smpRate,attr"`
	NofASDU        uint32     `xml:"nofASDU,attr"`
	Multicast      string     `xml:"multicast,attr"`
	SmpMod         string     `xml:"smpMod,attr"`
	SvType         string     `xml:"svType,attr"`
	SecurityEnable string     `xml:"securityEnable,attr"`
	SmvOpts        *SmvOpts   `xml:"SmvOpts"`
	Protocol       *Protocol  `xml:"Protocol"`
	IEDName        []ClientLN `xml:"IEDName"`
}

// Protocol names the transmission profile of a GOOSE or SV control block,
// with mustUnderstand stating whether the IED must reject a peer that does
// not implement it.
type Protocol struct {
	Value          string `xml:",chardata"`
	MustUnderstand bool   `xml:"mustUnderstand,attr"`
}

// SmvOpts selects the optional fields of the sampled-value ASDU. Each
// attribute is a string because the schema defaults them all to false, so
// absence must be distinguished from an explicit false.
type SmvOpts struct {
	RefreshTime        string `xml:"refreshTime,attr"`
	SampleSynchronized string `xml:"sampleSynchronized,attr"`
	SampleRate         string `xml:"sampleRate,attr"`
	DataSet            string `xml:"dataSet,attr"`
	Security           string `xml:"security,attr"`
	Timestamp          string `xml:"timestamp,attr"`
	SynchSourceId      string `xml:"synchSourceId,attr"`
}

// SmpMod is the sample mode of a sampled-value control block: the rate is
// samples per measurement period, per second, or seconds per sample.
type SmpMod string

const (
	SmpPerPeriod SmpMod = "SmpPerPeriod"
	SmpPerSec    SmpMod = "SmpPerSec"
	SecPerSmp    SmpMod = "SecPerSmp"
)

// LogControl configures a log control block. logEna defaults to true and
// reasonCode to true in the schema, hence the strings. The ln* attributes
// are the Ed 2 addition that lets a log control name its own logical node
// instead of living on LN0.
type LogControl struct {
	Name       string  `xml:"name,attr"`
	Desc       string  `xml:"desc,attr"`
	DatSet     string  `xml:"datSet,attr"`
	DBPrefix   string  `xml:"dbprefix,attr"`
	LogName    string  `xml:"logName,attr"`
	LogEna     string  `xml:"logEna,attr"`
	ReasonCode string  `xml:"reasonCode,attr"`
	BufTime    uint32  `xml:"bufTime,attr"`
	IntgPd     uint32  `xml:"intgPd,attr"`
	LDInst     string  `xml:"ldInst,attr"`
	Prefix     string  `xml:"prefix,attr"`
	LNClass    string  `xml:"lnClass,attr"`
	LNInst     string  `xml:"lnInst,attr"`
	TrgOps     *TrgOps `xml:"TrgOps"`
}

// SettingControl declares the setting groups of a logical device. ResvTms
// is how long a reservation lasts (IEC 61850-8-1, Ed 2.1).
type SettingControl struct {
	NumOfSGs int `xml:"numOfSGs,attr"`
	ActSG    int `xml:"actSG,attr"`
	ResvTms  int `xml:"resvTms,attr"`
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
	Desc        string `xml:"desc,attr"`
	ServiceType string `xml:"serviceType,attr"`
	SrcLDInst   string `xml:"srcLdInst,attr"`
	SrcPrefix   string `xml:"srcPrefix,attr"`
	SrcLNClass  string `xml:"srcLNClass,attr"`
	SrcLNInst   string `xml:"srcLNInst,attr"`
	SrcCBName   string `xml:"srcCBName,attr"`
}

// DataTypeTemplates holds the reusable type definitions. IEDType is the Ed
// 2 scoping attribute that restricts a template to one IED type.
type DataTypeTemplates struct {
	LNodeTypes []LNodeType `xml:"LNodeType"`
	DOTypes    []DOType    `xml:"DOType"`
	DATypes    []DAType    `xml:"DAType"`
	EnumTypes  []EnumType  `xml:"EnumType"`
}

// LNodeType is a logical node type template. Its identity is the pair
// (ID, LNClass), so two nodes of different classes may share an id.
type LNodeType struct {
	ID      string `xml:"id,attr"`
	LNClass string `xml:"lnClass,attr"`
	IEDType string `xml:"iedType,attr"`
	Desc    string `xml:"desc,attr"`
	DOs     []DO   `xml:"DO"`
}

// DO declares a data object of a logical node type. Transient marks an
// object whose value is not retained across a restart.
type DO struct {
	Name      string `xml:"name,attr"`
	Type      string `xml:"type,attr"`
	Desc      string `xml:"desc,attr"`
	Transient bool   `xml:"transient,attr"`
}

// DOType is a data object type template (a CDC specialisation).
type DOType struct {
	ID      string `xml:"id,attr"`
	CDC     string `xml:"cdc,attr"`
	IEDType string `xml:"iedType,attr"`
	DAs     []DA   `xml:"DA"`
	SDOs    []SDO  `xml:"SDO"`
}

// SDO declares a sub data object inside a DOType. Count makes the
// sub-object an array of that many instances.
type SDO struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Desc  string `xml:"desc,attr"`
	Count string `xml:"count,attr"`
}

// DA declares a data attribute inside a DOType. Count may be a number or
// (rarely) an enum value name; only numeric counts are honoured. SAddr is
// the sub-address within the attribute and ValKind/ValImport describe how
// its value is obtained (IEC 61850-6, Ed 2.1).
type DA struct {
	Name      string `xml:"name,attr"`
	FC        string `xml:"fc,attr"`
	BType     string `xml:"bType,attr"`
	Type      string `xml:"type,attr"`
	Count     string `xml:"count,attr"`
	Dchg      bool   `xml:"dchg,attr"`
	Qchg      bool   `xml:"qchg,attr"`
	Dupd      bool   `xml:"dupd,attr"`
	Desc      string `xml:"desc,attr"`
	SAddr     string `xml:"sAddr,attr"`
	ValKind   string `xml:"valKind,attr"`
	ValImport string `xml:"valImport,attr"`
	Vals      []Val  `xml:"Val"`
}

// DAType is a constructed attribute type template.
type DAType struct {
	ID      string `xml:"id,attr"`
	IEDType string `xml:"iedType,attr"`
	BDAs    []BDA  `xml:"BDA"`
}

// BDA declares a member of a constructed attribute type. It inherits the
// functional constraint and the trigger options of the DA that owns it, so
// its own trigger attributes are additional to those.
type BDA struct {
	Name      string `xml:"name,attr"`
	BType     string `xml:"bType,attr"`
	Type      string `xml:"type,attr"`
	Count     string `xml:"count,attr"`
	Dchg      bool   `xml:"dchg,attr"`
	Qchg      bool   `xml:"qchg,attr"`
	Dupd      bool   `xml:"dupd,attr"`
	Desc      string `xml:"desc,attr"`
	SAddr     string `xml:"sAddr,attr"`
	ValKind   string `xml:"valKind,attr"`
	ValImport string `xml:"valImport,attr"`
	Vals      []Val  `xml:"Val"`
}

// EnumType is an enumeration type template.
type EnumType struct {
	ID       string    `xml:"id,attr"`
	EnumVals []EnumVal `xml:"EnumVal"`
}

// EnumVal is one enumeration literal.
type EnumVal struct {
	Ord  int    `xml:"ord,attr"`
	Desc string `xml:"desc,attr"`
	Name string `xml:",chardata"`
}
