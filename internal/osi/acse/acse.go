// Package acse implements the subset of ISO 8650 / X.227 ACSE used by
// MMS: the AARQ/AARE association-control APDUs that carry the MMS
// Initiate request/response as user information, plus the RLRQ/RLRE
// release APDUs. Optional ACSE password authentication is supported.
package acse

import (
	"fmt"

	"github.com/dscsystems/go-iec61850/asn1"
)

// APDU tags (application class).
var (
	tagAARQ = asn1.ApplicationConstructed(0) // 0x60
	tagAARE = asn1.ApplicationConstructed(1) // 0x61
	tagRLRQ = asn1.ApplicationConstructed(2) // 0x62
	tagRLRE = asn1.ApplicationConstructed(3) // 0x63
	tagABRT = asn1.ApplicationConstructed(4) // 0x64
)

// MMS application context name OID.
var oidMMSContext = asn1.OID{1, 0, 9506, 2, 3}

// The ACSI application context name, the alternative IEC 61850-7-2 defines
// for the association. Some servers accept only this one; most, including
// the reference C stack, accept the plain MMS context. Neither is wrong, so
// the choice is per association: see ApplicationContext.
var oidACSIContext = asn1.OID{1, 0, 61850, 4, 0, 2}

// ApplicationContext names the application-context-name an AARQ proposes.
// The zero value is the plain MMS context, which interoperates with the
// widest set of peers. A responder does not choose one: an AARE echoes the
// context the peer proposed (AAREFor).
type ApplicationContext int

const (
	// MMSContext is the plain ISO 9506-2 MMS context, 1.0.9506.2.3.
	MMSContext ApplicationContext = iota
	// ACSIContext is the IEC 61850 ACSI context, 1.0.61850.4.0.2.
	ACSIContext
)

// OID returns the object identifier the context is named by.
func (c ApplicationContext) OID() asn1.OID {
	if c == ACSIContext {
		return oidACSIContext
	}
	return oidMMSContext
}

// knownApplicationContext reports whether oid is one of the two contexts
// this library serves.
func knownApplicationContext(oid asn1.OID) bool {
	return oid.Equal(oidMMSContext) || oid.Equal(oidACSIContext)
}

// PresentationContextMMS is the presentation-context-identifier used for
// MMS in the EXTERNAL indirect reference.
const PresentationContextMMS = 3

// PasswordMechanism is the ACSE password authentication mechanism, 2.2.3.1
// (ISO/IEC 8650-1, IEC 61850-8-1 clause 21).
var PasswordMechanism = asn1.OID{2, 2, 3, 1}

// AARQ builds an A-ASSOCIATE request APDU carrying mmsInitiate (an MMS
// InitiateRequestPDU) as user information. If password is non-empty an
// ACSE authentication-value (mechanism-name password) is included.
func AARQ(mmsInitiate []byte, password string) []byte {
	return AARQWithIdentity(mmsInitiate, password, Identity{}, Identity{})
}

// AARQWithIdentity is AARQ addressing a called AE and claiming a calling one.
// Empty identities produce the same APDU AARQ builds.
func AARQWithIdentity(mmsInitiate []byte, password string, called, calling Identity) []byte {
	return AARQFor(mmsInitiate, password, called, calling, MMSContext)
}

// Auth is an ACSE authentication: the mechanism-name and the
// Authentication-value, encoded as the CHOICE element (charstring [0] for a
// password, external [2] for the IEC 62351-4 A-profile).
type Auth struct {
	Mechanism asn1.OID
	Value     []byte
}

// PasswordAuth is the password mechanism carrying pw.
func PasswordAuth(pw string) *Auth {
	// AuthenticationValue charstring [0] IMPLICIT GraphicString
	return &Auth{Mechanism: PasswordMechanism, Value: asn1.Prim(asn1.ContextPrimitive(0), []byte(pw)).Encode()}
}

// AARQFor is AARQWithIdentity proposing the given application context.
func AARQFor(mmsInitiate []byte, password string, called, calling Identity, appCtx ApplicationContext) []byte {
	var auth *Auth
	if password != "" {
		auth = PasswordAuth(password)
	}
	return AARQAuth(mmsInitiate, auth, called, calling, appCtx)
}

// AARQAuth is AARQFor with any authentication mechanism; nil sends none.
func AARQAuth(mmsInitiate []byte, auth *Auth, called, calling Identity, appCtx ApplicationContext) []byte {
	seq := asn1.Cons(tagAARQ,
		// application-context-name [1] EXPLICIT OID
		asn1.Cons(asn1.ContextConstructed(1), asn1.OIDElem(asn1.TagOID, appCtx.OID())),
	)
	// called-AP-title [2] .. [5], then calling-AP-title [6] .. [9].
	addIdentity(seq, 2, called)
	addIdentity(seq, 6, calling)
	// sender-acse-requirements [10], mechanism-name [11],
	// calling-authentication-value [12]. A password names password-1,
	// {joint-iso-itu-t(2) association-control(2) authentication-mechanism(3)
	// password-1(1)}: libiec61850 drops an association naming another
	// mechanism with a charstring value.
	addAuth(seq, 10, auth)
	// user-information [30] IMPLICIT SEQUENCE OF EXTERNAL
	seq.Add(asn1.Cons(asn1.ContextConstructed(30), external(mmsInitiate, PresentationContextMMS)))
	return seq.Encode()
}

// addAuth appends acse-requirements {authentication(0)}, mechanism-name and
// the authentication value [EXPLICIT] at consecutive tags from base: [10]
// to [12] in an AARQ, [8] to [10] in an AARE.
func addAuth(seq *asn1.Element, base uint32, auth *Auth) {
	if auth == nil {
		return
	}
	bs := asn1.NewBitString(1)
	bs.SetBit(0, true)
	seq.Add(asn1.BitStringElem(asn1.ContextPrimitive(base), bs))
	if auth.Mechanism != nil {
		seq.Add(asn1.OIDElem(asn1.ContextPrimitive(base+1), auth.Mechanism))
	}
	seq.Add(asn1.RawContent(asn1.ContextConstructed(base+2), auth.Value))
}

// Identity is the application-entity identity carried in an AARQ or AARE:
// the AP-title and AE-qualifier, plus the invocation identifiers when the
// peer supplies them.
//
// Clients configured with a device's AP-title check the responding identity
// in the AARE before they will use the association, so a server standing in
// for a device has to answer with the device's identity rather than omit it.
type Identity struct {
	APTitle     asn1.OID // ap-title-form2 (OBJECT IDENTIFIER)
	AEQualifier int32
	HasAEQual   bool

	APInvocationID  int32
	HasAPInvocation bool
	AEInvocationID  int32
	HasAEInvocation bool
}

// Empty reports whether the identity carries nothing to encode.
func (id Identity) Empty() bool {
	return len(id.APTitle) == 0 && !id.HasAEQual && !id.HasAPInvocation && !id.HasAEInvocation
}

// addIdentity appends the identity fields to an AARQ or AARE, starting at the
// given context tag number. The four fields are consecutive in both APDUs —
// called-AP-title is [2] and responding-AP-title is [4] — so one encoder
// serves both by being told where its block begins.
func addIdentity(seq *asn1.Element, base uint32, id Identity) {
	if len(id.APTitle) > 0 {
		// AP-title ::= CHOICE { ap-title-form1, ap-title-form2 OBJECT IDENTIFIER }
		seq.Add(asn1.Cons(asn1.ContextConstructed(base),
			asn1.OIDElem(asn1.TagOID, id.APTitle)))
	}
	if id.HasAEQual {
		// AE-qualifier ::= CHOICE { ..., ae-qualifier-form2 INTEGER }
		seq.Add(asn1.Cons(asn1.ContextConstructed(base+1),
			asn1.IntElem(asn1.TagInteger, int64(id.AEQualifier))))
	}
	if id.HasAPInvocation {
		seq.Add(asn1.Cons(asn1.ContextConstructed(base+2),
			asn1.IntElem(asn1.TagInteger, int64(id.APInvocationID))))
	}
	if id.HasAEInvocation {
		seq.Add(asn1.Cons(asn1.ContextConstructed(base+3),
			asn1.IntElem(asn1.TagInteger, int64(id.AEInvocationID))))
	}
}

// parseIdentity reads the identity block beginning at the given context tag
// number, ignoring tags outside it.
func parseIdentity(tag asn1.Tag, content []byte, base uint32, id *Identity) bool {
	switch tag {
	case asn1.ContextConstructed(base):
		if oid, ok := firstOID(content); ok {
			id.APTitle = oid
		}
	case asn1.ContextConstructed(base + 1):
		if n, err := asn1.DecodeInt(firstInt(content)); err == nil {
			id.AEQualifier, id.HasAEQual = int32(n), true
		}
	case asn1.ContextConstructed(base + 2):
		if n, err := asn1.DecodeInt(firstInt(content)); err == nil {
			id.APInvocationID, id.HasAPInvocation = int32(n), true
		}
	case asn1.ContextConstructed(base + 3):
		if n, err := asn1.DecodeInt(firstInt(content)); err == nil {
			id.AEInvocationID, id.HasAEInvocation = int32(n), true
		}
	default:
		return false
	}
	return true
}

// AARE builds an A-ASSOCIATE response APDU accepting the association and
// carrying mmsInitiateResp as user information.
func AARE(mmsInitiateResp []byte) []byte {
	return AAREWithIdentity(mmsInitiateResp, Identity{})
}

// AAREWithIdentity is AARE carrying a responding AP-title and AE-qualifier.
// An empty identity produces the same bare acceptance AARE builds, so a
// server that has nothing to claim is unchanged.
func AAREWithIdentity(mmsInitiateResp []byte, responding Identity) []byte {
	return AAREFor(mmsInitiateResp, responding, nil, 0)
}

// AAREFor is AAREWithIdentity answering a specific AARQ. proposed is the
// application-context-name the peer proposed, which the AARE echoes when
// it is one this library serves: answering an ACSI proposal with the MMS
// context, or the reverse, is a mismatch a strict peer refuses. Nil or an
// unknown context answers with the plain MMS one.
//
// mmsContextID is the presentation-context-identifier the peer gave the
// MMS abstract syntax, which the user information's EXTERNAL must carry as
// its indirect-reference: it tells the peer which syntax the
// InitiateResponse is in, and the identifier is the proposer's choice, not
// a constant. Zero uses the conventional PresentationContextMMS.
func AAREFor(mmsInitiateResp []byte, responding Identity, proposed asn1.OID, mmsContextID int) []byte {
	return AAREAuth(mmsInitiateResp, responding, proposed, mmsContextID, nil)
}

// AAREAuth is AAREFor carrying a responding authentication (nil: none).
func AAREAuth(mmsInitiateResp []byte, responding Identity, proposed asn1.OID, mmsContextID int, auth *Auth) []byte {
	if !knownApplicationContext(proposed) {
		proposed = oidMMSContext
	}
	if mmsContextID == 0 {
		mmsContextID = PresentationContextMMS
	}
	seq := asn1.Cons(tagAARE,
		asn1.Cons(asn1.ContextConstructed(1), asn1.OIDElem(asn1.TagOID, proposed)),
		// result [2] EXPLICIT INTEGER accepted(0)
		asn1.Cons(asn1.ContextConstructed(2), asn1.IntElem(asn1.TagInteger, 0)),
		// result-source-diagnostic [3] EXPLICIT CHOICE acse-service-user [1] INTEGER 0
		asn1.Cons(asn1.ContextConstructed(3),
			asn1.Cons(asn1.ContextConstructed(1), asn1.IntElem(asn1.TagInteger, 0))),
	)
	// responding-AP-title [4] .. responding-AE-invocation-identifier [7],
	// which the ASN.1 places between the diagnostic and the user information.
	addIdentity(seq, 4, responding)
	// responder-acse-requirements [8], mechanism-name [9],
	// responding-authentication-value [10].
	addAuth(seq, 8, auth)
	seq.Add(asn1.Cons(asn1.ContextConstructed(30), external(mmsInitiateResp, mmsContextID)))
	return seq.Encode()
}

// Associate-source-diagnostic values of the acse-service-user (ISO 8650).
const (
	DiagNoReason                   = 1
	DiagAuthenticationFailure      = 13
	DiagAuthenticationRequired     = 14
	DiagAuthMechanismNotRecognised = 11
	DiagAuthMechanismRequired      = 12
)

// AAREReject builds a rejecting AARE with the given service-user diagnostic.
func AAREReject(diagnostic int) []byte { return AARERejectFor(nil, diagnostic) }

// AARERejectFor is AAREReject answering with the application context the
// peer proposed (the MMS context when nil), as a responder must echo it.
func AARERejectFor(proposed asn1.OID, diagnostic int) []byte {
	ctx := oidMMSContext
	if knownApplicationContext(proposed) {
		ctx = proposed
	}
	seq := asn1.Cons(tagAARE,
		asn1.Cons(asn1.ContextConstructed(1), asn1.OIDElem(asn1.TagOID, ctx)),
		asn1.Cons(asn1.ContextConstructed(2), asn1.IntElem(asn1.TagInteger, 1)), // rejected-permanent
		asn1.Cons(asn1.ContextConstructed(3),
			asn1.Cons(asn1.ContextConstructed(1), asn1.IntElem(asn1.TagInteger, int64(diagnostic)))),
	)
	return seq.Encode()
}

// ABRT source values (ISO 8650).
const (
	AbortSourceUser     = 0 // acse-service-user
	AbortSourceProvider = 1 // acse-service-provider
)

// ABRT builds an A-ABORT APDU: ABRT-apdu ::= [APPLICATION 4] IMPLICIT
// SEQUENCE { abort-source [0] IMPLICIT INTEGER }.
func ABRT(source int) []byte {
	return asn1.Cons(tagABRT, asn1.IntElem(asn1.ContextPrimitive(0), int64(source))).Encode()
}

// ParseABRT returns the abort source of an A-ABORT APDU.
func ParseABRT(apdu []byte) (int, error) {
	content, err := asn1.NewDecoder(apdu).Expect(tagABRT)
	if err != nil {
		return 0, fmt.Errorf("acse: not an ABRT: %w", err)
	}
	src, ok, err := asn1.NewDecoder(content).Optional(asn1.ContextPrimitive(0))
	if err != nil || !ok {
		return 0, err
	}
	n, err := asn1.DecodeInt(src)
	return int(n), err
}

// RLRQ builds an A-RELEASE request APDU.
func RLRQ() []byte {
	return asn1.Cons(tagRLRQ).Encode()
}

// RLRE builds an A-RELEASE response APDU.
func RLRE() []byte {
	return asn1.Cons(tagRLRE).Encode()
}

// external wraps a pre-encoded MMS PDU as an ACSE EXTERNAL using the MMS
// presentation context indirect reference and single-ASN1-type encoding.
func external(mmsPDU []byte, contextID int) *asn1.Element {
	return asn1.Cons(asn1.Tag{Class: asn1.ClassUniversal, Constructed: true, Number: 8}, // [UNIVERSAL 8] EXTERNAL
		asn1.IntElem(asn1.TagInteger, int64(contextID)),     // indirect-reference
		asn1.RawContent(asn1.ContextConstructed(0), mmsPDU), // single-ASN1-type [0]
	)
}

// Result is the outcome of parsing an AARE.
type Result struct {
	Accepted   bool
	Diagnostic int
	UserData   []byte // the MMS InitiateResponsePDU

	// Responding is the identity the peer answered with. A proxy replays it
	// so its own clients see the device's identity; it is zero when the peer
	// omitted the fields, which is legal.
	Responding Identity

	// Result is the associate-result (0 accepted, 1 rejected-permanent, 2
	// rejected-transient), DiagSource the result-source-diagnostic choice
	// (1 acse-service-user, 2 acse-service-provider).
	Result, DiagSource int
	// ApplicationContext is the application-context-name answered.
	ApplicationContext asn1.OID
	// UserInfo holds every EXTERNAL of the user-information.
	UserInfo [][]byte

	// ResponderAuth reports the authentication functional unit selected in
	// responder-acse-requirements; Mechanism is the mechanism-name and
	// AuthValue the responding-authentication-value (the CHOICE element),
	// each nil when absent.
	ResponderAuth bool
	Mechanism     asn1.OID
	AuthValue     []byte
}

// ParseAARE parses an A-ASSOCIATE response and extracts the MMS user data.
func ParseAARE(apdu []byte) (*Result, error) {
	dec := asn1.NewDecoder(apdu)
	content, err := dec.Expect(tagAARE)
	if err != nil {
		return nil, fmt.Errorf("acse: not an AARE: %w", err)
	}
	res := &Result{Accepted: true}
	inner := asn1.NewDecoder(content)
	for inner.More() {
		tag, c, err := inner.ReadTLV()
		if err != nil {
			return nil, err
		}
		// responding-AP-title [4] .. responding-AE-invocation-identifier [7].
		if parseIdentity(tag, c, 4, &res.Responding) {
			continue
		}
		switch tag {
		case asn1.ContextConstructed(2): // result
			n, err := asn1.DecodeInt(firstInt(c))
			if err == nil && n != 0 {
				res.Accepted = false
			}
			res.Result = int(n)
		case asn1.ContextConstructed(3): // result-source-diagnostic
			res.Diagnostic = parseDiagnostic(c)
			if t, err := asn1.NewDecoder(c).Peek(); err == nil {
				res.DiagSource = int(t.Number)
			}
		case asn1.ContextConstructed(1): // application-context-name
			res.ApplicationContext, _ = firstOID(c)
		case asn1.ContextPrimitive(8): // responder-acse-requirements
			res.ResponderAuth = authBit(c)
		case asn1.ContextPrimitive(9): // mechanism-name
			res.Mechanism, _ = asn1.DecodeOID(c)
		case asn1.ContextConstructed(10): // responding-authentication-value
			res.AuthValue = c
		case asn1.ContextConstructed(30): // user-information
			if res.UserInfo, err = externals(c); err != nil {
				return nil, err
			}
			res.UserData, _ = parseUserInfo(c)
		}
	}
	return res, nil
}

// Request is the outcome of parsing an AARQ.
type Request struct {
	UserData []byte // the MMS InitiateRequestPDU
	Password string

	// Called is the identity the peer addressed, and Calling the one it
	// claims. A client that fills in Called is checking who it reached, and
	// expects the responding identity in the AARE to match.
	Called  Identity
	Calling Identity

	// ApplicationContext is the application-context-name the peer
	// proposed, nil when it could not be decoded.
	ApplicationContext asn1.OID

	// UserInfo holds every EXTERNAL of the user-information, complete TLVs.
	UserInfo [][]byte
	// Mechanism is the mechanism-name and AuthValue the
	// calling-authentication-value (the CHOICE element), nil when absent.
	Mechanism asn1.OID
	AuthValue []byte

	// NonKernel reports fields outside the ACSE kernel: sender-acse-
	// requirements, mechanism-name, calling-authentication-value or
	// application-context-name-list (IEC 62351-4 15.6.1).
	NonKernel bool
}

// ParseAARQ parses an A-ASSOCIATE request and extracts the MMS user data
// and any calling authentication password.
func ParseAARQ(apdu []byte) (userData []byte, password string, err error) {
	req, err := ParseAARQFull(apdu)
	if err != nil {
		return nil, "", err
	}
	return req.UserData, req.Password, nil
}

// ParseAARQFull is ParseAARQ including the ACSE identities.
func ParseAARQFull(apdu []byte) (Request, error) {
	var req Request
	dec := asn1.NewDecoder(apdu)
	content, err := dec.Expect(tagAARQ)
	if err != nil {
		return req, fmt.Errorf("acse: not an AARQ: %w", err)
	}
	inner := asn1.NewDecoder(content)
	for inner.More() {
		tag, c, err := inner.ReadTLV()
		if err != nil {
			return req, err
		}
		// called-AP-title [2] .. called-AE-invocation-identifier [5], then
		// calling-AP-title [6] .. calling-AE-invocation-identifier [9].
		if parseIdentity(tag, c, 2, &req.Called) || parseIdentity(tag, c, 6, &req.Calling) {
			continue
		}
		switch tag {
		case asn1.ContextConstructed(1): // application-context-name
			if oidBody, err := asn1.NewDecoder(c).Expect(asn1.TagOID); err == nil {
				if oid, err := asn1.DecodeOID(oidBody); err == nil {
					req.ApplicationContext = oid
				}
			}
		case asn1.ContextPrimitive(10), asn1.ContextConstructed(13):
			req.NonKernel = true
		case asn1.ContextPrimitive(11): // mechanism-name
			req.NonKernel = true
			req.Mechanism, _ = asn1.DecodeOID(c)
		case asn1.ContextConstructed(12): // calling-authentication-value
			req.NonKernel = true
			req.AuthValue = c
			av := asn1.NewDecoder(c)
			if pw, ok, _ := av.Optional(asn1.ContextPrimitive(0)); ok {
				req.Password = string(pw)
			}
		case asn1.ContextConstructed(30):
			if req.UserInfo, err = externals(c); err != nil {
				return req, err
			}
			req.UserData, _ = parseUserInfo(c)
		}
	}
	return req, nil
}

// IsRelease reports whether apdu is an RLRQ (release request).
func IsRelease(apdu []byte) bool {
	dec := asn1.NewDecoder(apdu)
	return dec.PeekIs(tagRLRQ)
}

func parseUserInfo(content []byte) ([]byte, error) {
	dec := asn1.NewDecoder(content)
	extTag := asn1.Tag{Class: asn1.ClassUniversal, Constructed: true, Number: 8}
	ext, err := dec.Expect(extTag)
	if err != nil {
		return nil, fmt.Errorf("acse: user-info not EXTERNAL: %w", err)
	}
	ed := asn1.NewDecoder(ext)
	for ed.More() {
		tag, c, err := ed.ReadTLV()
		if err != nil {
			return nil, err
		}
		switch tag {
		case asn1.ContextConstructed(0): // single-ASN1-type
			return c, nil
		case asn1.ContextPrimitive(1): // octet-aligned
			return c, nil
		}
	}
	return nil, fmt.Errorf("acse: EXTERNAL has no encoding")
}

// authBit reports the authentication(0) bit of an ACSE-requirements BIT
// STRING's content (unused-bits octet, then the bits).
func authBit(c []byte) bool { return len(c) >= 2 && c[1]&0x80 != 0 }

func parseDiagnostic(content []byte) int {
	dec := asn1.NewDecoder(content)
	for dec.More() {
		_, c, err := dec.ReadTLV()
		if err != nil {
			return 0
		}
		if n, err := asn1.DecodeInt(firstInt(c)); err == nil {
			return int(n)
		}
	}
	return 0
}

// firstOID returns the OBJECT IDENTIFIER inside an EXPLICIT wrapper, which is
// how AP-title form2 is carried.
func firstOID(content []byte) (asn1.OID, bool) {
	dec := asn1.NewDecoder(content)
	c, err := dec.Expect(asn1.TagOID)
	if err != nil {
		return nil, false
	}
	oid, err := asn1.DecodeOID(c)
	if err != nil {
		return nil, false
	}
	return oid, true
}

// firstInt returns the content of the first INTEGER within an EXPLICIT
// wrapper, or the bytes themselves if already primitive content.
func firstInt(content []byte) []byte {
	dec := asn1.NewDecoder(content)
	if dec.PeekIs(asn1.TagInteger) {
		c, _ := dec.Expect(asn1.TagInteger)
		return c
	}
	return content
}
