// Package gdoi implements group key distribution for IEC 61850 (IEC
// 62351-9): the Group Domain of Interpretation (GDOI, RFC 6407) with the
// IEC 61850 payloads of RFC 8052, over an IKEv1 phase 1 (RFC 2409). A key
// server hands the traffic encryption keys (TEKs) of a group to the
// members it authorises; a member installs them in the rsession.KeyStore
// its R-GOOSE and R-SV sessions use.
//
// # Key server
//
//	g := &gdoi.Group{}
//	tek, _ := gdoi.NewTEK(streamOID, nil, gdoi.AuthNone, gdoi.EncAESGCM128, 24*time.Hour)
//	g.Add(tek)
//	ks, _ := gdoi.NewServer(gdoi.ServerConfig{
//	    Credentials: gdoi.Credentials{Certificate: chain, Key: key, Roots: roots},
//	    Authorize:   func(m gdoi.Peer, grp gdoi.GroupID) bool { return allowed(m.Certificate, grp) },
//	})
//	ks.AddGroup(gdoi.GroupID{OID: streamOID}, g)
//	go ks.ListenAndServe(":848")
//
// A rotation adds the next TEK with an ActivationDelay, so members pick it
// up before it is used, and removes the old one after it expires.
//
// # Group member
//
//	keys := &rsession.KeyStore{}
//	m := gdoi.NewMember(gdoi.MemberConfig{
//	    Server:          "ks.substation:848",
//	    Credentials:     gdoi.Credentials{Certificate: chain, Key: key, Roots: roots},
//	    AuthorizeServer: func(p gdoi.Peer) error { return isOurKeyServer(p.Certificate) },
//	}, gdoi.GroupID{OID: streamOID}, keys)
//	go m.Run(ctx)
//	s, _ := rsession.Open(rsession.Config{Remote: dst, Keys: keys})
//
// Run registers, installs each TEK when its activation delay passes, makes
// the newest one active for sending, drops keys when they expire or the
// key server stops listing them, and registers again before they run out.
//
// # What is implemented
//
//   - Phase 1: IKEv1 main mode, as initiator (member) and responder (key
//     server), authenticated with certificates (RSA of 2048 bits or more,
//     ECDSA P-256 and P-384, RFC 4754) or a pre-shared key; AES-CBC-128 or
//     -256, SHA2-256 or SHA2-384, and Diffie-Hellman groups 14 (2048-bit
//     MODP), 19 and 20 (256- and 384-bit ECP, RFC 5903). Certificates are
//     verified to configured roots and bound to the identification payload.
//   - GROUPKEY-PULL (RFC 6407 3): the member names its group by ID_KEY_ID or
//     by the ID_OID of RFC 8052, and receives the group's SA TEKs
//     (GDOI_PROTO_IEC_61850) and their keys (TEK_ALGORITHM_KEY,
//     TEK_INTEGRITY_KEY), with the SA_ATD activation delay and the SA_KDA
//     attribute. The key server authorises each member for each group, and
//     records nothing until the member has proven it holds the server's
//     nonce (message 3).
//   - Both sides retransmit or answer retransmissions, refuse what does not
//     verify, and tell the peer with an ISAKMP notification (in the clear
//     before phase 1 completes, protected after).
//   - A TEK maps to an rsession key: HMAC-SHA256-128 and HMAC-SHA256 sign,
//     AES-GCM-128 and -256 encrypt, the SPI is the key ID.
//
// # Not implemented
//
//   - GROUPKEY-PUSH and the rekey SA (KEK, LKH, SEQ): a member
//     re-registers instead, so a key server has to distribute a new key
//     ahead of its use (ActivationDelay longer than Member.Refresh). A
//     KEK in the policy is ignored.
//   - Aggressive mode, NAT traversal, and the GAP payload (sender IDs,
//     which RFC 8052 does not use).
//   - AES-CBC and AES-GMAC TEKs are distributed and returned, but the
//     session layer has no counterpart: Member skips them with an event.
//   - The group OIDs of IEC 62351-9 are the application's to supply.
//
// # Choices the RFCs leave open
//
//   - "An OID encoded using DER" is taken as the whole DER encoding, tag
//     and length included, in both the ID_OID data and the SA TEK.
//   - The 4-octet salt RFC 8052 appends to GCM and GMAC keys is not used by
//     the session layer, which carries a full random IV in every SPDU.
//   - The phase 1 SA carries the GDOI DOI, as RFC 6407 2.1 requires; the
//     IPsec DOI is accepted from a peer that sends it.
//
// # Verification
//
// Beyond the unit tests (the RFC 5903 ECP-256 vectors, codec round trips,
// registration with each credential type, authorisation, loss and
// tampering, key rotation into rsession, fuzzing), a registration is
// captured and dissected by Wireshark's IKEv1 dissector, which decrypts
// every message with its own derivation of the IVs from the key alone
// (wireshark_test.go; interop/run.sh runs it). Wireshark reads an SA with
// the GDOI DOI in the phase 2 layout only, so that capture carries the
// IPsec DOI in its phase 1 SA.
package gdoi
