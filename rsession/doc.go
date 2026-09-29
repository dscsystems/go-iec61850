// Package rsession implements the session protocol of IEC 61850-90-5,
// which carries GOOSE and sampled values over UDP (R-GOOSE and R-SV,
// adopted by IEC 61850-8-1 and 9-2 Amendment 1), with the message security
// that goes with it: an HMAC over each SPDU, or AES-GCM encryption of its
// user data, under keys identified in the header.
//
// # Using it
//
// A Session is an ethernet.Interface, so the GOOSE and SV publishers and
// subscribers of this module run over it as they run over a network
// interface:
//
//	keys, _ := rsession.NewKeyStore(rsession.Key{ID: 1, Material: k, Sec: rsession.SecAES128GCM})
//	s, _ := rsession.Open(rsession.Config{Remote: gc.DstIP.String(), Keys: keys})
//	pub, _ := goose.NewPublisherFromModel(s, ld, ln, gc, [6]byte{})
//
// and on the receiving side
//
//	s, _ := rsession.Open(rsession.Config{Groups: []string{"239.192.0.1"}, Keys: keys})
//	stop, _ := goose.NewSubscriber(s).Subscribe(goose.Filter{GoCbRef: ref}, handle)
//
// A receiver refuses what it cannot verify: an SPDU under a key it does
// not hold, one whose MAC or tag does not verify, an unsecured one (unless
// Config.AllowUnsecured), and a secured one it has already accepted (the
// replay window). Refusals are counted (Session.Stats) and reported to
// Config.OnReject for the security event log.
//
// # Keys
//
// Keys come from the KeyStore: the active key secures what a session
// sends, and every key in the store is accepted on receipt, so a key
// change is add the new key everywhere, make it active at the publisher,
// then remove the old one. Package gdoi does this from a key server (IEC
// 62351-9, GDOI): a gdoi.Member keeps a KeyStore current.
//
// # The wire format
//
// Marshal documents the layout. Where the references disagree it follows
// the one that makes the fields consistent, and reads the other:
//
//   - Header lengths. The session header length counts the common header
//     and the security information; the common header length is 10.
//     libiec61850 writes fixed values (24 and 18) whatever the header
//     holds. Neither it nor Wireshark reads them, and neither does
//     Unmarshal.
//   - SPDU length counts the octets after the field. No receiver checks
//     it.
//   - APDU length is the length of the APDU, as Wireshark reads it.
//     libiec61850 writes two more; Unmarshal accepts that on the last
//     element.
//   - A MAC covers the SPDU from its first octet (the transport header)
//     to the signature tag, as libiec61850 computes it. HMAC-SHA256-80,
//     -128 and -256 and the HMAC-SHA3 variants are implemented; the
//     AES-GMAC ones are not.
//   - Encryption (version 2 only) is AES-GCM with a random 12-octet IV in
//     the header, everything before the user data as additional
//     authenticated data, and the 16-octet tag in the trailer. A key
//     either signs or encrypts: GCM already authenticates, and
//     libiec61850's layout for both is not verifiable.
//
// The encoding is checked against libiec61850 1.6 in both directions for
// GOOSE and SV, unsecured, HMAC-SHA256-128/256 and AES-128/256-GCM (see
// interop/). libiec61850's own HMAC-SHA256-256 SPDUs carry a length octet
// of 16 before a 32-octet MAC; no receiver can take them, this one
// included.
package rsession
