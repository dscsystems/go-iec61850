package presentation

import "testing"

// Presentation PDUs from the peer: the CP a server parses, the CPA/CPR a
// client parses, and the data that follows.
func FuzzPresentation(f *testing.F) {
	f.Add(BuildCP(DefaultCallingPSel, DefaultCalledPSel, []byte{0x60, 0x00}))
	_, cpa := BuildCPA(nil, []Context{{ID: 1, AbstractSyntax: oidACSE, TransferSyntax: oidBER}}, []byte{0x61, 0x00})
	f.Add(cpa)
	f.Add(WrapData(ContextMMS, []byte{0xa0, 0x00}))
	f.Fuzz(func(t *testing.T, pdu []byte) {
		if cp, err := ParseCP(pdu); err == nil {
			BuildCPA(nil, cp.Contexts, []byte{0x61, 0x00})
		}
		ParseCPUserData(pdu)
		ParseCPRUserData(pdu)
		parseUserData(pdu)
	})
}
