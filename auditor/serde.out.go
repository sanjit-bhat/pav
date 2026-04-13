// Auto-generated from spec "github.com/sanjit-bhat/pav/auditor/serde.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package auditor

import (
	"github.com/sanjit-bhat/pav/safemarshal"
	"github.com/tchajed/marshal"
)

func GetArgEncode(b0 []byte, o *GetArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	return b
}
func GetArgDecode(b0 []byte) (*GetArg, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &GetArg{Epoch: a1}, b1, false
}
func SignedLinkEncode(b0 []byte, o *SignedLink) []byte {
	var b = b0
	b = safemarshal.WriteSlice1D(b, o.Link)
	b = safemarshal.WriteSlice1D(b, o.ServSig)
	b = safemarshal.WriteSlice1D(b, o.AdtrSig)
	return b
}
func SignedLinkDecode(b0 []byte) (*SignedLink, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := safemarshal.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := safemarshal.ReadSlice1D(b2)
	if err3 {
		return nil, nil, true
	}
	return &SignedLink{Link: a1, ServSig: a2, AdtrSig: a3}, b3, false
}
func SignedVrfEncode(b0 []byte, o *SignedVrf) []byte {
	var b = b0
	b = safemarshal.WriteSlice1D(b, o.VrfPk)
	b = safemarshal.WriteSlice1D(b, o.ServSig)
	b = safemarshal.WriteSlice1D(b, o.AdtrSig)
	return b
}
func SignedVrfDecode(b0 []byte) (*SignedVrf, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := safemarshal.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := safemarshal.ReadSlice1D(b2)
	if err3 {
		return nil, nil, true
	}
	return &SignedVrf{VrfPk: a1, ServSig: a2, AdtrSig: a3}, b3, false
}
func GetReplyEncode(b0 []byte, o *GetReply) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.StartEp)
	b = SignedLinkEncode(b, o.StartLink)
	b = SignedLinkEncode(b, o.CurrLink)
	b = SignedVrfEncode(b, o.Vrf)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func GetReplyDecode(b0 []byte) (*GetReply, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := SignedLinkDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := SignedLinkDecode(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := SignedVrfDecode(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := safemarshal.ReadBool(b4)
	if err5 {
		return nil, nil, true
	}
	return &GetReply{StartEp: a1, StartLink: a2, CurrLink: a3, Vrf: a4, Err: a5}, b5, false
}
