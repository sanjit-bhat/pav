// Auto-generated from spec "github.com/sanjit-bhat/pav/auditor/serde.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package auditor

import (
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/safemarshal"
	"github.com/tchajed/marshal"
)

func UpdateReplyEncode(b0 []byte, o *UpdateReply) []byte {
	var b = b0
	b = marshal.WriteInt(b, uint64(o.Err))
	return b
}
func UpdateReplyDecode(b0 []byte) (*UpdateReply, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &UpdateReply{Err: ktcore.Blame(a1)}, b1, false
}
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
func GetReplyEncode(b0 []byte, o *GetReply) []byte {
	var b = b0
	b = safemarshal.WriteSlice1D(b, o.Link)
	b = safemarshal.WriteSlice1D(b, o.ServLinkSig)
	b = safemarshal.WriteSlice1D(b, o.AdtrLinkSig)
	b = safemarshal.WriteSlice1D(b, o.VrfPk)
	b = safemarshal.WriteSlice1D(b, o.ServVrfSig)
	b = safemarshal.WriteSlice1D(b, o.AdtrVrfSig)
	b = marshal.WriteInt(b, uint64(o.Err))
	return b
}
func GetReplyDecode(b0 []byte) (*GetReply, []byte, bool) {
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
	a4, b4, err4 := safemarshal.ReadSlice1D(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := safemarshal.ReadSlice1D(b4)
	if err5 {
		return nil, nil, true
	}
	a6, b6, err6 := safemarshal.ReadSlice1D(b5)
	if err6 {
		return nil, nil, true
	}
	a7, b7, err7 := safemarshal.ReadInt(b6)
	if err7 {
		return nil, nil, true
	}
	return &GetReply{Link: a1, ServLinkSig: a2, AdtrLinkSig: a3, VrfPk: a4, ServVrfSig: a5, AdtrVrfSig: a6, Err: ktcore.Blame(a7)}, b7, false
}
