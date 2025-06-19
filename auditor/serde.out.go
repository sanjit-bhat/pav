// Auto-generated from spec "github.com/mit-pdos/pav/auditor/serde.go"
// using compiler "github.com/mit-pdos/pav/serde".
package auditor

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func UpdateReplyEncode(b0 []byte, o *UpdateReply) []byte {
	var b = b0
	b = marshal.WriteBool(b, o.Err)
	return b
}
func UpdateReplyDecode(b0 []byte) (*UpdateReply, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadBool(b0)
	if err1 {
		return nil, nil, true
	}
	return &UpdateReply{Err: a1}, b1, false
}
func GetArgEncode(b0 []byte, o *GetArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	return b
}
func GetArgDecode(b0 []byte) (*GetArg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &GetArg{Epoch: a1}, b1, false
}
func GetReplyEncode(b0 []byte, o *GetReply) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Link)
	b = marshalutil.WriteSlice1D(b, o.ServLinkSig)
	b = marshalutil.WriteSlice1D(b, o.AdtrLinkSig)
	b = marshalutil.WriteSlice1D(b, o.VrfPk)
	b = marshalutil.WriteSlice1D(b, o.ServVrfSig)
	b = marshalutil.WriteSlice1D(b, o.AdtrVrfSig)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func GetReplyDecode(b0 []byte) (*GetReply, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadSlice1D(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := marshalutil.ReadSlice1D(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := marshalutil.ReadSlice1D(b4)
	if err5 {
		return nil, nil, true
	}
	a6, b6, err6 := marshalutil.ReadSlice1D(b5)
	if err6 {
		return nil, nil, true
	}
	a7, b7, err7 := marshalutil.ReadBool(b6)
	if err7 {
		return nil, nil, true
	}
	return &GetReply{Link: a1, ServLinkSig: a2, AdtrLinkSig: a3, VrfPk: a4, ServVrfSig: a5, AdtrVrfSig: a6, Err: a7}, b7, false
}
