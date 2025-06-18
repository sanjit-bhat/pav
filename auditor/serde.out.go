// Auto-generated from spec "github.com/mit-pdos/pav/auditor/serde.go"
// using compiler "github.com/mit-pdos/pav/serde".
package auditor

import (
	"github.com/mit-pdos/pav/ktserde"
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func UpdateArgEncode(b0 []byte, o *UpdateArg) []byte {
	var b = b0
	b = ktserde.AuditProofEncode(b, o.P)
	return b
}
func UpdateArgDecode(b0 []byte) (*UpdateArg, []byte, bool) {
	a1, b1, err1 := ktserde.AuditProofDecode(b0)
	if err1 {
		return nil, nil, true
	}
	return &UpdateArg{P: a1}, b1, false
}
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
	b = EpochInfoEncode(b, o.X)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func GetReplyDecode(b0 []byte) (*GetReply, []byte, bool) {
	a1, b1, err1 := EpochInfoDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadBool(b1)
	if err2 {
		return nil, nil, true
	}
	return &GetReply{X: a1, Err: a2}, b2, false
}
func EpochInfoEncode(b0 []byte, o *EpochInfo) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Link)
	b = marshalutil.WriteSlice1D(b, o.ServSig)
	b = marshalutil.WriteSlice1D(b, o.AdtrSig)
	return b
}
func EpochInfoDecode(b0 []byte) (*EpochInfo, []byte, bool) {
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
	return &EpochInfo{Link: a1, ServSig: a2, AdtrSig: a3}, b3, false
}
