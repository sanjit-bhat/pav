package auditor

import (
	"github.com/mit-pdos/pav/ktserde"
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func AdtrUpdateArgEncode(b0 []byte, o *AdtrUpdateArg) []byte {
	var b = b0
	b = ktserde.UpdateProofEncode(b, o.P)
	return b
}
func AdtrUpdateArgDecode(b0 []byte) (*AdtrUpdateArg, []byte, bool) {
	a1, b1, err1 := ktserde.UpdateProofDecode(b0)
	if err1 {
		return nil, nil, true
	}
	return &AdtrUpdateArg{P: a1}, b1, false
}
func AdtrUpdateReplyEncode(b0 []byte, o *AdtrUpdateReply) []byte {
	var b = b0
	b = marshal.WriteBool(b, o.Err)
	return b
}
func AdtrUpdateReplyDecode(b0 []byte) (*AdtrUpdateReply, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadBool(b0)
	if err1 {
		return nil, nil, true
	}
	return &AdtrUpdateReply{Err: a1}, b1, false
}
func AdtrGetArgEncode(b0 []byte, o *AdtrGetArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	return b
}
func AdtrGetArgDecode(b0 []byte) (*AdtrGetArg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &AdtrGetArg{Epoch: a1}, b1, false
}
func AdtrEpochInfoEncode(b0 []byte, o *AdtrEpochInfo) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Dig)
	b = marshalutil.WriteSlice1D(b, o.ServSig)
	b = marshalutil.WriteSlice1D(b, o.AdtrSig)
	return b
}
func AdtrEpochInfoDecode(b0 []byte) (*AdtrEpochInfo, []byte, bool) {
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
	return &AdtrEpochInfo{Dig: a1, ServSig: a2, AdtrSig: a3}, b3, false
}
func AdtrGetReplyEncode(b0 []byte, o *AdtrGetReply) []byte {
	var b = b0
	b = AdtrEpochInfoEncode(b, o.X)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func AdtrGetReplyDecode(b0 []byte) (*AdtrGetReply, []byte, bool) {
	a1, b1, err1 := AdtrEpochInfoDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadBool(b1)
	if err2 {
		return nil, nil, true
	}
	return &AdtrGetReply{X: a1, Err: a2}, b2, false
}
