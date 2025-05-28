package server

import (
	"github.com/mit-pdos/pav/ktserde"
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func ServerPutArgEncode(b0 []byte, o *ServerPutArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	b = marshalutil.WriteSlice1D(b, o.Pk)
	return b
}
func ServerPutArgDecode(b0 []byte) (*ServerPutArg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &ServerPutArg{Uid: a1, Pk: a2}, b2, false
}
func ServerPutReplyEncode(b0 []byte, o *ServerPutReply) []byte {
	var b = b0
	b = ktserde.SigDigEncode(b, o.Dig)
	b = ktserde.MembEncode(b, o.Latest)
	b = ktserde.NonMembEncode(b, o.Bound)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func ServerPutReplyDecode(b0 []byte) (*ServerPutReply, []byte, bool) {
	a1, b1, err1 := ktserde.SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := ktserde.MembDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := ktserde.NonMembDecode(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := marshalutil.ReadBool(b3)
	if err4 {
		return nil, nil, true
	}
	return &ServerPutReply{Dig: a1, Latest: a2, Bound: a3, Err: a4}, b4, false
}
func ServerGetArgEncode(b0 []byte, o *ServerGetArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	return b
}
func ServerGetArgDecode(b0 []byte) (*ServerGetArg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &ServerGetArg{Uid: a1}, b1, false
}
func ServerGetReplyEncode(b0 []byte, o *ServerGetReply) []byte {
	var b = b0
	b = ktserde.SigDigEncode(b, o.Dig)
	b = ktserde.MembHideSlice1DEncode(b, o.Hist)
	b = marshal.WriteBool(b, o.IsReg)
	b = ktserde.MembEncode(b, o.Latest)
	b = ktserde.NonMembEncode(b, o.Bound)
	return b
}
func ServerGetReplyDecode(b0 []byte) (*ServerGetReply, []byte, bool) {
	a1, b1, err1 := ktserde.SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := ktserde.MembHideSlice1DDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadBool(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := ktserde.MembDecode(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := ktserde.NonMembDecode(b4)
	if err5 {
		return nil, nil, true
	}
	return &ServerGetReply{Dig: a1, Hist: a2, IsReg: a3, Latest: a4, Bound: a5}, b5, false
}
func ServerSelfMonArgEncode(b0 []byte, o *ServerSelfMonArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	return b
}
func ServerSelfMonArgDecode(b0 []byte) (*ServerSelfMonArg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &ServerSelfMonArg{Uid: a1}, b1, false
}
func ServerSelfMonReplyEncode(b0 []byte, o *ServerSelfMonReply) []byte {
	var b = b0
	b = ktserde.SigDigEncode(b, o.Dig)
	b = ktserde.NonMembEncode(b, o.Bound)
	return b
}
func ServerSelfMonReplyDecode(b0 []byte) (*ServerSelfMonReply, []byte, bool) {
	a1, b1, err1 := ktserde.SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := ktserde.NonMembDecode(b1)
	if err2 {
		return nil, nil, true
	}
	return &ServerSelfMonReply{Dig: a1, Bound: a2}, b2, false
}
func ServerAuditArgEncode(b0 []byte, o *ServerAuditArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	return b
}
func ServerAuditArgDecode(b0 []byte) (*ServerAuditArg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &ServerAuditArg{Epoch: a1}, b1, false
}
func ServerAuditReplyEncode(b0 []byte, o *ServerAuditReply) []byte {
	var b = b0
	b = ktserde.UpdateProofEncode(b, o.P)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func ServerAuditReplyDecode(b0 []byte) (*ServerAuditReply, []byte, bool) {
	a1, b1, err1 := ktserde.UpdateProofDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadBool(b1)
	if err2 {
		return nil, nil, true
	}
	return &ServerAuditReply{P: a1, Err: a2}, b2, false
}
