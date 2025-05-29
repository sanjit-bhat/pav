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
	b = marshal.WriteInt(b, o.Ver)
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
	a3, b3, err3 := marshalutil.ReadInt(b2)
	if err3 {
		return nil, nil, true
	}
	return &ServerPutArg{Uid: a1, Pk: a2, Ver: a3}, b3, false
}
func ServerHistoryArgEncode(b0 []byte, o *ServerHistoryArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	b = marshal.WriteInt(b, o.PrefixLen)
	return b
}
func ServerHistoryArgDecode(b0 []byte) (*ServerHistoryArg, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	return &ServerHistoryArg{Uid: a1, PrefixLen: a2}, b2, false
}
func ServerHistoryReplyEncode(b0 []byte, o *ServerHistoryReply) []byte {
	var b = b0
	b = ktserde.SigDigEncode(b, o.Dig)
	b = ktserde.MembSlice1DEncode(b, o.Hist)
	b = ktserde.NonMembEncode(b, o.Bound)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func ServerHistoryReplyDecode(b0 []byte) (*ServerHistoryReply, []byte, bool) {
	a1, b1, err1 := ktserde.SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := ktserde.MembSlice1DDecode(b1)
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
	return &ServerHistoryReply{Dig: a1, Hist: a2, Bound: a3, Err: a4}, b4, false
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
