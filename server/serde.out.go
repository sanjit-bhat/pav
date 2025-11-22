// Auto-generated from spec "github.com/sanjit-bhat/pav/server/serde.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package server

import (
	"github.com/sanjit-bhat/pav/ktcore"
	"github.com/sanjit-bhat/pav/safemarshal"
	"github.com/tchajed/marshal"
)

func StartReplyEncode(b0 []byte, o *StartReply) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.PrevEpochLen)
	b = safemarshal.WriteSlice1D(b, o.PrevLink)
	b = safemarshal.WriteSlice1D(b, o.ChainProof)
	b = safemarshal.WriteSlice1D(b, o.LinkSig)
	b = safemarshal.WriteSlice1D(b, o.VrfPk)
	b = safemarshal.WriteSlice1D(b, o.VrfSig)
	return b
}
func StartReplyDecode(b0 []byte) (*StartReply, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadInt(b0)
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
	return &StartReply{PrevEpochLen: a1, PrevLink: a2, ChainProof: a3, LinkSig: a4, VrfPk: a5, VrfSig: a6}, b6, false
}
func PutArgEncode(b0 []byte, o *PutArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	b = safemarshal.WriteSlice1D(b, o.Pk)
	b = marshal.WriteInt(b, o.Ver)
	return b
}
func PutArgDecode(b0 []byte) (*PutArg, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := safemarshal.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := safemarshal.ReadInt(b2)
	if err3 {
		return nil, nil, true
	}
	return &PutArg{Uid: a1, Pk: a2, Ver: a3}, b3, false
}
func HistoryArgEncode(b0 []byte, o *HistoryArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	b = marshal.WriteInt(b, o.PrevEpoch)
	b = marshal.WriteInt(b, o.PrevVerLen)
	return b
}
func HistoryArgDecode(b0 []byte) (*HistoryArg, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := safemarshal.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := safemarshal.ReadInt(b2)
	if err3 {
		return nil, nil, true
	}
	return &HistoryArg{Uid: a1, PrevEpoch: a2, PrevVerLen: a3}, b3, false
}
func HistoryReplyEncode(b0 []byte, o *HistoryReply) []byte {
	var b = b0
	b = safemarshal.WriteSlice1D(b, o.ChainProof)
	b = safemarshal.WriteSlice1D(b, o.LinkSig)
	b = ktcore.MembSlice1DEncode(b, o.Hist)
	b = ktcore.NonMembEncode(b, o.Bound)
	b = marshal.WriteInt(b, uint64(o.Err))
	return b
}
func HistoryReplyDecode(b0 []byte) (*HistoryReply, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := safemarshal.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := ktcore.MembSlice1DDecode(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := ktcore.NonMembDecode(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := safemarshal.ReadInt(b4)
	if err5 {
		return nil, nil, true
	}
	return &HistoryReply{ChainProof: a1, LinkSig: a2, Hist: a3, Bound: a4, Err: ktcore.Blame(a5)}, b5, false
}
func AuditArgEncode(b0 []byte, o *AuditArg) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.PrevEpoch)
	return b
}
func AuditArgDecode(b0 []byte) (*AuditArg, []byte, bool) {
	a1, b1, err1 := safemarshal.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	return &AuditArg{PrevEpoch: a1}, b1, false
}
func AuditReplyEncode(b0 []byte, o *AuditReply) []byte {
	var b = b0
	b = ktcore.AuditProofSlice1DEncode(b, o.P)
	b = marshal.WriteInt(b, uint64(o.Err))
	return b
}
func AuditReplyDecode(b0 []byte) (*AuditReply, []byte, bool) {
	a1, b1, err1 := ktcore.AuditProofSlice1DDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := safemarshal.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	return &AuditReply{P: a1, Err: ktcore.Blame(a2)}, b2, false
}
