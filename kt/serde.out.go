// Auto-generated from spec "github.com/mit-pdos/pav/kt/serde.go"
// using compiler "github.com/mit-pdos/pav/serde".
package kt

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func PreSigDigEncode(b0 []byte, o *PreSigDig) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	b = marshalutil.WriteSlice1D(b, o.Dig)
	return b
}
func PreSigDigDecode(b0 []byte) (*PreSigDig, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &PreSigDig{Epoch: a1, Dig: a2}, b2, false
}
func SigDigEncode(b0 []byte, o *SigDig) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	b = marshalutil.WriteSlice1D(b, o.Dig)
	b = marshalutil.WriteSlice1D(b, o.Sig)
	return b
}
func SigDigDecode(b0 []byte) (*SigDig, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
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
	return &SigDig{Epoch: a1, Dig: a2, Sig: a3}, b3, false
}
func MapLabelPreEncode(b0 []byte, o *MapLabelPre) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	b = marshal.WriteInt(b, o.Ver)
	return b
}
func MapLabelPreDecode(b0 []byte) (*MapLabelPre, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	return &MapLabelPre{Uid: a1, Ver: a2}, b2, false
}
func CommitOpenEncode(b0 []byte, o *CommitOpen) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Val)
	b = marshalutil.WriteSlice1D(b, o.Rand)
	return b
}
func CommitOpenDecode(b0 []byte) (*CommitOpen, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &CommitOpen{Val: a1, Rand: a2}, b2, false
}
func MapValPreEncode(b0 []byte, o *MapValPre) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	b = marshalutil.WriteSlice1D(b, o.PkCommit)
	return b
}
func MapValPreDecode(b0 []byte) (*MapValPre, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &MapValPre{Epoch: a1, PkCommit: a2}, b2, false
}
func MembEncode(b0 []byte, o *Memb) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.LabelProof)
	b = marshal.WriteInt(b, o.EpochAdded)
	b = CommitOpenEncode(b, o.PkOpen)
	b = marshalutil.WriteSlice1D(b, o.MerkleProof)
	return b
}
func MembDecode(b0 []byte) (*Memb, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := CommitOpenDecode(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := marshalutil.ReadSlice1D(b3)
	if err4 {
		return nil, nil, true
	}
	return &Memb{LabelProof: a1, EpochAdded: a2, PkOpen: a3, MerkleProof: a4}, b4, false
}
func MembHideEncode(b0 []byte, o *MembHide) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.LabelProof)
	b = marshalutil.WriteSlice1D(b, o.MapVal)
	b = marshalutil.WriteSlice1D(b, o.MerkleProof)
	return b
}
func MembHideDecode(b0 []byte) (*MembHide, []byte, bool) {
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
	return &MembHide{LabelProof: a1, MapVal: a2, MerkleProof: a3}, b3, false
}
func NonMembEncode(b0 []byte, o *NonMemb) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.LabelProof)
	b = marshalutil.WriteSlice1D(b, o.MerkleProof)
	return b
}
func NonMembDecode(b0 []byte) (*NonMemb, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &NonMemb{LabelProof: a1, MerkleProof: a2}, b2, false
}
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
	b = SigDigEncode(b, o.Dig)
	b = MembEncode(b, o.Latest)
	b = NonMembEncode(b, o.Bound)
	return b
}
func ServerPutReplyDecode(b0 []byte) (*ServerPutReply, []byte, bool) {
	a1, b1, err1 := SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := MembDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := NonMembDecode(b2)
	if err3 {
		return nil, nil, true
	}
	return &ServerPutReply{Dig: a1, Latest: a2, Bound: a3}, b3, false
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
	b = SigDigEncode(b, o.Dig)
	b = MembHideSlice1DEncode(b, o.Hist)
	b = marshal.WriteBool(b, o.IsReg)
	b = MembEncode(b, o.Latest)
	b = NonMembEncode(b, o.Bound)
	return b
}
func ServerGetReplyDecode(b0 []byte) (*ServerGetReply, []byte, bool) {
	a1, b1, err1 := SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := MembHideSlice1DDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadBool(b2)
	if err3 {
		return nil, nil, true
	}
	a4, b4, err4 := MembDecode(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := NonMembDecode(b4)
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
	b = SigDigEncode(b, o.Dig)
	b = NonMembEncode(b, o.Bound)
	return b
}
func ServerSelfMonReplyDecode(b0 []byte) (*ServerSelfMonReply, []byte, bool) {
	a1, b1, err1 := SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := NonMembDecode(b1)
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
func UpdateProofEncode(b0 []byte, o *UpdateProof) []byte {
	var b = b0
	b = MapstringSlbyteEncode(b, o.Updates)
	b = marshalutil.WriteSlice1D(b, o.Sig)
	return b
}
func UpdateProofDecode(b0 []byte) (*UpdateProof, []byte, bool) {
	a1, b1, err1 := MapstringSlbyteDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &UpdateProof{Updates: a1, Sig: a2}, b2, false
}
func ServerAuditReplyEncode(b0 []byte, o *ServerAuditReply) []byte {
	var b = b0
	b = UpdateProofEncode(b, o.P)
	b = marshal.WriteBool(b, o.Err)
	return b
}
func ServerAuditReplyDecode(b0 []byte) (*ServerAuditReply, []byte, bool) {
	a1, b1, err1 := UpdateProofDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadBool(b1)
	if err2 {
		return nil, nil, true
	}
	return &ServerAuditReply{P: a1, Err: a2}, b2, false
}
func AdtrUpdateArgEncode(b0 []byte, o *AdtrUpdateArg) []byte {
	var b = b0
	b = UpdateProofEncode(b, o.P)
	return b
}
func AdtrUpdateArgDecode(b0 []byte) (*AdtrUpdateArg, []byte, bool) {
	a1, b1, err1 := UpdateProofDecode(b0)
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
