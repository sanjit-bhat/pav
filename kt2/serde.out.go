// Auto-generated from spec "github.com/mit-pdos/pav/kt2/serde.go"
// using compiler "github.com/mit-pdos/pav/serde".
package kt2

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
func PkCommOpenEncode(b0 []byte, o *PkCommOpen) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Pk)
	b = marshalutil.WriteSlice1D(b, o.R)
	return b
}
func PkCommOpenDecode(b0 []byte) (*PkCommOpen, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &PkCommOpen{Pk: a1, R: a2}, b2, false
}
func MapValPreEncode(b0 []byte, o *MapValPre) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Epoch)
	b = marshalutil.WriteSlice1D(b, o.PkComm)
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
	return &MapValPre{Epoch: a1, PkComm: a2}, b2, false
}
func MembProofEncode(b0 []byte, o *MembProof) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Label)
	b = marshalutil.WriteSlice1D(b, o.VrfProof)
	b = marshal.WriteInt(b, o.EpochAdded)
	b = PkCommOpenEncode(b, o.CommOpen)
	b = marshalutil.WriteSlice3D(b, o.MerkProof)
	return b
}
func MembProofDecode(b0 []byte) (*MembProof, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
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
	a4, b4, err4 := PkCommOpenDecode(b3)
	if err4 {
		return nil, nil, true
	}
	a5, b5, err5 := marshalutil.ReadSlice3D(b4)
	if err5 {
		return nil, nil, true
	}
	return &MembProof{Label: a1, VrfProof: a2, EpochAdded: a3, CommOpen: a4, MerkProof: a5}, b5, false
}
func NonMembProofEncode(b0 []byte, o *NonMembProof) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Label)
	b = marshalutil.WriteSlice1D(b, o.VrfProof)
	b = marshalutil.WriteSlice3D(b, o.MerkProof)
	return b
}
func NonMembProofDecode(b0 []byte) (*NonMembProof, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadSlice3D(b2)
	if err3 {
		return nil, nil, true
	}
	return &NonMembProof{Label: a1, VrfProof: a2, MerkProof: a3}, b3, false
}
func HistProofEncode(b0 []byte, o *HistProof) []byte {
	var b = b0
	b = SigDigEncode(b, o.SigDig)
	b = MembProofSlice1DEncode(b, o.Membs)
	b = NonMembProofEncode(b, o.NonMemb)
	return b
}
func HistProofDecode(b0 []byte) (*HistProof, []byte, bool) {
	a1, b1, err1 := SigDigDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := MembProofSlice1DDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := NonMembProofDecode(b2)
	if err3 {
		return nil, nil, true
	}
	return &HistProof{SigDig: a1, Membs: a2, NonMemb: a3}, b3, false
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
	b = HistProofEncode(b, o.P)
	return b
}
func ServerPutReplyDecode(b0 []byte) (*ServerPutReply, []byte, bool) {
	a1, b1, err1 := HistProofDecode(b0)
	if err1 {
		return nil, nil, true
	}
	return &ServerPutReply{P: a1}, b1, false
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
	b = HistProofEncode(b, o.P)
	return b
}
func ServerGetReplyDecode(b0 []byte) (*ServerGetReply, []byte, bool) {
	a1, b1, err1 := HistProofDecode(b0)
	if err1 {
		return nil, nil, true
	}
	return &ServerGetReply{P: a1}, b1, false
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
