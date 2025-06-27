// Auto-generated from spec "github.com/sanjit-bhat/pav/ktcore/serde.go"
// using compiler "github.com/sanjit-bhat/pav/serde".
package ktcore

import (
	"github.com/sanjit-bhat/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func VrfSigEncode(b0 []byte, o *VrfSig) []byte {
	var b = b0
	b = marshalutil.WriteByte(b, o.SigTag)
	b = marshalutil.WriteSlice1D(b, o.VrfPk)
	return b
}
func VrfSigDecode(b0 []byte) (*VrfSig, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadByte(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &VrfSig{SigTag: a1, VrfPk: a2}, b2, false
}
func LinkSigEncode(b0 []byte, o *LinkSig) []byte {
	var b = b0
	b = marshalutil.WriteByte(b, o.SigTag)
	b = marshal.WriteInt(b, o.Epoch)
	b = marshalutil.WriteSlice1D(b, o.Link)
	return b
}
func LinkSigDecode(b0 []byte) (*LinkSig, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadByte(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadSlice1D(b2)
	if err3 {
		return nil, nil, true
	}
	return &LinkSig{SigTag: a1, Epoch: a2, Link: a3}, b3, false
}
func MapLabelEncode(b0 []byte, o *MapLabel) []byte {
	var b = b0
	b = marshal.WriteInt(b, o.Uid)
	b = marshal.WriteInt(b, o.Ver)
	return b
}
func MapLabelDecode(b0 []byte) (*MapLabel, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadInt(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadInt(b1)
	if err2 {
		return nil, nil, true
	}
	return &MapLabel{Uid: a1, Ver: a2}, b2, false
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
func MembEncode(b0 []byte, o *Memb) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.LabelProof)
	b = CommitOpenEncode(b, o.PkOpen)
	b = marshalutil.WriteSlice1D(b, o.MerkleProof)
	return b
}
func MembDecode(b0 []byte) (*Memb, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := CommitOpenDecode(b1)
	if err2 {
		return nil, nil, true
	}
	a3, b3, err3 := marshalutil.ReadSlice1D(b2)
	if err3 {
		return nil, nil, true
	}
	return &Memb{LabelProof: a1, PkOpen: a2, MerkleProof: a3}, b3, false
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
func AuditProofEncode(b0 []byte, o *AuditProof) []byte {
	var b = b0
	b = UpdateProofSlice1DEncode(b, o.Updates)
	b = marshalutil.WriteSlice1D(b, o.LinkSig)
	return b
}
func AuditProofDecode(b0 []byte) (*AuditProof, []byte, bool) {
	a1, b1, err1 := UpdateProofSlice1DDecode(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadSlice1D(b1)
	if err2 {
		return nil, nil, true
	}
	return &AuditProof{Updates: a1, LinkSig: a2}, b2, false
}
func UpdateProofEncode(b0 []byte, o *UpdateProof) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.MapLabel)
	b = marshalutil.WriteSlice1D(b, o.MapVal)
	b = marshalutil.WriteSlice1D(b, o.NonMembProof)
	return b
}
func UpdateProofDecode(b0 []byte) (*UpdateProof, []byte, bool) {
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
	return &UpdateProof{MapLabel: a1, MapVal: a2, NonMembProof: a3}, b3, false
}
