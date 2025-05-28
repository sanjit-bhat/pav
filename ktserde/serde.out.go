// Auto-generated from spec "github.com/mit-pdos/pav/ktserde/serde.go"
// using compiler "github.com/mit-pdos/pav/serde".
package ktserde

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
