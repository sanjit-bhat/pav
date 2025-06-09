// Auto-generated from spec "github.com/mit-pdos/pav/merkle/serde.go"
// using compiler "github.com/mit-pdos/pav/serde".
package merkle

import (
	"github.com/mit-pdos/pav/marshalutil"
	"github.com/tchajed/marshal"
)

func MerkleProofEncode(b0 []byte, o *MerkleProof) []byte {
	var b = b0
	b = marshalutil.WriteSlice1D(b, o.Siblings)
	b = marshal.WriteBool(b, o.IsOtherLeaf)
	b = marshalutil.WriteSlice1D(b, o.LeafLabel)
	b = marshalutil.WriteSlice1D(b, o.LeafVal)
	return b
}
func MerkleProofDecode(b0 []byte) (*MerkleProof, []byte, bool) {
	a1, b1, err1 := marshalutil.ReadSlice1D(b0)
	if err1 {
		return nil, nil, true
	}
	a2, b2, err2 := marshalutil.ReadBool(b1)
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
	return &MerkleProof{Siblings: a1, IsOtherLeaf: a2, LeafLabel: a3, LeafVal: a4}, b4, false
}
